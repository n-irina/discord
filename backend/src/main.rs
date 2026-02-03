use axum::{
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::net::SocketAddr;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};

#[derive(Clone)]
struct AppState {
    db: PgPool,
    jwt_secret: String,
    jwt_expires_hours: i64,
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/* -------------------- SIGNUP -------------------- */

#[derive(Deserialize)]
struct SignupBody {
    username: String,
    email: String,
    password: String,
}

#[derive(Serialize)]
struct PublicUser {
    id: i32,
    username: String,
    email: String,
}

async fn signup(
    State(state): State<AppState>,
    Json(body): Json<SignupBody>,
) -> Result<(StatusCode, Json<PublicUser>), (StatusCode, Json<serde_json::Value>)> {
    if body.username.trim().is_empty() || body.email.trim().is_empty() || body.password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid input (password min 8 chars)"})),
        ));
    }

    // Hash password (Argon2)
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Password hashing failed"})),
            )
        })?
        .to_string();

    // Insert user
    let row = sqlx::query(
        r#"
        INSERT INTO users (username, email, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id, username, email
        "#,
    )
    .bind(body.username)
    .bind(body.email)
    .bind(password_hash)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate key") || msg.contains("unique") {
            (
                StatusCode::CONFLICT,
                Json(json!({"error": "Username or email already exists"})),
            )
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        }
    })?;

    Ok((
        StatusCode::CREATED,
        Json(PublicUser {
            id: row.get("id"),
            username: row.get("username"),
            email: row.get("email"),
        }),
    ))
}

/* -------------------- JWT -------------------- */

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: i32,          // user id
    exp: i64,          // expiration (unix ts)
    iat: i64,          // issued at
}

fn make_token(user_id: i32, secret: &str, expires_hours: i64) -> Result<String, ()> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id,
        iat: now.timestamp(),
        exp: (now + Duration::hours(expires_hours)).timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| ())
}

/* -------------------- LOGIN -------------------- */

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    access_token: String,
    token_type: String,
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginBody>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<serde_json::Value>)> {
    if body.email.trim().is_empty() || body.password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid input"})),
        ));
    }

    // Find user by email
    let row = sqlx::query(
        r#"
        SELECT id, password_hash
        FROM users
        WHERE email = $1
        "#,
    )
    .bind(&body.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database error"})),
        )
    })?;

    let Some(row) = row else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid credentials"})),
        ));
    };

    let user_id: i32 = row.get("id");
    let password_hash: String = row.get("password_hash");

    // Verify password
    let parsed_hash = PasswordHash::new(&password_hash).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Password hash invalid in DB"})),
        )
    })?;

    Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed_hash)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid credentials"})),
            )
        })?;

    // Create JWT
    let token = make_token(user_id, &state.jwt_secret, state.jwt_expires_hours).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Token generation failed"})),
        )
    })?;

    Ok(Json(LoginResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
    }))
}

/* -------------------- AUTH EXTRACTOR (Bearer) -------------------- */

struct AuthUser {
    user_id: i32,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing Bearer token"})),
            ))?;

        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or expired token"})),
            )
        })?;

        Ok(AuthUser {
            user_id: decoded.claims.sub,
        })
    }
}

/* -------------------- /me -------------------- */

async fn me(
    State(state): State<AppState>,
    AuthUser { user_id }: AuthUser,
) -> Result<Json<PublicUser>, (StatusCode, Json<serde_json::Value>)> {
    let row = sqlx::query(
        r#"
        SELECT id, username, email
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database error"})),
        )
    })?;

    Ok(Json(PublicUser {
        id: row.get("id"),
        username: row.get("username"),
        email: row.get("email"),
    }))
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let jwt_expires_hours: i64 = std::env::var("JWT_EXPIRES_IN_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Cannot connect to database");

    let state = AppState {
        db: pool,
        jwt_secret,
        jwt_expires_hours,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/auth/signup", post(signup))
        .route("/auth/login", post(login))
        .route("/me", get(me))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
    println!("Backend running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
