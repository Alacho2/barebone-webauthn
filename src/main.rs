use axum::{extract::Extension, routing::post, Router};
use axum_sessions::{async_session::MemoryStore, SameSite, SessionLayer};
use std::net::SocketAddr;
use axum::headers::HeaderValue;
use axum::http::{header, Method};
use axum::response::Html;
use axum::routing::get;
use tower_http::cors::{CorsLayer};

mod error;
/*
 * Webauthn RS server side tutorial.
 */

// The handlers that process the data can be found in the auth.rs file
// This file contains the wasm client loading code and the axum routing

use crate::auth::{finish_authentication, finish_register, start_authentication, start_register};
use crate::startup::AppState;

use rand::prelude::*;


mod auth;
mod startup;

#[cfg(all(feature = "javascript", feature = "wasm", not(doc)))]
compile_error!("Feature \"javascript\" and feature \"wasm\" cannot be enabled at the same time");

// 7. That's it! The user has now authenticated!

// =======
// Below is glue/stubs that are needed to make the above work, but don't really affect
// the work flow too much.

#[tokio::main]
async fn main() {

    let id = "lcinncgkpdbmincnojedpklnmnbifmmj";

    let app_state = AppState::new(id);

    let store = MemoryStore::new();
    let secret = thread_rng().gen::<[u8; 128]>(); // MUST be at least 64 bytes!
    let session_layer = SessionLayer::new(store, &secret)
        .with_cookie_name("webauthnrs")
        .with_same_site_policy(SameSite::Lax)
        .with_secure(true);

    let app = Router::new()
        .route("/", get(basic_get_handler))
        .route("/register_start/:username", post(start_register))
        .route("/register_finish", post(finish_register))
        .route("/login_start/:username", post(start_authentication))
        .route("/login_finish", post(finish_authentication))
        .layer(Extension(app_state))
        .layer(session_layer)
        .layer(CorsLayer::new()
        .allow_origin(
            format!("chrome-extension://{}", id)
              .parse::<HeaderValue>()
              .unwrap()
        ).allow_methods([Method::GET, Method::POST])
          .allow_credentials(true)
          .allow_headers(vec![header::CONTENT_TYPE, header::AUTHORIZATION]));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("listening on {addr}");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn basic_get_handler() -> Html<&'static str> {
    Html("<body>Hello</body>")
}
