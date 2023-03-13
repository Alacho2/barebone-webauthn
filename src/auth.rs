use crate::error::WebauthnError;
use crate::startup::AppState;
use axum::{
    extract::{Extension, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use axum::headers::HeaderMap;
use axum::http::header;
use axum::response::Response;
use axum_sessions::async_session::log::{debug, info};
use axum_sessions::async_session::serde_json;
use axum_sessions::extractors::WritableSession;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use webauthn_rs::prelude::*;

#[derive(Serialize, Deserialize)]
struct Claim {
    user_id: Uuid,
    username: String,
    reg_state: PasskeyRegistration,
    exp: usize,
}

pub async fn start_register(
    Extension(app_state): Extension<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start register");
    let user_unique_id = {
        let users_guard = app_state.users.lock().await;
        users_guard
            .name_to_id
            .get(&username)
            .copied()
            .unwrap_or_else(Uuid::new_v4)
    };


    let exclude_credentials = {
        let users_guard = app_state.users.lock().await;
        users_guard
            .keys
            .get(&user_unique_id)
            .map(|keys| keys.iter().map(|sk| sk.cred_id().clone()).collect())
    };

    let res = match app_state.webauthn.start_passkey_registration(
        user_unique_id,
        &username,
        &username,
        exclude_credentials,
    ) {
        Ok((ccr, reg_state)) => {

            let claim = Claim {
                user_id: user_unique_id,
                username,
                reg_state,
                exp: (Utc::now() + Duration::minutes(1)).timestamp() as usize,
            };
            let token = jsonwebtoken::encode(
                &Header::default(),
                &claim,
                &EncodingKey::from_secret("secret".as_ref())
            ).unwrap();
            info!("Registration Successful!");
            let response = Response::builder()
              .header(header::AUTHORIZATION, format!("Bearer {}", token))
              .header(header::ACCESS_CONTROL_EXPOSE_HEADERS, "Authorization")
              .status(StatusCode::OK)
              .body::<String>(serde_json::to_string(&ccr).unwrap().into()).unwrap();
            response
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            return Err(WebauthnError::Unknown);
        }
    };
    Ok(res)
}

pub async fn finish_register(
    headers: HeaderMap,
    Extension(app_state): Extension<AppState>,
    Json(reg): Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {

    let auth_header = headers.get(header::AUTHORIZATION).unwrap().to_str().unwrap();

    let split_auth_header: Vec<&str> = auth_header.split(" ").collect();

    let token = split_auth_header[1];


    // if let Some(i) = token.find(' ') {
    //     token = &token[i + 1..];
    //     println!("Hello {} {}", token, &token[i + 1..]);
    // }

    let Claim {
        user_id: user_unique_id,
        username,
        reg_state,
        exp: _
    } = jsonwebtoken::decode(
        &token,
        &DecodingKey::from_secret("secret".as_ref()),
        &Validation::default()
    ).map(|data: TokenData<Claim>| data.claims).unwrap();

    println!("{}", username);

    let res = match app_state
        .webauthn
        .finish_passkey_registration(&reg, &reg_state)
    {
        Ok(sk) => {
        println!("We got here :)");
            let mut users_guard = app_state.users.lock().await;

            //TODO: This is where we would store the credential in a db, or persist them in some other way.
            users_guard
                .keys
                .entry(user_unique_id)
                .and_modify(|keys| keys.push(sk.clone()))
                .or_insert_with(|| vec![sk.clone()]);

            users_guard.name_to_id.insert(username, user_unique_id);

            StatusCode::OK
        }
        Err(e) => {
            println!("We got here :( {}", e);
            debug!("challenge_register -> {:?}", e);
            StatusCode::BAD_REQUEST
        }
    };

    Ok(res)
}

pub async fn start_authentication(
    Extension(app_state): Extension<AppState>,
    mut session: WritableSession,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start Authentication");

    session.remove("auth_state");

    let users_guard = app_state.users.lock().await;

    let user_unique_id = users_guard
        .name_to_id
        .get(&username)
        .copied()
        .ok_or(WebauthnError::UserNotFound)?;

    let allow_credentials = users_guard
        .keys
        .get(&user_unique_id)
        .ok_or(WebauthnError::UserHasNoCredentials)?;

    let res = match app_state
        .webauthn
        .start_passkey_authentication(allow_credentials)
    {
        Ok((rcr, auth_state)) => {
            drop(users_guard);

            session
                .insert("auth_state", (user_unique_id, auth_state))
                .expect("Failed to insert");
            Json(rcr)
        }
        Err(e) => {
            debug!("challenge_authenticate -> {:?}", e);
            return Err(WebauthnError::Unknown);
        }
    };
    Ok(res)
}

pub async fn finish_authentication(
    Extension(app_state): Extension<AppState>,
    mut session: WritableSession,
    Json(auth): Json<PublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    let (user_unique_id, auth_state): (Uuid, PasskeyAuthentication) = session
        .get("auth_state")
        .ok_or(WebauthnError::CorruptSession)?;

    session.remove("auth_state");

    let res = match app_state
        .webauthn
        .finish_passkey_authentication(&auth, &auth_state)
    {
        Ok(auth_result) => {
            let mut users_guard = app_state.users.lock().await;

            users_guard
                .keys
                .get_mut(&user_unique_id)
                .map(|keys| {
                    keys.iter_mut().for_each(|sk| {
                        sk.update_credential(&auth_result);
                    })
                })
                .ok_or(WebauthnError::UserHasNoCredentials)?;
            StatusCode::OK
        }
        Err(e) => {
            debug!("challenge_register -> {:?}", e);
            StatusCode::BAD_REQUEST
        }
    };
    info!("Authentication Successful!");
    Ok(res)
}
