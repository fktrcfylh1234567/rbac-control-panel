mod config;
mod controller;

use crate::config::Config;
extern crate rusqlite;
use std::convert::Infallible;
use std::fs;
use serde::Serialize;
use warp::{http::{Response, StatusCode}, Filter, hyper};
use crate::controller::{AuthRequest, CONTROLLER, Fingerprint, RegistrationRequest, Role};

fn response_ok<T: Serialize>(body: T) -> Result<hyper::http::Result<Response<String>>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(serde_json::json!(&body).to_string()))
}

fn response_unauthorized(msg: String) -> Result<hyper::http::Result<Response<String>>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(msg))
}

fn response_forbidden(msg: String) -> Result<hyper::http::Result<Response<String>>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(msg))
}

fn response_internal_server_error(msg: String) -> Result<hyper::http::Result<Response<String>>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(msg))
}

async fn handle_auth_request(b: AuthRequest) -> Result<hyper::http::Result<Response<String>>, Infallible> {
    println!("{:?}", b);
    match CONTROLLER.log_in_with_password(b) {
        Ok(Some(r)) => response_ok(&r),
        Ok(None) => response_unauthorized(format!("incorrect login or password")),
        Err(e) => response_internal_server_error(format!("error: {}", e))
    }
}

async fn handle_registr_request(token: String, b: RegistrationRequest) -> Result<hyper::http::Result<Response<String>>, Infallible> {
    println!("{:?}", b);
    let role = match CONTROLLER.check_auth(&token, b.fingerprint) {
        None => return response_unauthorized(format!("incorrect token")),
        Some(role) => role
    };

    if role != Role::ADMIN {
        return response_forbidden(format!("not enough rights"))
    };

    match CONTROLLER.create_user(b.login, b.password, b.admin) {
        Ok(r) => response_ok(&r),
        Err(e) => response_internal_server_error(format!("error: {}", e))
    }
}

async fn handle_system_data_request(token: String, b: Fingerprint) -> Result<hyper::http::Result<Response<String>>, Infallible> {
    println!("{:?}", b);
    if CONTROLLER.check_auth(&token, b).is_none() {
        return response_unauthorized(format!("incorrect token"))
    }

    let r = CONTROLLER.get_system_data();
    response_ok(&r)
}

async fn handle_static_request(url: &str) -> Result<hyper::http::Result<Response<String>>, Infallible> {
    match fs::read_to_string(url) {
        Ok(r) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=UTF-8")
            .body(r)),
        Err(e) => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(format!("error: {}", e))),
    }
}

pub async fn run_http_api() {
    let static_index = warp::get().and(warp::path::end())
        .and_then(|| handle_static_request("./www/index.html"));

    let registr = warp::post().and(warp::path("registr"))
        .and(warp::header("Authentication"))
        .and(warp::body::json())
        .and_then(move |token: String, b: RegistrationRequest| handle_registr_request(token, b));

    let auth = warp::post().and(warp::path("auth"))
        .and(warp::body::json())
        .and_then(move |b: AuthRequest| handle_auth_request(b));

    let system_data = warp::post().and(warp::path("system_data"))
        .and(warp::header("Authentication"))
        .and(warp::body::json())
        .and_then(move |token: String, b: Fingerprint| handle_system_data_request(token, b));

    let api = static_index
        .or(auth)
        .or(registr)
        .or(system_data);

    warp::serve(api).run(([0, 0, 0, 0], 8000)).await;
}

#[tokio::main]
async fn main() {
    CONTROLLER.start();
    println!("server started!");
    run_http_api().await;
}
