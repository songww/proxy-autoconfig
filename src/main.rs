use axum::{service, prelude::*};
use tower_http::services::ServeFile;

#[tokio::main]
async fn main() {

    let app = route(
        // GET `/static/Cargo.toml` goes to a service from tower-http
        "/proxy.pac",
        service::get(ServeFile::new("/home/songww/.config/shadowsocks/shadowsocks.pac"))
        // application/x-ns-proxy-autoconfig
    );

    // run it with hyper on localhost:3000
    hyper::Server::bind(&"0.0.0.0:1089".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
