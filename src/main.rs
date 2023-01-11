use poem::{
    endpoint::{EndpointExt, StaticFileEndpoint},
    listener::TcpListener,
    IntoResponse, Route, Server,
};

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = Route::new().at(
        "/proxy.pac",
        StaticFileEndpoint::new("/home/songww/.config/shadowsocks/shadowsocks.pac").and_then(
            |resp| async move { Ok(resp.with_content_type("application/x-ns-proxy-autoconfig")) },
        ),
    );

    Server::new(TcpListener::bind("127.0.0.1:3000"))
        .run(app)
        .await
}
