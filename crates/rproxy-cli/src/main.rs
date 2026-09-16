//! rproxy-cli — CLI-интерфейс к ядру (tech-plan.md §7).
//! M0/M2: `rproxy run --port 8888` — forward proxy с построчным логом exchanges.

use clap::Parser;
use rproxy_core::{EventBus, ProxyEvent, ProxyServer, pipeline::Pipeline};

#[derive(Parser, Debug)]
#[command(name = "rproxy", version, about = "Открытый аналог Charles Proxy (M0)")]
struct Cli {
    /// Порт прокси
    #[arg(long, short, default_value_t = 8888)]
    port: u16,

    /// Адрес для bind
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let bus = EventBus::new();
    let pipeline = Pipeline::new();
    let server = ProxyServer::new(bus.clone(), pipeline).with_mitm();

    // Подписчик: построчный лог exchanges в stdout.
    let mut events = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(ProxyEvent::ExchangeCompleted(ex)) => {
                    let (method, uri) = ex
                        .request
                        .as_ref()
                        .map(|r| (r.method.clone(), r.uri.clone()))
                        .unwrap_or_else(|| ("-".into(), "-".into()));
                    let status = ex
                        .response_status
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".into());
                    let dur = ex
                        .timing
                        .total()
                        .map(|d| format!("{d:?}"))
                        .unwrap_or_else(|| "-".into());
                    println!("{method} {uri} -> {status} ({dur}) [{:?}]", ex.state);
                }
                Ok(ProxyEvent::Error(msg)) => eprintln!("[error] {msg}"),
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!("[warn] пропущено {n} событий");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let addr = format!("{}:{}", cli.bind, cli.port);
    println!("rproxy (M0) listening on http://{addr}");
    server.run(&addr).await?;
    Ok(())
}
