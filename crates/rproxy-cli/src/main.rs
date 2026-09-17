//! rproxy-cli — CLI-интерфейс к ядру (tech-plan.md §7).
//! M0/M2: `rproxy run --port 8888` — forward proxy с построчным логом exchanges.

use clap::Parser;
use rproxy_core::{EventBus, Exchange, ProxyEvent, ProxyServer, pipeline::Pipeline};

#[derive(Parser, Debug)]
#[command(name = "rproxy", version, about = "Открытый аналог Charles Proxy")]
struct Cli {
    /// Порт прокси
    #[arg(long, short, default_value_t = 8888)]
    port: u16,

    /// Адрес для bind
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// Записать сессию в HAR-файл при выходе (Ctrl+C)
    #[arg(long)]
    har: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let bus = EventBus::new();
    let pipeline = Pipeline::new();
    let server = ProxyServer::new(bus.clone(), pipeline).with_mitm();

    // Подписчик: построчный лог + сбор сессии для --har.
    let mut events = bus.subscribe();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let recorder = tokio::spawn(async move {
        let mut session: Vec<Exchange> = Vec::new();
        loop {
            tokio::select! {
                ev = events.recv() => match ev {
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
                        session.push(ex);
                    }
                    Ok(ProxyEvent::Error(msg)) => eprintln!("[error] {msg}"),
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("[warn] пропущено {n} событий");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
                _ = &mut shutdown_rx => break,
            }
        }
        session
    });

    let addr = format!("{}:{}", cli.bind, cli.port);
    println!("rproxy listening on http://{addr} (HTTP + MITM HTTPS)");
    println!("Нажми Ctrl+C для выхода{}", if cli.har.is_some() { " — сессия сохранится в HAR" } else { "" });

    // Ждём Ctrl+C, затем корректно пишем HAR.
    tokio::signal::ctrl_c().await?;
    eprintln!("\n[rproxy] завершение...");
    let _ = shutdown_tx.send(());
    // даём дочитать последние события, прилетевшие до shutdown
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    drop(server);
    drop(bus);
    if let Some(path) = cli.har {
        let session = recorder.await.unwrap_or_default();
        rproxy_export::write_har(&path, &session)?;
        println!("[rproxy] сессия сохранена в {path} ({} exchanges)", session.len());
    }
    Ok(())
}
