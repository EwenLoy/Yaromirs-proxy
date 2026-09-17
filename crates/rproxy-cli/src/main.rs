//! rproxy-cli — CLI-интерфейс к ядру (tech-plan.md §7).
//! M0/M2: `rproxy run --port 8888` — forward proxy с построчным логом exchanges.

use clap::Parser;
use rproxy_core::{EventBus, ProxyEvent, ProxyServer, pipeline::Pipeline};

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

    /// Поднять MCP-сервер на stdio (для AI-агентов: Claude Code, Codex, Cursor)
    #[arg(long)]
    mcp: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let bus = EventBus::new();
    let pipeline = Pipeline::new();
    let server = ProxyServer::new(bus.clone(), pipeline).with_mitm();

    let mut events = bus.subscribe();
    let store = rproxy_mcp::Store::new();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let session_for_har = store.clone();
    let session_store = store.clone();
    let _recorder = tokio::spawn(async move {
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
                        eprintln!("{method} {uri} -> {status} ({dur})");
                        if session_store.is_recording() {
                            session_store.session.lock().unwrap().push(ex);
                        }
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
    });

    let addr = format!("{}:{}", cli.bind, cli.port);
    eprintln!("rproxy listening on http://{addr} (HTTP + MITM HTTPS)");
    if cli.mcp {
        eprintln!("MCP server on stdio (tools: get_flows, get_flow, export_flow_curl, toggle_recording, clear_session, get_status)");
    }

    // MCP-режим: живём, пока открыт stdin агента; иначе — до Ctrl+C.
    if cli.mcp {
        rproxy_mcp::serve(store).await?;
    } else {
        tokio::signal::ctrl_c().await?;
        eprintln!("\n[rproxy] завершение...");
    }

    let _ = shutdown_tx.send(());

    drop(server);
    drop(bus);

    if let Some(path) = cli.har {
        let session = {
            // даём рекордеру дочитать хвост и забираем сессию из store
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            session_for_har.session.lock().unwrap().clone()
        };
        rproxy_export::write_har(&path, &session)?;
        eprintln!("[rproxy] сессия сохранена в {path} ({} exchanges)", session.len());
    }
    Ok(())
}
