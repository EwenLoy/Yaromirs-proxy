# rproxy — Yaromirs Proxy

<div align="center">

**Open-source web debugging proxy — an alternative to Charles Proxy, written in Rust.**

See, intercept and modify the HTTP/HTTPS traffic of your applications.
In the future — the same familiar tools: Map Remote, Rewrite, Breakpoints, Throttling.

[![Rust](https://img.shields.io/badge/rust-1.91%2B-orange?logo=rust)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-cargo-green?logo=rust)](#build)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey)](#)

</div>

---

## What is it

`rproxy` is a debugging HTTP proxy, built on the principle of Charles Proxy / mitmproxy:
the application directs traffic to the proxy, and you see every request and response in a
convenient interface.

The main idea of the architecture: **the GUI and CLI are two equal clients of the same
proxy-engine**. The kernel knows nothing about the UI and publishes all events to a bus,
which any consumer connects to — a desktop interface, a headless daemon, exporters.

> Status: **M0 completed** — the core of the proxy is working (HTTP forwarding +
> HTTPS tunneling), CLI and live GUI are connected to the real kernel.
> Roadmap below.

## Features (already working)

- **HTTP/1.1 forward proxy** — requests are forwarded to the origin, the body is streamed
  without buffering.
- **CONNECT tunneling (HTTPS)** — the traffic of HTTPS clients passes through the proxy
  in its entirety (passthrough, without decryption yet).
- **Event bus** — every exchange (request/response) is published as an event; any number of
  subscribers (GUI, CLI, future exporters).
- **Interceptors pipeline** — an extensible chain in the style of Charles tools:
  `RequestInterceptor` / `ResponseInterceptor` with actions `Continue / Block /
  ShortCircuit / Hold` (the basis for Map Local, Block List, Rewrite, Breakpoints).
- **CLI daemon** — `rproxy run` with live logging of exchanges.
- **GUI (egui)** — Sequence view with live updates, Structure view (tree by domains),
  filtering, color coding of methods and statuses.

## Screenshots

> TODO: screenshot of GUI with live traffic (M4)

## Quick start

Requirements: [Rust](https://rustup.rs) 1.75+

```bash
git clone https://github.com/EwenLoy/Yaromirs-proxy.git
cd Yaromirs-proxy

# GUI: proxy + interface in one window (port 8888 by default)
cargo run -p rproxy-gui

# or headless daemon
cargo run -p rproxy-cli -- --port 8888

# daemon with MCP server for AI agents (Claude Code, Codex, Cursor)
cargo run -p rproxy-cli -- --port 8888 --mcp
```

### Tools (M3) — TOML config

```bash
rproxy --tools tools.toml
```

```toml
[[block]]
match = "ads.example.com"
status = 403

no_caching = true

[[map_local]]
match = "https://api.test/config"
file = "mock.json"
content_type = "application/json"

[[map_remote]]
match = "api.old.com"
replace = "api.new.com"
```

### MCP — proxy for AI agents

`rproxy` is **headless by design**: an AI agent can drive the proxy without any GUI —
locally, in CI, in Docker or over SSH (unlike Proxyman/Charles, whose MCP requires an
open desktop app).

```bash
claude mcp add rproxy -- rproxy --port 8888 --mcp
```

Tools exposed to the agent: `get_flows` (list/filter), `get_flow` (headers + bodies),
`export_flow_curl`, `toggle_recording`, `clear_session`, `get_status`.
Example prompt for your agent: *"Run rproxy, capture the traffic of my test suite and
show me every request that returned 5xx with its response body."*

Direct traffic through the proxy:

```bash
# curl
curl -x http://127.0.0.1:8888 http://example.com/

# HTTPS (tunneling, MITM in M1)
curl -x http://127.0.0.1:8888 -k https://api.github.com/zen

# or set 127.0.0.1:8888 as the system/browser proxy
```

GUI port can be changed: `RPROXY_PORT=9999 cargo run -p rproxy-gui`.

### Tests

```bash
cargo test --workspace
```

Integration tests cover: forward proxying, CONNECT passthrough, and the interceptor
pipeline (ShortCircuit).

## Architecture

```
rproxy/
├── crates/
│   ├── rproxy-core/     # kernel: proxy engine, event bus, pipeline (no UI)
│   ├── rproxy-cli/      # binary `rproxy`: daemon mode (mitmdump style)
│   └── rproxy-gui/      # binary: egui/eframe desktop app
```

Key principles:

- **The kernel knows nothing about the UI.** The GUI and CLI subscribe to the event bus
  (`tokio::sync::broadcast`) and see the same traffic. Later — connecting to an already
  running daemon via IPC (which Charles does not have at all).
- **Every Charles tool = one interceptor.** Map Remote, Map Local, Rewrite, Block List,
  No Caching — all of this is implemented by a single trait and is included in the
  pipeline in an explicit order.
- **Streaming.** Bodies are not buffered in the kernel without the need — important for
  large responses and streams.

Stack: `tokio`, `hyper` 1.x, `egui`/`eframe`, `clap`. MITM — planned `rustls` + `rcgen`.

## Roadmap

| Stage | What | Status |
|---|---|---|
| **M0** | Proxy core: HTTP forward, CONNECT passthrough, event bus, pipeline, CLI, live GUI | ✅ done |
| **M1** | MITM: root CA (rcgen), dynamic leaf certificates (SNI), HTTPS decryption | ⏳ next |
| **M2** | CLI daemon: logging, HAR export, `cert install/export` | ⏳ |
| **M3** | Tools: Block List, No Caching, Map Local, Map Remote, Rewrite | ⏳ |
| **M4** | GUI MVP: full request/response viewers, JSON/XML tree | ⏳ |
| **M5** | TUI (ratatui) | ⏳ |
| **M6** | Breakpoints, Compose, Repeat | ⏳ |
| **M7** | HTTP/2, WebSocket | ⏳ |
| **M8** | Throttling/Chaos, DNS Spoofing, Mirror, Profiles | ⏳ |
| **M9** | Import/export: HAR, `.chlz`/`.chls` (Charles), cURL | ⏳ |
| **M10** | HTTP/3 (quinn), IPv6, SOCKS5, Happy Eyeballs | ⏳ |

The full analysis of Charles Proxy 5.2.1 and the detailed technical plan are in
[tech-plan.md](tech-plan.md).

## Contributing

The project is at an early stage, the architecture is being laid right now — this is the
best time to influence decisions. Open an Issue or PR.

## License

MIT. See [LICENSE](LICENSE).
