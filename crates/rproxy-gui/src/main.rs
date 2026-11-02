#![windows_subsystem = "windows"]

use eframe::egui;
use egui::{Color32, RichText};
use rproxy_core::{EventBus, ProxyEvent, ProxyServer};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::SystemTime;

// Палитра подобрана по скриншотам Charles 5.2.1: тело — средне-серое (не чёрное!),
// меню/тулбар/статус-бар — на тон светлее, выделение — насыщенно-синее,
// но синим заливается ТОЛЬКО активный/нажатый элемент; при наведении —
// просто более светлый серый (это отдельная константа HOVER).
const BG: Color32 = Color32::from_rgb(0x30, 0x30, 0x30);        // основная рабочая область
const PANEL: Color32 = Color32::from_rgb(0x36, 0x36, 0x36);     // левое дерево / боковые панели
const HEADER: Color32 = Color32::from_rgb(0x3C, 0x3C, 0x3C);    // меню, тулбар, статус-бар
const HOVER: Color32 = Color32::from_rgb(0x48, 0x48, 0x48);     // просто подсветка при наведении
const MENU_BORDER: Color32 = Color32::from_rgb(0x50, 0x50, 0x50);
const SELECT: Color32 = Color32::from_rgb(0x2F, 0x6F, 0xED);    // синее — только для активного/нажатого
const TEXT: Color32 = Color32::from_rgb(0xD4, 0xD4, 0xD4);
const DIM: Color32 = Color32::from_rgb(0x8A, 0x8A, 0x8A);
const GREEN: Color32 = Color32::from_rgb(0x2E, 0x9E, 0x4B);
const RED: Color32 = Color32::from_rgb(0xD0, 0x40, 0x3A);
const ORANGE: Color32 = Color32::from_rgb(0xE0, 0x60, 0x30);

fn main() -> eframe::Result<()> {
    let port: u16 = std::env::var("RPROXY_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8888);

    let (tx, rx) = channel::<GuiEv>();
    let bus = EventBus::new();
    let bp_hub = Arc::new(rproxy_core::BreakpointHub::default());
    let ssl_cfg = Arc::new(std::sync::RwLock::new(rproxy_core::SslProxyConfig::default()));

    // Ошибку бинда не «съедаем»: показываем её в UI и даём кнопку повторить
    // (порт мог освободиться, или пользователь введёт другой).
    let bind_error = spawn_engine(port, &bus, &bp_hub, Some(ssl_cfg.clone()), &tx).err();
    let listening = bind_error.is_none();

    let ssl_ui = Some(ssl_cfg);
    // Как Charles: при старте перехватываем системный прокси Windows, иначе трафик
    // (Telegram, браузеры с «использовать системный прокси») идёт мимо rproxy.
    // Прежние значения сохраняются в снапшот и возвращаются при выходе/выключении.
    // RPROXY_NO_SYSPROXY=1 отключает автоперехват (например, если системный прокси
    // уже занят другим инструментом).
    // RPROXY_NO_SYSPROXY=1 принудительно отключает автоперехват.
    let autotake = std::env::var("RPROXY_NO_SYSPROXY").is_err() && sysproxy_pref();
    let win_proxy = if listening && autotake {
        set_windows_proxy(true, port).is_ok()
    } else {
        false
    };
    eframe::run_native(
        "rproxy",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1240.0, 780.0])
                .with_min_inner_size([900.0, 560.0]),
            ..Default::default()
        },
        Box::new(move |cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            cc.egui_ctx.set_pixels_per_point(1.15);
            setup_style(&cc.egui_ctx);
            Ok(Box::new(App::new(
                rx, tx, bus, port, bp_hub, ssl_ui, listening, bind_error, win_proxy, autotake,
            )))
        }),
    )
}

/// Поднять движок на порту. Ошибка возвращается вызывающему, чтобы UI показал её
/// и дал кнопку «повторить» — без перезапуска всего приложения.
fn spawn_engine(
    port: u16,
    bus: &EventBus,
    bp_hub: &Arc<rproxy_core::BreakpointHub>,
    ssl_cfg: Option<Arc<std::sync::RwLock<rproxy_core::SslProxyConfig>>>,
    tx: &std::sync::mpsc::Sender<GuiEv>,
) -> Result<(), String> {
    let addr = format!("127.0.0.1:{port}");
    let listener = std::net::TcpListener::bind(&addr)
        .map_err(|e| format!("Cannot listen on {addr}: {e}"))?;
    // КРИТИЧНО: tokio требует НЕблокирующий сокет. С блокирующим accept внутри
    // async-рантайма залипает на втором вызове — движок принимает первое
    // соединение и дальше молчит (именно так «трафика нет»).
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("Cannot set non-blocking on {addr}: {e}"))?;
    let bus2 = bus.clone();
    let hub2 = bp_hub.clone();
    let tx2 = tx.clone();
    std::thread::Builder::new()
        .name("rproxy-engine".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx2.send(GuiEv::EngineError(format!("tokio runtime: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::from_std(listener) {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = tx2.send(GuiEv::EngineError(format!("listener: {e}")));
                        return;
                    }
                };
                let mut sub = bus2.subscribe();
                let tx3 = tx2.clone();
                tokio::spawn(async move {
                    loop {
                        match sub.recv().await {
                            Ok(ProxyEvent::ExchangeCompleted(ex)) => { let _ = tx3.send(GuiEv::Done(ex)); }
                            Ok(ProxyEvent::BreakpointHit(ex)) => { let _ = tx3.send(GuiEv::Bp(ex)); }
                            Ok(_) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            Err(_) => continue,
                        }
                    }
                });
                let server = ProxyServer::new(bus2, rproxy_core::Pipeline::new())
                    .with_mitm()
                    .with_breakpoints_hub(hub2);
                // Один общий SslProxyConfig для движка и GUI (хот-релоад из диалога).
                if let Some(cfg) = &ssl_cfg {
                    if let (Ok(mut dst), Ok(src)) = (server.ssl_proxy_config().write(), cfg.read()) {
                        *dst = src.clone();
                    }
                }
                let _ = server.serve(listener).await;
            });
        })
        .map_err(|e| format!("engine thread: {e}"))?;
    Ok(())
}

fn setup_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals.dark_mode = true;
    style.visuals.panel_fill = BG;
    // Фон самого выпадающего меню/попапа — на тон светлее фона, с тонкой рамкой,
    // как у Charles (у него меню не сливается с телом окна).
    style.visuals.window_fill = HEADER;
    style.visuals.window_stroke = egui::Stroke::new(1.0, MENU_BORDER);
    style.visuals.extreme_bg_color = Color32::from_rgb(0x15, 0x15, 0x15);
    style.visuals.faint_bg_color = Color32::from_rgb(0x28, 0x28, 0x28);
    style.visuals.selection.bg_fill = SELECT;
    style.visuals.selection.stroke = egui::Stroke::NONE;

    // Обычная (невыбранная) кнопка/пункт меню — прозрачный фон, просто текст.
    style.visuals.widgets.noninteractive.bg_fill = Color32::TRANSPARENT;
    style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.widgets.inactive.bg_fill = Color32::TRANSPARENT;
    style.visuals.widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
    style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::NONE;

    // Hover — просто светлее серый (как у Charles: наведение не заливает синим,
    // синим подсвечивается только то, что реально нажато/выбрано).
    style.visuals.widgets.hovered.bg_fill = HOVER;
    style.visuals.widgets.hovered.weak_bg_fill = HOVER;
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::NONE;
    style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, Color32::WHITE);
    style.visuals.widgets.hovered.expansion = 0.0;

    // Active (реальное нажатие/клик) — вот тут уже сплошной синий.
    style.visuals.widgets.active.bg_fill = SELECT;
    style.visuals.widgets.active.weak_bg_fill = SELECT;
    style.visuals.widgets.active.bg_stroke = egui::Stroke::NONE;
    style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, Color32::WHITE);

    // Открытое menu_button (кнопка "File"/"Proxy" в баре, пока её меню раскрыто) —
    // у Charles она подсвечена синим, пока меню открыто (это тоже "активное" состояние).
    style.visuals.widgets.open.bg_fill = SELECT;
    style.visuals.widgets.open.weak_bg_fill = SELECT;
    style.visuals.widgets.open.bg_stroke = egui::Stroke::NONE;
    style.visuals.widgets.open.fg_stroke = egui::Stroke::new(1.0, Color32::WHITE);

    style.visuals.override_text_color = Some(TEXT);
    // Выпадающие меню (menu_rounding) оставляем прямоугольными — как у Charles.
    // А обычные кнопки/панели чуть скругляем (window_rounding + rounding виджетов) —
    // так тулбар и диалоги смотрятся мягче, менее "топорно", а меню всё равно плоское.
    style.visuals.window_rounding = 6.0.into();
    style.visuals.menu_rounding = 0.0.into();
    for w in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        w.rounding = 3.0.into();
    }
    style.spacing.item_spacing = egui::vec2(5.0, 3.0);
    // Внутренний отступ у пункта меню/кнопки: больше по X, чтобы текст не лип к краям
    // выпадающего списка (в Charles у пунктов заметный левый/правый инсет).
    style.spacing.button_padding = egui::vec2(12.0, 4.0);
    // Рамка самого попапа меню — отступ от края попапа до содержимого.
    style.spacing.menu_margin = egui::Margin::symmetric(0.0, 4.0);
    style.spacing.interact_size.y = 24.0;
    // Минимальная ширина выпадающего меню — иначе оно ужимается по самому
    // узкому пункту (justified-layout в egui 0.26+ авто-подгоняет ширину под
    // контент), из-за чего попап выглядит "квадратным"/тесным, не как в Charles.
    style.spacing.menu_width = 180.0;
    ctx.set_style(style);
}

#[derive(Clone)]
struct Row {
    id: u32,
    locked: bool,
    method: String,
    host: String,
    path: String,
    status: u16,
    time: String,
    duration: String,
    req_headers: Vec<(String, String)>,
    resp_headers: Vec<(String, String)>,
    req_body: Option<String>,
    resp_body: Option<String>,
    content_type: Option<String>,
}

#[derive(Clone)]
struct Node {
    name: String,
    children: Vec<Node>,
    count: u32,
    leaf: bool,
}

impl Node {
    fn new(name: &str) -> Self {
        Self { name: name.into(), children: Vec::new(), count: 0, leaf: false }
    }

    fn insert(&mut self, segs: &[&str]) {
        self.count += 1;
        match segs.split_first() {
            None => self.leaf = true,
            Some((first, rest)) => {
                let child = match self.children.iter_mut().find(|c| c.name == *first) {
                    Some(c) => c,
                    None => {
                        self.children.push(Node::new(first));
                        self.children.last_mut().unwrap()
                    }
                };
                child.insert(rest);
            }
        }
    }
}

#[derive(Clone)]
struct TreeRoot {
    host: String,
    secure: bool,
    count: u32,
    root: Node,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab { Overview, Request, Response, Timing }

#[derive(Clone, Default)]
struct SslLocations {
    enabled: bool,
    include: Vec<String>,
    exclude: Vec<String>,
}

#[derive(Clone)]
struct RecCaptureConfig {
    include: Vec<String>,
    exclude: Vec<String>,
}

impl Default for RecCaptureConfig {
    fn default() -> Self {
        Self { include: vec!["*".to_string()], exclude: Vec::new() }
    }
}

impl RecCaptureConfig {
    fn allows(&self, host: &str) -> bool {
        if self.exclude.iter().any(|p| host_pat_matches(p, host)) {
            return false;
        }
        self.include.iter().any(|p| host_pat_matches(p, host))
    }
}

/// Паттерны хостов для Recording settings (`*`, `*.example.com`, `host`).
fn host_pat_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim();
    if p == "*" || p.is_empty() {
        return true;
    }
    if let Some(suf) = p.strip_prefix("*.") {
        let h = host.to_ascii_lowercase();
        let s = suf.to_ascii_lowercase();
        h == s || h.ends_with(&format!(".{s}"))
    } else {
        p.eq_ignore_ascii_case(host)
    }
}

/// Host часть для capture-фильтра (у CONNECT `host:port` — отрезаем порт).
fn capture_host(ex: &rproxy_core::Exchange) -> String {
    match &ex.request {
        Some(r) if r.is_connect => r.uri.split(':').next().unwrap_or(&r.uri).to_string(),
        Some(r) => {
            let rest = r.uri.as_str()
                .strip_prefix("https://").or_else(|| r.uri.as_str().strip_prefix("http://"))
                .unwrap_or(r.uri.as_str());
            rest.split('/').next().unwrap_or(rest).to_string()
        }
        None => String::new(),
    }
}

#[derive(PartialEq, Clone, Copy)]
enum SslTab { Locations, RootCert }

enum DialogKind { Ssl, Recording, Proxy, Breakpoints }

struct App {
    port: u16,
    /// Порт из поля ввода настроек (старт/перезапуск без рестарта приложения).
    port_text: String,
    bus: EventBus,
    tx: std::sync::mpsc::Sender<GuiEv>,
    autotake: bool,
    recording: bool,
    filter: String,
    sel_host: Option<(String, String)>, // (host, path prefix)
    tab: Tab,
    sel_row: Option<u32>,
    body_pretty: bool,
    rows: Vec<Row>,
    trees: Vec<TreeRoot>,
    exchanges: Vec<rproxy_core::Exchange>,
    about: bool,
    install_win: bool,
    install_msg: Option<String>,
    /// Кэш проверки «CA в доверенных» (None = ещё не проверяли).
    ca_trusted: Option<bool>,
    listening: bool,
    bind_error: Option<String>,
    win_proxy: bool,
    proxy_msg: Option<String>,
    /// Показывать дерево хостов слева (Structure view); иначе — только список.
    show_tree: bool,
    /// Текущее состояние системного прокси Windows (сверяется периодически).
    sys_on: bool,
    sys_proxy: Option<String>,
    last_proxy_poll: std::time::Instant,
    /// Результат последнего тестового запроса (пустой экран).
    /// Размер окна на прошлом кадре — чтобы поймать ресайз и перерисоваться.
    last_size: egui::Vec2,
    test_msg: Option<String>,
    test_running: bool,
    want_test: bool,
    rec_cfg: RecCaptureConfig,
    ssl_cfg: Option<Arc<std::sync::RwLock<rproxy_core::SslProxyConfig>>>,
    ssl_enabled: bool,
    open_dialogs: Vec<DialogKind>,
    ssl_win_open: bool,
    recording_win_open: bool,
    proxy_win_open: bool,
    ssl_tab: SslTab,
    ssl_locs: SslLocations,
    ssl_inc_new: String,
    ssl_exc_new: String,
    ssl_msg: Option<String>,
    rec_inc_new: String,
    rec_exc_new: String,
    bp_open: bool,
    bp_hub: Arc<rproxy_core::BreakpointHub>,
    bp_on: bool,
    bp_pattern: String,
    pending_bp: Vec<Row>,
    rx: Receiver<GuiEv>,
}

enum GuiEv {
    Done(rproxy_core::Exchange),
    Bp(rproxy_core::Exchange),
    /// Движок не смог стартовать уже после запуска окна (показать в UI).
    EngineError(String),
    /// Результат тестового запроса из фонового потока.
    TestResult(Result<(), String>),
}

fn now_str() -> String {
    let d = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let (h, m, s) = ((d.as_secs() / 3600) % 24, (d.as_secs() / 60) % 60, d.as_secs() % 60);
    format!("{h:02}:{m:02}:{s:02}.{:03}", d.subsec_millis())
}

// ---------------- SVG-иконки ----------------
// Авторские иконки (24×24, белый штрих) лежат в crates/rproxy-gui/assets/icons/*.svg
// и встраиваются в бинарь. Цвет задаётся через Image::tint — поэтому один и тот же
// файл работает и для обычного, и для «активного» (зелёный/красный) состояния.

fn icon_img(name: &str) -> egui::Image<'static> {
    let (uri, bytes): (&'static str, &'static [u8]) = match name {
        "list" => ("bytes://icon-list.svg", include_bytes!("../assets/icons/list.svg")),
        "tree" => ("bytes://icon-tree.svg", include_bytes!("../assets/icons/tree.svg")),
        "trash" => ("bytes://icon-trash.svg", include_bytes!("../assets/icons/trash.svg")),
        "record" => ("bytes://icon-record.svg", include_bytes!("../assets/icons/record.svg")),
        "pause" => ("bytes://icon-pause.svg", include_bytes!("../assets/icons/pause.svg")),
        "lock" => ("bytes://icon-lock.svg", include_bytes!("../assets/icons/lock.svg")),
        "save" => ("bytes://icon-save.svg", include_bytes!("../assets/icons/save.svg")),
        "gear" => ("bytes://icon-gear.svg", include_bytes!("../assets/icons/gear.svg")),
        "bolt" => ("bytes://icon-bolt.svg", include_bytes!("../assets/icons/bolt.svg")),
        "deny" => ("bytes://icon-deny.svg", include_bytes!("../assets/icons/deny.svg")),
        _ => ("bytes://icon-globe.svg", include_bytes!("../assets/icons/globe.svg")),
    };
    egui::Image::from_bytes(uri, bytes).fit_to_exact_size(egui::vec2(18.0, 18.0))
}

fn icon_button(ui: &mut egui::Ui, name: &str, tint: Color32, tip: &str) -> egui::Response {
    ui.add(egui::ImageButton::new(icon_img(name).tint(tint))).on_hover_text(tip)
}

/// Цветная точка статуса: ok = зелёная, warn = оранжевая, иначе красная.
/// Рисуем сами (а не символом «●»), иначе в шрифте egui нет глифа и выходит квадрат.
fn status_dot(ui: &mut egui::Ui, ok: bool, warn: bool) {
    let c = if ok { GREEN } else if warn { ORANGE } else { RED };
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, c);
}

/// Тестовый запрос через собственный прокси: локальный одноразовый HTTP-сервер
/// принимает соединение, запрос идёт через 127.0.0.1:{port}. Если в таблице
/// появилась строка — движок и GUI живы, проблема была в маршрутизации трафика.
///
/// Вызывается ТОЛЬКО из фонового потока и никогда не ждёт бесконечно: у сервера
/// есть дедлайн на accept, у клиента — таймауты чтения/записи.
fn self_test(port: u16) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    let srv = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let addr = srv.local_addr().map_err(|e| e.to_string())?;
    srv.set_nonblocking(true).map_err(|e| e.to_string())?;

    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            match srv.accept() {
                Ok((mut s, _)) => {
                    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf);
                    let body = "{\"ok\":true,\"source\":\"rproxy self-test\"}";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = s.write_all(resp.as_bytes());
                    let _ = s.flush();
                    let _ = s.shutdown(std::net::Shutdown::Both);
                    return;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return; // прокси так и не подключился к origin
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return,
            }
        }
    });

    let mut c = std::net::TcpStream::connect(("127.0.0.1", port))
        .map_err(|e| format!("cannot connect to proxy on 127.0.0.1:{port}: {e}"))?;
    c.set_read_timeout(Some(Duration::from_secs(6))).ok();
    c.set_write_timeout(Some(Duration::from_secs(6))).ok();
    let req = format!(
        "GET http://{addr}/self-test HTTP/1.1\r\nHost: {addr}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    c.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let read_res = c.read_to_end(&mut out); // вернётся по EOF или таймауту, но не повиснет
    let _ = c.shutdown(std::net::Shutdown::Both);
    let _ = server.join();

    if out.is_empty() {
        return Err(format!("no response from proxy (read: {read_res:?})"));
    }
    let head = String::from_utf8_lossy(&out[..out.len().min(200)]).to_string();
    if head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200") {
        Ok(())
    } else {
        Err(format!("unexpected reply: {}", head.lines().next().unwrap_or("")))
    }
}

impl Row {
    fn body_str(b: &Option<bytes::Bytes>) -> Option<String> {
        b.as_ref().and_then(|b| {
            (b.len() > 0).then(|| match std::str::from_utf8(b) {
                Ok(s) => s.to_string(),
                Err(_) => format!("[binary, {} bytes]", b.len()),
            })
        })
    }

    fn from(ex: &rproxy_core::Exchange) -> Self {
        let (method, host, path, locked) = match &ex.request {
            Some(r) if r.is_connect => ("CONNECT".into(), r.uri.clone(), "*".into(), true),
            Some(r) => {
                let rest = r.uri.as_str()
                    .strip_prefix("https://").or_else(|| r.uri.as_str().strip_prefix("http://"))
                    .unwrap_or(r.uri.as_str());
                let (h, p) = match rest.split_once('/') {
                    Some((h, p)) => (h, format!("/{p}")),
                    None => (rest, "/".to_string()),
                };
                (r.method.clone(), h.to_string(), p, false)
            }
            None => ("-".into(), "-".into(), "-".into(), false),
        };
        let resp = ex.response_body_decoded.as_ref().or(ex.response_body.as_ref());
        Self {
            id: ex.id.0 as u32,
            locked, method, host, path,
            status: ex.response_status.unwrap_or(0),
            time: now_str(),
            duration: ex.timing.total().map(|d| format!("{d:.1?}")).unwrap_or_else(|| "-".into()),
            req_headers: ex.request.as_ref().map(|r| r.headers.clone()).unwrap_or_default(),
            resp_headers: ex.response_headers.clone(),
            req_body: Self::body_str(&ex.request_body),
            resp_body: resp.cloned().and_then(|b| Self::body_str(&Some(b))),
            content_type: ex.response_content_type.clone(),
        }
    }

    fn url(&self) -> String {
        format!("{}://{}{}", if self.locked { "https" } else { "http" }, self.host, self.path)
    }

    fn is_json(&self) -> bool {
        self.content_type.as_deref().map_or(false, |ct| ct.contains("json"))
    }

    fn method_color(m: &str) -> Color32 {
        match m {
            "GET" => Color32::from_rgb(0x3A, 0x8F, 0xD6),
            "POST" => Color32::from_rgb(0x3A, 0xA1, 0x5A),
            "PUT" => Color32::from_rgb(0xB5, 0x86, 0x2A),
            "DELETE" => Color32::from_rgb(0xC0, 0x46, 0x3F),
            "PATCH" => Color32::from_rgb(0x7A, 0x5C, 0xC9),
            "CONNECT" => Color32::from_rgb(0x6E, 0x6E, 0x6E),
            _ => Color32::GRAY,
        }
    }

    fn status_color(s: u16) -> Color32 {
        match s {
            200..=299 => Color32::from_rgb(0x2E, 0x9E, 0x4B),
            300..=399 => Color32::from_rgb(0xC9, 0x8A, 0x1A),
            0 => DIM,
            _ => Color32::from_rgb(0xD0, 0x40, 0x3A),
        }
    }
}

impl App {
    fn new(
        rx: Receiver<GuiEv>,
        tx: std::sync::mpsc::Sender<GuiEv>,
        bus: EventBus,
        port: u16,
        bp_hub: Arc<rproxy_core::BreakpointHub>,
        ssl_cfg: Option<Arc<std::sync::RwLock<rproxy_core::SslProxyConfig>>>,
        listening: bool,
        bind_error: Option<String>,
        win_proxy: bool,
        autotake: bool,
    ) -> Self {
        let (ssl_enabled, ssl_locs) = match &ssl_cfg {
            Some(cfg) => {
                let c = cfg.read().map(|c| c.clone()).unwrap_or_default();
                (
                    c.enabled,
                    SslLocations {
                        enabled: c.enabled,
                        include: c.include.clone(),
                        exclude: c.exclude.clone(),
                    },
                )
            }
            None => (false, SslLocations::default()),
        };
        Self {
            port, port_text: port.to_string(), bus, tx, autotake,
            recording: true, filter: String::new(), sel_host: None,
            tab: Tab::Overview, sel_row: None, body_pretty: true, rows: Vec::new(),
            trees: Vec::new(), exchanges: Vec::new(), about: false,
            install_win: false, install_msg: None, ca_trusted: None,
            listening, bind_error, win_proxy, proxy_msg: None,
            show_tree: true, sys_on: false, sys_proxy: None,
            last_proxy_poll: std::time::Instant::now(),
            last_size: egui::Vec2::ZERO,
            test_msg: None, test_running: false, want_test: false,
            rec_cfg: RecCaptureConfig::default(),
            ssl_cfg, ssl_enabled, open_dialogs: Vec::new(),
            ssl_win_open: false, recording_win_open: false, proxy_win_open: false,
            ssl_tab: SslTab::Locations, ssl_locs,
            ssl_inc_new: String::new(), ssl_exc_new: String::new(), ssl_msg: None,
            rec_inc_new: String::new(), rec_exc_new: String::new(),
            bp_open: false,
            bp_hub: bp_hub.clone(), bp_on: false, bp_pattern: String::new(),
            pending_bp: Vec::new(), rx,
        }
    }

    fn poll(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                GuiEv::Done(ex) if self.recording && self.rec_cfg.allows(&capture_host(&ex)) => {
                    self.rows.push(Row::from(&ex));
                    self.exchanges.push(ex);
                }
                GuiEv::Done(_) => {}
                GuiEv::Bp(ex) => self.pending_bp.push(Row::from(&ex)),
                GuiEv::TestResult(res) => {
                    self.test_running = false;
                    self.test_msg = Some(match res {
                        Ok(()) => {
                            "Test request passed through the proxy — the engine is working."
                                .to_string()
                        }
                        Err(e) => format!("Test request failed: {e}"),
                    });
                }
                GuiEv::EngineError(msg) => {
                    self.listening = false;
                    self.bind_error = Some(msg);
                }
            }
        }

        // Structure tree: хост → сегменты пути → leaf.
        self.trees.clear();
        for r in &self.rows {
            // У CONNECT нет пути (path = "*") — не строим из него фиктивное дерево.
            let segs: Vec<&str> = if r.path == "*" {
                Vec::new()
            } else {
                let base = r.path.split('?').next().unwrap_or("/");
                base.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect()
            };
            match self.trees.iter_mut().find(|t| t.host == r.host) {
                Some(t) => {
                    t.count += 1;
                    if t.root.children.is_empty() && segs.is_empty() {
                        t.root.leaf = true;
                        t.root.count += 1;
                    } else {
                        t.root.insert(&segs);
                    }
                }
                None => {
                    let mut root = Node::new(&r.host);
                    root.count = 1;
                    if segs.is_empty() {
                        root.leaf = true;
                    } else {
                        root.insert(&segs);
                    }
                    self.trees.push(TreeRoot { host: r.host.clone(), secure: r.locked, count: 1, root });
                }
            }
        }
        self.trees.sort_by(|a, b| b.count.cmp(&a.count).then(a.host.cmp(&b.host)));
    }

    fn visible(&self) -> Vec<&Row> {
        let f = self.filter.to_lowercase();
        self.rows.iter()
            .filter(|r| match &self.sel_host {
                None => true,
                Some((h, p)) => &r.host == h && (p.is_empty() || r.path.starts_with(p.as_str())),
            })
            .filter(|r| f.is_empty()
                || r.host.to_lowercase().contains(&f)
                || r.path.to_lowercase().contains(&f)
                || r.method.to_lowercase().contains(&f)
                || (f.len() >= 3 && (
                    r.req_body.as_deref().map_or(false, |b| b.to_lowercase().contains(&f))
                        || r.resp_body.as_deref().map_or(false, |b| b.to_lowercase().contains(&f))
                )))
            .collect()
    }
}


impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        // Восстановить системный прокси при закрытии окна (как Charles при quit).
        if ctx.input(|i| i.viewport().close_requested()) {
            restore_proxy_on_exit();
        }
        self.poll();
        // Системный прокси мог перехватить другой процесс (Charles) — сверяемся редко
        // и без окон: один `reg query` раз в 5 секунд.
        if self.last_proxy_poll.elapsed() >= std::time::Duration::from_secs(5) {
            self.last_proxy_poll = std::time::Instant::now();
            self.refresh_sys_proxy();
        }
        if std::mem::take(&mut self.want_test) && !self.test_running {
            // ВАЖНО: тест идёт в отдельном потоке — блокирующие сокеты на UI-потоке
            // подвешивают окно (Windows показывает «Не отвечает»).
            self.test_running = true;
            self.test_msg = None;
            let tx = self.tx.clone();
            let port = self.port;
            std::thread::spawn(move || {
                let _ = tx.send(GuiEv::TestResult(self_test(port)));
            });
        }
        self.menus(ctx);
        self.toolbar(ctx);
        if self.show_tree {
            egui::SidePanel::left("hosts")
                .resizable(true)
                .default_width(260.0)
                .min_width(180.0)
                .frame(egui::Frame::default().fill(PANEL).inner_margin(egui::Margin::same(4.0)))
                .show(ctx, |ui| self.tree(ui));
        }
        self.status_bar(ctx);
        egui::CentralPanel::default().show(ctx, |ui| self.central(ui));
        if self.install_win {
            self.install_win = self.install_dialog(ctx);
        }
        if self.about {
            self.about = self.about_dialog(ctx);
        }
        if self.bp_open || !self.pending_bp.is_empty() {
            self.bp_open = self.breakpoints_dialog(ctx);
        }
        // open_dialogs — это только очередь команд "открой мне такое-то окно",
        // приходящих из разных мест (меню, тулбар). Она разово переводится в
        // персистентные *_win_open флаги, которые затем проверяются КАЖДЫЙ кадр —
        // иначе (как было раньше) show_viewport_immediate вызывался бы только в
        // тот единственный кадр, когда очередь непуста, и окно тут же исчезало
        // на следующем кадре.
        for d in std::mem::take(&mut self.open_dialogs) {
            match d {
                DialogKind::Ssl => self.ssl_win_open = true,
                DialogKind::Recording => self.recording_win_open = true,
                DialogKind::Proxy => self.proxy_win_open = true,
                DialogKind::Breakpoints => self.bp_open = true,
            }
        }
        if self.ssl_win_open {
            self.ssl_win_open = self.ssl_win(ctx);
        }
        if self.recording_win_open {
            self.recording_win_open = self.recording_win(ctx);
        }
        if self.proxy_win_open {
            self.proxy_win_open = self.proxy_win(ctx);
        }
        // Во время ресайза окна/разделителя egui успевает отрисовать кадр по старой
        // раскладке — на Windows это видно как чёрная полоса между панелями.
        // Пока тянем мышью или размер изменился — перерисовываемся немедленно.
        let size = ctx.screen_rect().size();
        if (size - self.last_size).length() > 0.5 {
            self.last_size = size;
            ctx.request_repaint();
        }
        if ctx.input(|i| i.pointer.any_down()) {
            ctx.request_repaint();
        }
        if self.recording || self.test_running {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

impl App {
    fn menus(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu").frame(
            egui::Frame::default().fill(HEADER).inner_margin(egui::Margin::symmetric(4.0, 2.0))
        ).show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("New Session").clicked() {
                        self.rows.clear(); self.exchanges.clear();
                        self.sel_row = None; self.sel_host = None;
                        ui.close_menu();
                    }
                    if ui.button("Open Session…").clicked() { ui.close_menu(); }
                    ui.separator();
                    if ui.button("Clear Session").clicked() {
                        self.rows.clear(); self.exchanges.clear();
                        self.sel_row = None; self.sel_host = None;
                        ui.close_menu();
                    }
                    if ui.button("Close Session").clicked() { ui.close_menu(); }
                    ui.separator();
                    if ui.button("Save Session").clicked() { ui.close_menu(); }
                    if ui.button("Save session as HAR…").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("HAR", &["har"]).set_file_name("session.har").save_file()
                        {
                            match rproxy_export::write_har(&path, &self.exchanges) {
                                Ok(()) => println!("[rproxy] HAR saved: {}", path.display()),
                                Err(e) => eprintln!("[rproxy] HAR save failed: {e}"),
                            }
                        }
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Import…").clicked() { ui.close_menu(); }
                    if ui.button("Export Session…").clicked() { ui.close_menu(); }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Edit", |ui| {
                    let can = self.rows.iter().any(|r| Some(r.id) == self.sel_row);
                    let _ = ui.add_enabled(false, egui::Button::new("Undo"));
                    let _ = ui.add_enabled(false, egui::Button::new("Redo"));
                    ui.separator();
                    let _ = ui.add_enabled(false, egui::Button::new("Cut"));
                    if ui.add_enabled(can, egui::Button::new("Copy URL")).clicked() {
                        if let Some(r) = self.rows.iter().find(|r| Some(r.id) == self.sel_row) {
                            ctx.copy_text(r.url());
                        }
                        ui.close_menu();
                    }
                    let _ = ui.add_enabled(false, egui::Button::new("Paste"));
                    if ui.button("Select All").clicked() { ui.close_menu(); }
                    ui.separator();
                    if ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Find…").desired_width(140.0)).changed() {}
                    ui.separator();
                    if ui.button("Settings…").clicked() {
                        self.open_dialogs.push(DialogKind::Proxy);
                        ui.close_menu();
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.label(RichText::new("Session view").color(DIM));
                    if ui.radio(self.show_tree, "Structure (tree of hosts)").clicked() {
                        self.show_tree = true;
                        ui.close_menu();
                    }
                    if ui.radio(!self.show_tree, "Sequence (flat list)").clicked() {
                        self.show_tree = false;
                        ui.close_menu();
                    }
                    ui.separator();
                    let mut wrap = self.body_pretty;
                    if ui.checkbox(&mut wrap, "Auto-format response body").changed() {
                        self.body_pretty = wrap;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Expand All").clicked() { ui.close_menu(); }
                    if ui.button("Collapse All").clicked() { ui.close_menu(); }
                });
                ui.menu_button("Proxy", |ui| {
                    let rec = if self.recording { "Stop recording" } else { "Start recording" };
                    if ui.button(rec).clicked() { self.recording = !self.recording; ui.close_menu(); }
                    let ssl = if self.ssl_enabled { "Stop SSL proxying" } else { "Start SSL proxying" };
                    if ui.button(ssl).clicked() { self.toggle_ssl(); ui.close_menu(); }
                    let mut bp = self.bp_on;
                    if ui.checkbox(&mut bp, "Enable breakpoints").changed() {
                        self.bp_on = bp;
                        self.bp_hub.set_enabled(bp);
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Recording settings…").clicked() {
                        self.open_dialogs.push(DialogKind::Recording); ui.close_menu();
                    }
                    if ui.button("SSL proxying settings…").clicked() {
                        self.sync_ssl_from_engine();
                        self.open_dialogs.push(DialogKind::Ssl); ui.close_menu();
                    }
                    if ui.button("Proxy settings…").clicked() {
                        self.open_dialogs.push(DialogKind::Proxy); ui.close_menu();
                    }
                    if ui.button("Breakpoints settings…").clicked() {
                        self.open_dialogs.push(DialogKind::Breakpoints); ui.close_menu();
                    }
                    ui.separator();
                    // Галка отражает РЕАЛЬНОЕ состояние реестра (его может менять Charles).
                    self.win_proxy = self.sys_proxy_is_ours();
                    if ui.checkbox(&mut self.win_proxy, "Windows proxy").changed() {
                        match set_windows_proxy(self.win_proxy, self.port) {
                            Ok(()) => {
                                self.proxy_msg = if self.win_proxy {
                                    Some(format!("System proxy set to 127.0.0.1:{}", self.port))
                                } else {
                                    None
                                };
                            }
                            Err(e) => {
                                self.win_proxy = !self.win_proxy;
                                self.proxy_msg = Some(format!("Windows proxy failed: {e}"));
                            }
                        }
                        self.refresh_sys_proxy();
                    }
                });
                ui.menu_button("Tools", |ui| {
                    if ui.button("Send test request through proxy").clicked() {
                        self.want_test = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    let soon = "Not implemented yet";
                    let _ = ui.add_enabled(false, egui::Button::new("No caching…")).on_hover_text(soon);
                    let _ = ui.add_enabled(false, egui::Button::new("Block cookies…")).on_hover_text(soon);
                    ui.separator();
                    let _ = ui.add_enabled(false, egui::Button::new("Map Remote…")).on_hover_text(soon);
                    let _ = ui.add_enabled(false, egui::Button::new("Map Local…")).on_hover_text(soon);
                    let _ = ui.add_enabled(false, egui::Button::new("Rewrite…")).on_hover_text(soon);
                    ui.separator();
                    let _ = ui.add_enabled(false, egui::Button::new("Block list…")).on_hover_text(soon);
                    let _ = ui.add_enabled(false, egui::Button::new("Compose")).on_hover_text(soon);
                    let _ = ui.add_enabled(false, egui::Button::new("Repeat")).on_hover_text(soon);
                });
                ui.menu_button("Window", |ui| {
                    let _ = ui.button("Minimize");
                    let _ = ui.button("Zoom");
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("About rproxy").clicked() { self.about = true; ui.close_menu(); }
                    ui.separator();
                    ui.menu_button("SSL proxying", |ui| {
                        if ui.button("About rproxy Root Certificate").clicked() {
                            self.about = true; ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Install rproxy Root Certificate").clicked() {
                            self.install_win = true; ui.close_menu();
                        }
                        if ui.button("Install Root Certificate on a mobile device or remote browser").clicked() {
                            self.install_win = true; ui.close_menu();
                        }
                        if ui.button("Save rproxy Root Certificate…").clicked() {
                            match save_ca() {
                                Ok(p) => println!("[rproxy] CA saved: {}", p.display()),
                                Err(e) => eprintln!("[rproxy] CA save failed: {e}"),
                            }
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Export Root Certificate and private key…").clicked() { ui.close_menu(); }
                        if ui.button("Show generated SSL certificates keystore password").clicked() { ui.close_menu(); }
                        ui.separator();
                        if ui.button("Reset rproxy Root Certificate…").clicked() { ui.close_menu(); }
                    });
                    ui.separator();
                    if ui.button("Check for updates").clicked() { ui.close_menu(); }
                    if ui.button("Visit website").clicked() { ui.close_menu(); }
                });
                }); // закрыли egui::menu::bar
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak(RichText::new("rproxy 0.1.0").color(DIM));
                });
            });
    }
    fn toolbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar").frame(
            egui::Frame::default().fill(HEADER).inner_margin(egui::Margin::symmetric(6.0, 4.0))
        ).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 3.0;

                // --- Вид сессии: список / дерево ---
                if icon_button(ui, "list", if self.show_tree { DIM } else { TEXT },
                    "Sequence view — только список запросов").clicked() {
                    self.show_tree = false;
                }
                if icon_button(ui, "tree", if self.show_tree { TEXT } else { DIM },
                    "Structure view — дерево хостов").clicked() {
                    self.show_tree = true;
                }
                ui.separator();

                // --- Сессия ---
                if icon_button(ui, "trash", TEXT, "Clear session").clicked() {
                    self.rows.clear();
                    self.exchanges.clear();
                    self.sel_row = None;
                    self.sel_host = None;
                }
                let (rec_icon, rec_tint, rec_tip) = if self.recording {
                    ("pause", RED, "Stop recording")
                } else {
                    ("record", GREEN, "Start recording")
                };
                if icon_button(ui, rec_icon, rec_tint, rec_tip).clicked() {
                    self.recording = !self.recording;
                }
                ui.separator();

                // --- SSL ---
                if icon_button(ui, "lock", if self.ssl_enabled { GREEN } else { DIM },
                    "SSL proxying settings").clicked() {
                    self.sync_ssl_from_engine();
                    self.open_dialogs.push(DialogKind::Ssl);
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 3.0;
                    if icon_button(ui, "gear", TEXT, "Proxy settings").clicked() {
                        self.open_dialogs.push(DialogKind::Proxy);
                    }
                    if icon_button(ui, "save", TEXT, "Save session as HAR…").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("HAR", &["har"]).set_file_name("session.har").save_file()
                        {
                            let _ = rproxy_export::write_har(&path, &self.exchanges);
                        }
                    }
                    if icon_button(ui, "bolt", TEXT,
                        "Send a test request through the proxy (проверка, что движок жив)").clicked() {
                        self.want_test = true;
                    }
                    ui.separator();
                    if icon_button(ui, "deny", if self.bp_on { ORANGE } else { DIM },
                        "Breakpoints: on / off").clicked() {
                        self.bp_on = !self.bp_on;
                        self.bp_hub.set_enabled(self.bp_on);
                    }
                });
            });
        });
    }


    /// Запустить (или повторить запуск) движок на текущем порту.
    fn start_engine(&mut self) {
        match spawn_engine(self.port, &self.bus, &self.bp_hub, self.ssl_cfg.clone(), &self.tx) {
            Ok(()) => {
                self.listening = true;
                self.bind_error = None;
                self.proxy_msg = Some(format!("Listening on 127.0.0.1:{}", self.port));
                if self.autotake {
                    let _ = set_windows_proxy(true, self.port);
                }
                self.refresh_sys_proxy();
            }
            Err(e) => {
                self.listening = false;
                self.bind_error = Some(e);
            }
        }
    }

    /// Перечитать реальное состояние системного прокси Windows (его мог
    /// перехватить другой процесс — Charles при старте/выходе).
    fn refresh_sys_proxy(&mut self) {
        #[cfg(windows)]
        {
            let s = query_proxy_settings();
            self.sys_on = s.enable.unwrap_or(0) != 0;
            self.sys_proxy = s.server;
        }
    }

    /// Системный прокси сейчас указывает именно на этот rproxy?
    fn sys_proxy_is_ours(&self) -> bool {
        self.sys_on
            && self.sys_proxy
                .as_deref()
                .map(|v| v.contains(&format!("127.0.0.1:{}", self.port)))
                .unwrap_or(false)
    }

    fn toggle_ssl(&mut self) {
        self.ssl_enabled = !self.ssl_enabled;
        self.ssl_locs.enabled = self.ssl_enabled;
        if let Some(cfg) = &self.ssl_cfg {
            if let Ok(mut c) = cfg.write() {
                c.enabled = self.ssl_enabled;
            }
        }
    }

    fn sync_ssl_from_engine(&mut self) {
        if let Some(cfg) = &self.ssl_cfg {
            if let Ok(c) = cfg.read() {
                self.ssl_enabled = c.enabled;
                self.ssl_locs = SslLocations {
                    enabled: c.enabled,
                    include: c.include.clone(),
                    exclude: c.exclude.clone(),
                };
            }
        }
    }

    fn apply_ssl_to_engine(&mut self) {
        if let Some(cfg) = &self.ssl_cfg {
            if let Ok(mut c) = cfg.write() {
                c.enabled = self.ssl_locs.enabled;
                c.include = self.ssl_locs.include.clone();
                c.exclude = self.ssl_locs.exclude.clone();
            }
        }
        self.ssl_enabled = self.ssl_locs.enabled;
    }

    fn about_dialog(&mut self, ctx: &egui::Context) -> bool {
        let mut open = true;
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("About rproxy"),
            egui::ViewportBuilder::default().with_title("About rproxy").with_inner_size([420.0, 220.0]),
            |ctx, _| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label(RichText::new("rproxy").heading());
                    ui.label("Open-source web debugging proxy (Charles Proxy alternative)");
                    ui.label(format!("Proxy: http://127.0.0.1:{}", self.port));
                    ui.label("MITM HTTPS: enabled (CA in %USERPROFILE%\\.rproxy\\ca.cert.pem)");
                    ui.add_space(6.0);
                    if ui.button("Close").clicked() {
                        open = false;
                    }
                });
            },
        );
        open
    }

    fn proxy_win(&mut self, ctx: &egui::Context) -> bool {
        let mut open = true;
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("Proxy settings"),
            egui::ViewportBuilder::default()
                .with_title("Proxy settings")
                .with_inner_size([460.0, 260.0]),
            |ctx, _| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    open = false;
                }
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label(RichText::new("HTTP Proxy").strong());
                    ui.horizontal(|ui| {
                        ui.weak("Address:");
                        ui.monospace(format!("127.0.0.1:{}", self.port));
                        ui.weak(if self.listening {
                            RichText::new("listening").color(GREEN)
                        } else {
                            RichText::new("not running").color(RED)
                        });
                    });
                    ui.monospace(format!(
                        "System value: http=127.0.0.1:{0};https=127.0.0.1:{0}",
                        self.port
                    ));
                    ui.separator();
                    ui.label(RichText::new("Port").strong());
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.port_text)
                                .desired_width(64.0)
                                .hint_text("8888"),
                        );
                        if ui.add_enabled(!self.listening, egui::Button::new("Start proxy")).clicked() {
                            if let Ok(p) = self.port_text.trim().parse::<u16>() {
                                self.port = p;
                            }
                            self.start_engine();
                        }
                        ui.weak(if self.listening {
                            "to change the port, restart the app"
                        } else {
                            "port is free — press Start"
                        });
                    });
                    if let Some(err) = &self.bind_error {
                        if !self.listening {
                            ui.colored_label(RED, err);
                        }
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Copy proxy address").clicked() {
                            ctx.copy_text(format!("http://127.0.0.1:{}", self.port));
                        }
                        if ui.button("Close").clicked() {
                            open = false;
                        }
                    });
                });
            },
        );
        open
    }

    /// Окно сертификата в духе Charles: крупное, со статусом доверия,
    /// авто-установкой через UAC и понятной ручной инструкцией.
    fn install_dialog(&mut self, ctx: &egui::Context) -> bool {
        let mut open = true;
        let ca = ca_file();
        if self.ca_trusted.is_none() {
            self.ca_trusted = Some(ca_installed());
        }
        let installed = self.ca_trusted.unwrap_or(false);
        let port = self.port;
        let lan_ip = local_ipv4().map(|i| i.to_string()).unwrap_or_else(|| "<this computer's IP>".into());
        let ca_path = ca.as_ref().ok().map(|p| p.display().to_string()).unwrap_or_default();
        let mut msg = self.install_msg.clone();
        let mut copy: Option<String> = None;
        let mut auto = false;
        let mut save = false;
        let mut recheck = false;

        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("Install root certificate"),
            egui::ViewportBuilder::default()
                .with_title("Root certificate — rproxy")
                .with_inner_size([720.0, 660.0])
                .with_min_inner_size([620.0, 560.0]),
            |ctx, _| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    open = false;
                }
                egui::CentralPanel::default()
                    .frame(egui::Frame::default().fill(BG).inner_margin(egui::Margin::same(18.0)))
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.add(icon_img("lock")
                                .tint(if installed { GREEN } else { ORANGE })
                                .fit_to_exact_size(egui::vec2(40.0, 40.0)));
                            ui.add_space(6.0);
                            ui.vertical(|ui| {
                                ui.label(RichText::new("rproxy Root Certificate").size(22.0).strong());
                                if installed {
                                    ui.label(RichText::new("Trusted on this computer").color(GREEN).strong());
                                } else {
                                    ui.label(RichText::new(
                                        "Not installed — browsers warn on every HTTPS site",
                                    ).color(ORANGE).strong());
                                }
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                                if ui.button("Refresh status").clicked() {
                                    recheck = true;
                                }
                            });
                        });
                        ui.add_space(6.0);
                        ui.label(RichText::new(
                            "rproxy decrypts HTTPS by signing certificates with its own root CA. \
Install it once and browsers will trust captured traffic.",
                        ).color(DIM));
                        ui.add_space(12.0);

                        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                            card(ui, "1 · Install on this computer", |ui| {
                                if installed {
                                    ui.label(RichText::new(
                                        "The certificate is already in the Trusted Root store.",
                                    ).color(GREEN));
                                    ui.add_space(4.0);
                                }
                                let label = if installed { "Reinstall certificate" } else { "Install certificate" };
                                let btn = egui::Button::new(RichText::new(label).strong().color(Color32::WHITE))
                                    .fill(SELECT)
                                    .rounding(4.0)
                                    .min_size(egui::vec2(0.0, 30.0));
                                if ui.add(btn).clicked() {
                                    auto = true;
                                }
                                ui.add_space(4.0);
                                ui.label(RichText::new(
                                    "Windows will ask for administrator permission (UAC).",
                                ).color(DIM));
                                if let Some(m) = &msg {
                                    ui.add_space(4.0);
                                    ui.label(RichText::new(m.clone()).color(if installed { GREEN } else { TEXT }));
                                }
                            });
                            ui.add_space(10.0);

                            card(ui, "2 · Manual installation", |ui| {
                                ui.label("1. Save the certificate to disk with the button below.");
                                ui.label("2. Double-click the saved file → Install Certificate…");
                                ui.label("3. Choose \"Local Machine\" → \"Place all certificates in the following store\".");
                                ui.label("4. Pick \"Trusted Root Certification Authorities\" → Next → Finish.");
                                ui.add_space(6.0);
                                ui.horizontal(|ui| {
                                    if ui.button("Save certificate…").clicked() {
                                        save = true;
                                    }
                                    if ui.button("Copy path").clicked() {
                                        copy = Some(ca_path.clone());
                                    }
                                });
                                if !ca_path.is_empty() {
                                    ui.add_space(2.0);
                                    ui.monospace(RichText::new(ca_path.clone()).color(DIM));
                                }
                            });
                            ui.add_space(10.0);

                            card(ui, "3 · Phone or tablet", |ui| {
                                ui.label(format!(
                                    "1. In the device Wi-Fi settings set the proxy to {lan_ip}:{port}."
                                ));
                                ui.label("2. Send the .cer file to the device and install it as a root certificate.");
                                ui.label("Android: Settings → Security → Encryption & credentials → Install a certificate → CA certificate.");
                                ui.label("iOS: install the profile, then Settings → General → About → Certificate Trust Settings → enable full trust.");
                            });
                        });

                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(
                                "After installing, restart the browser — it caches certificate decisions.",
                            ).color(DIM));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("Close").clicked() {
                                    open = false;
                                }
                            });
                        });
                    });
            },
        );

        if recheck {
            self.ca_trusted = Some(ca_installed());
            msg = Some(if self.ca_trusted == Some(true) {
                "Certificate found in Trusted Root.".into()
            } else {
                "Not found in Trusted Root yet — install it (UAC), then press Refresh status.".into()
            });
        }
        if save {
            if let Ok(src) = ca_file() {
                if let Some(dst) = rfd::FileDialog::new()
                    .add_filter("Certificate", &["cer", "crt", "pem"])
                    .set_file_name("rproxy-ca.cer")
                    .save_file()
                {
                    msg = Some(match std::fs::copy(&src, &dst) {
                        Ok(_) => format!("Saved to {}", dst.display()),
                        Err(e) => format!("Save failed: {e}"),
                    });
                }
            }
        }
        if auto {
            match ca.as_ref() {
                Ok(path) => match install_ca_auto(path) {
                    Ok(()) => {
                        msg = Some("UAC prompt opened — confirm it, then press \"Refresh status\".".into())
                    }
                    Err(e) => msg = Some(format!("Failed to start installer: {e}")),
                },
                Err(e) => msg = Some(format!("CA not found: {e}")),
            }
        }
        self.install_msg = msg;
        if let Some(t) = copy {
            ctx.copy_text(t);
        }
        open
    }


    fn breakpoints_dialog(&mut self, ctx: &egui::Context) -> bool {
        let mut open = true;
        let mut pattern = self.bp_pattern.clone();
        let mut enabled = self.bp_on;
        let pending: Vec<Row> = self.pending_bp.clone();
        let title = format!("Breakpoints ({})", pending.len());
        let mut decisions: Vec<(u32, rproxy_core::BreakpointDecision)> = Vec::new();
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("Breakpoints"),
            egui::ViewportBuilder::default().with_title(title).with_inner_size([480.0, 320.0]),
            |ctx, _| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("URL contains:");
                        ui.add(
                            egui::TextEdit::singleline(&mut pattern)
                                .hint_text("api.test")
                                .desired_width(160.0),
                        );
                        ui.checkbox(&mut enabled, "Enabled");
                    });
                    ui.separator();
                    for r in &pending {
                        ui.horizontal(|ui| {
                            ui.monospace(RichText::new(format!("{} {}", r.method, r.url())).color(TEXT));
                            if ui.button("Continue").clicked() {
                                decisions.push((r.id, rproxy_core::BreakpointDecision::Continue));
                            }
                            if ui.button("Drop").clicked() {
                                decisions.push((r.id, rproxy_core::BreakpointDecision::Drop));
                            }
                        });
                    }
                    if !pending.is_empty() {
                        ui.separator();
                        ui.horizontal(|ui| {
                            if ui.button("Continue all").clicked() {
                                for r in &pending {
                                    decisions.push((r.id, rproxy_core::BreakpointDecision::Continue));
                                }
                            }
                            if ui.button("Drop all").clicked() {
                                for r in &pending {
                                    decisions.push((r.id, rproxy_core::BreakpointDecision::Drop));
                                }
                            }
                        });
                    } else {
                        ui.weak("Held requests appear here when they match the pattern.");
                    }
                    if ui.button("Close").clicked() {
                        open = false;
                    }
                });
            },
        );
        if pattern != self.bp_pattern {
            self.bp_pattern = pattern.clone();
            self.bp_hub.set_pattern(pattern);
        }
        if enabled != self.bp_on {
            self.bp_on = enabled;
            self.bp_hub.set_enabled(enabled);
        }
        for (id, d) in decisions {
            self.bp_hub.resolve(id as u64, d);
            self.pending_bp.retain(|r| r.id != id);
        }
        open
    }


    fn recording_win(&mut self, ctx: &egui::Context) -> bool {
        let mut inc = self.rec_cfg.include.clone();
        let mut exc = self.rec_cfg.exclude.clone();
        let mut inc_new = std::mem::take(&mut self.rec_inc_new);
        let mut exc_new = std::mem::take(&mut self.rec_exc_new);
        let mut done = false;
        let mut open = true;
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("Recording settings"),
            egui::ViewportBuilder::default()
                .with_title("Recording settings")
                .with_inner_size([560.0, 380.0]),
            |ctx, _| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    open = false;
                }
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.weak("Only hosts matching Include (and not Exclude) go to the session.");
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new("Include").strong());
                            list_editor(ui, &mut inc, &mut inc_new, "host, e.g. *.example.com");
                        });
                        ui.vertical(|ui| {
                            ui.label(RichText::new("Exclude").strong());
                            list_editor(ui, &mut exc, &mut exc_new, "host");
                        });
                    });
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Reset").clicked() {
                            inc = vec!["*".to_string()];
                            exc.clear();
                        }
                        if ui.button("Done").clicked() {
                            done = true;
                            open = false;
                        }
                    });
                });
            },
        );
        self.rec_inc_new = inc_new;
        self.rec_exc_new = exc_new;
        if done {
            self.rec_cfg = RecCaptureConfig { include: inc, exclude: exc };
        }
        open
    }

    fn ssl_win(&mut self, ctx: &egui::Context) -> bool {
        let mut locs = self.ssl_locs.clone();
        let mut tab = self.ssl_tab;
        let mut inc_new = std::mem::take(&mut self.ssl_inc_new);
        let mut exc_new = std::mem::take(&mut self.ssl_exc_new);
        let mut msg = self.ssl_msg.clone();
        let mut done = false;
        let mut open = true;
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("SSL proxying settings"),
            egui::ViewportBuilder::default()
                .with_title("SSL proxying settings")
                .with_inner_size([640.0, 420.0]),
            |ctx, _| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    open = false;
                }
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        if ui.selectable_label(tab == SslTab::Locations, "SSL proxying").clicked() {
                            tab = SslTab::Locations;
                        }
                        if ui.selectable_label(tab == SslTab::RootCert, "Root certificate").clicked() {
                            tab = SslTab::RootCert;
                        }
                    });
                    ui.separator();
                    match tab {
                        SslTab::Locations => {
                            ui.weak("Only listed locations are proxied (MITM). Others go as tunnels.");
                            ui.checkbox(&mut locs.enabled, "Enable SSL proxying");
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(RichText::new("Include").strong());
                                    list_editor(ui, &mut locs.include, &mut inc_new, "*:*");
                                });
                                ui.vertical(|ui| {
                                    ui.label(RichText::new("Exclude").strong());
                                    list_editor(ui, &mut locs.exclude, &mut exc_new, "host");
                                });
                            });
                        }
                        SslTab::RootCert => {
                            ui.label(RichText::new("Charles Clone Root CA").strong());
                            match ca_file() {
                                Ok(p) => {
                                    ui.monospace(p.display().to_string());
                                    ui.horizontal(|ui| {
                                        if ui.button("Auto install (UAC)").clicked() {
                                            match install_ca_auto(&p) {
                                                Ok(()) => msg = Some("Started: confirm the UAC prompt.".into()),
                                                Err(e) => msg = Some(format!("Failed to start: {e}")),
                                            }
                                        }
                                        if ui.button("Copy path").clicked() {
                                            ctx.copy_text(p.display().to_string());
                                            msg = Some("Path copied".into());
                                        }
                                    });
                                }
                                Err(e) => {
                                    ui.colored_label(Color32::from_rgb(0xD0, 0x40, 0x3A), format!("CA not found: {e}"));
                                }
                            }
                        }
                    }
                    if let Some(m) = &msg {
                        ui.label(RichText::new(m.clone()).color(Color32::from_rgb(0x2E, 0x9E, 0x4B)));
                    }
                    ui.separator();
                    if ui.button("Done").clicked() {
                        done = true;
                        open = false;
                    }
                });
            },
        );
        self.ssl_inc_new = inc_new;
        self.ssl_exc_new = exc_new;
        self.ssl_tab = tab;
        self.ssl_msg = msg;
        if done {
            self.ssl_locs = locs;
            self.apply_ssl_to_engine();
        }
        open
    }

    fn tree(&mut self, ui: &mut egui::Ui) {
        let trees = self.trees.clone();
        let plain: Vec<&TreeRoot> = trees.iter().filter(|t| !t.secure).collect();
        let enc: Vec<&TreeRoot> = trees.iter().filter(|t| t.secure).collect();

        ui.add_space(4.0);
        egui::ScrollArea::vertical().id_salt("tree").auto_shrink(false).show(ui, |ui| {
            for t in &plain {
                self.host_tree(ui, t);
            }
            if !enc.is_empty() {
                egui::CollapsingHeader::new(
                    RichText::new(format!("Encrypted ({})", enc.len())).color(SELECT),
                )
                .default_open(true)
                .show(ui, |ui| {
                    for t in &enc {
                        self.host_tree(ui, t);
                    }
                });
            }
            if trees.is_empty() {
                ui.add_space(6.0);
                ui.weak(RichText::new("Hosts will appear here").color(DIM));
                ui.weak(RichText::new("as soon as traffic reaches the proxy.").color(DIM));
            }
            if self.sel_host.is_some() {
                ui.separator();
                if ui.button("Show all traffic").clicked() {
                    self.sel_host = None;
                }
            }
        });

        // Filter — закреплён внизу панели, как в Charles.
        egui::TopBottomPanel::bottom("tree_filter")
            .frame(egui::Frame::none().outer_margin(egui::Margin::symmetric(6.0, 6.0)))
            .show_inside(ui, |ui| {
                ui.add(egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter")
                    .desired_width(f32::INFINITY));
            });
    }

    /// Корень дерева: хост, под ним — дерево путей (Structure view как в Charles).
    fn host_tree(&mut self, ui: &mut egui::Ui, t: &TreeRoot) {
        let selected = self.sel_host.as_ref().map_or(false, |(h, _)| h == &t.host);
        ui.horizontal(|ui| {
            ui.add(icon_img(if t.secure { "lock" } else { "globe" })
                .tint(if selected { Color32::WHITE } else { DIM })
                .fit_to_exact_size(egui::vec2(13.0, 13.0)));
            let label = RichText::new(t.host.clone())
                .color(if selected { Color32::WHITE } else { TEXT });
            if ui.selectable_label(selected, label).clicked() {
                // клик по хосту: весь трафик хоста
                self.sel_host = if selected {
                    None
                } else {
                    Some((t.host.clone(), String::new()))
                };
                self.sel_row = None;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.weak(RichText::new(t.count.to_string()).color(DIM));
            });
        });
        if t.root.children.is_empty() {
            return;
        }
        egui::CollapsingHeader::new(RichText::new("Structure").color(DIM))
            .id_salt(format!("root|{}", t.host))
            .default_open(true)
            .show(ui, |ui| {
                let mut clicked: Option<(String, String)> = None;
                for child in &t.root.children {
                    self.node_row(ui, t, child, String::new(), &mut clicked);
                }
                if let Some(c) = clicked {
                    self.sel_host = Some(c);
                    self.sel_row = None;
                }
            });
    }

    fn node_row(
        &mut self,
        ui: &mut egui::Ui,
        t: &TreeRoot,
        node: &Node,
        prefix: String,
        clicked: &mut Option<(String, String)>,
    ) {
        let path = format!("{prefix}/{}", node.name);
        let node_id = format!("{}|{}", t.host, path);
        let is_leaf = node.children.is_empty() || node.leaf;
        let selected = self
            .sel_host
            .as_ref()
            .map_or(false, |(h, p)| h == &t.host && p == &path);

        if is_leaf {
            let label = RichText::new(node.name.clone())
                .color(if selected { Color32::WHITE } else { TEXT });
            if ui.selectable_label(selected, label).clicked() {
                *clicked = Some((t.host.clone(), path));
            }
            ui.weak(RichText::new(node.count.to_string()).color(DIM));
        } else {
            egui::CollapsingHeader::new(
                RichText::new(format!("{} ({})", node.name, node.count))
                    .color(if selected { Color32::WHITE } else { TEXT }),
            )
            .id_salt(node_id)
            .show(ui, |ui| {
                // клик по заголовку папки = фильтр по префиксу
                if ui.small_button("only this path").clicked() {
                    *clicked = Some((t.host.clone(), path.clone()));
                }
                for child in &node.children {
                    self.node_row(ui, t, child, path.clone(), clicked);
                }
            });
        }
    }

    /// Пустой экран: объясняет, почему трафика нет, и даёт кнопки починить.
    fn empty_state(&mut self, ui: &mut egui::Ui) {
        let port = self.port;
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(34.0);
                ui.add(icon_img("globe")
                    .tint(Color32::from_rgb(0x5F, 0x5F, 0x5F))
                    .fit_to_exact_size(egui::vec2(54.0, 54.0)));
                ui.add_space(10.0);
                ui.label(RichText::new("No traffic is coming through yet").size(20.0).color(TEXT));
                ui.add_space(4.0);
                ui.label(RichText::new(
                    "rproxy is running, but apps are not sending their traffic to it.")
                    .color(DIM));
                ui.add_space(20.0);

                egui::Frame::default()
                    .fill(PANEL)
                    .stroke(egui::Stroke::new(1.0, MENU_BORDER))
                    .rounding(8.0)
                    .inner_margin(egui::Margin::same(18.0))
                    .show(ui, |ui| {
                        ui.set_max_width(660.0);
                        ui.spacing_mut().item_spacing.y = 10.0;

                        // 1. Слушатель.
                        ui.horizontal(|ui| {
                            status_dot(ui, self.listening, false);
                            ui.label(RichText::new(format!("1. Proxy listens on 127.0.0.1:{port}")).strong());
                            if !self.listening {
                                ui.label(RichText::new(format!(
                                    "— {}",
                                    self.bind_error.clone().unwrap_or_else(|| "port is busy".into())
                                )).color(RED));
                                if ui.button("Start").clicked() {
                                    self.start_engine();
                                }
                            }
                        });

                        // 2. Системный прокси.
                        ui.horizontal(|ui| {
                            status_dot(ui, self.sys_proxy_is_ours(), self.sys_on);
                            ui.label("2.");
                            let txt = if self.sys_proxy_is_ours() {
                                "Windows system proxy → rproxy".to_string()
                            } else if self.sys_on {
                                format!(
                                    "Windows system proxy → {} — другой прокси (Charles?)",
                                    self.sys_proxy.clone().unwrap_or_default()
                                )
                            } else {
                                "Windows system proxy is off".to_string()
                            };
                            ui.label(RichText::new(txt).strong());
                            if !self.sys_proxy_is_ours() && self.listening
                                && ui.button("Use rproxy").clicked()
                            {
                                match set_windows_proxy(true, port) {
                                    Ok(()) => {
                                        self.win_proxy = true;
                                        self.proxy_msg = Some("System proxy → rproxy".into());
                                        set_sysproxy_pref(true);
                                    }
                                    Err(e) => self.proxy_msg = Some(format!("Windows proxy failed: {e}")),
                                }
                                self.refresh_sys_proxy();
                            }
                        });

                        // 3. HTTPS.
                        ui.horizontal(|ui| {
                            status_dot(ui, self.ssl_enabled, true);
                            ui.label("3.");
                            ui.label(RichText::new("HTTPS decryption").strong());
                            ui.label(if self.ssl_enabled {
                                "— on. Install the root certificate so browsers trust it."
                            } else {
                                "— off. Turn it on in Proxy ▸ Start SSL proxying."
                            });
                            if ui.button("Install certificate…").clicked() {
                                self.install_win = true;
                            }
                        });

                        ui.add_space(2.0);
                        ui.separator();
                        ui.horizontal(|ui| {
                            let label = if self.test_running { "Testing…" } else { "Send a test request" };
                            if ui
                                .add_enabled(
                                    !self.test_running,
                                    egui::Button::new(RichText::new(label).strong().color(Color32::WHITE))
                                        .fill(SELECT)
                                        .rounding(4.0)
                                        .min_size(egui::vec2(0.0, 24.0)),
                                )
                                .clicked()
                            {
                                self.want_test = true;
                            }
                            ui.label(RichText::new(
                                "— one request through the proxy; a row must appear instantly.")
                                .color(DIM));
                        });

                        if let Some(m) = &self.test_msg {
                            let ok = m.starts_with("Test request passed");
                            ui.label(RichText::new(m).color(if ok { GREEN } else { RED }));
                        }

                        ui.add_space(2.0);
                        ui.label(RichText::new(
                            "Apps with their own proxy setting (Telegram, Postman, curl, mobile) \
must be pointed to http://127.0.0.1:8888 themselves.")
                            .color(DIM));
                        if let Some(m) = &self.proxy_msg {
                            ui.label(RichText::new(m).color(DIM));
                        }
                    });
            });
        });
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        let port = self.port;
        let sys_ours = self.sys_proxy_is_ours();
        let sys_on = self.sys_on;
        let sys_val = self.sys_proxy.clone().unwrap_or_default();
        let listening = self.listening;
        let recording = self.recording;
        let bp_on = self.bp_on;
        let mut sys_clicked = false;
        egui::TopBottomPanel::bottom("status").frame(
            egui::Frame::default().fill(HEADER).inner_margin(egui::Margin::symmetric(6.0, 2.0))
        ).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(
                    if listening {
                        format!("Listening on 127.0.0.1:{port}")
                    } else {
                        "Not listening".to_string()
                    },
                ).color(if listening { GREEN } else { RED }));

                ui.separator();
                // Системный прокси — главный индикатор «почему нет трафика».
                let (chip, tip) = if !cfg!(windows) {
                    ("System proxy: n/a".to_string(), "Only on Windows".to_string())
                } else if sys_ours {
                    (format!("System proxy: 127.0.0.1:{port}"), "Traffic is routed through rproxy".to_string())
                } else if sys_on {
                    (format!("System proxy: {sys_val}"), "System proxy points to another proxy".to_string())
                } else {
                    ("System proxy: OFF".to_string(), "Turn on to capture apps that use the system proxy".to_string())
                };
                let color = if !cfg!(windows) { DIM } else if sys_ours { GREEN } else if sys_on { ORANGE } else { RED };
                if ui.add(egui::Label::new(RichText::new(format!(" {chip} ")).color(color)).sense(egui::Sense::click()))
                    .on_hover_text(format!("{tip} — click to toggle"))
                    .clicked()
                {
                    sys_clicked = true;
                }

                ui.label(RichText::new(
                    if recording { "Recording started" } else { "Recording stopped" },
                ).color(DIM));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(if recording { " Recording " } else { " Stopped " })
                        .background_color(if recording { GREEN } else { Color32::from_rgb(0x55, 0x55, 0x55) })
                        .color(Color32::WHITE));
                    ui.separator();
                    if bp_on {
                        ui.label(RichText::new(" Breakpoints ")
                            .background_color(ORANGE)
                            .color(Color32::WHITE));
                    }
                });
            });
            ui.add_space(2.0);
        });
        if sys_clicked && cfg!(windows) {
            let enable = !sys_ours;
            self.win_proxy = enable;
            let _ = set_windows_proxy(enable, port);
            set_sysproxy_pref(enable);
            self.refresh_sys_proxy();
        }
    }


    fn central(&mut self, ui: &mut egui::Ui) {
        // Движок не поднялся: не молчим и не просим перезапускать приложение —
        // показываем ошибку и даём кнопку повторить прямо здесь.
        if !self.listening {
            let err = self.bind_error.clone().unwrap_or_else(|| "not started".into());
            egui::Frame::default()
                .fill(Color32::from_rgb(0x4A, 0x24, 0x22))
                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(0x7A, 0x35, 0x30)))
                .rounding(6.0)
                .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Proxy is not running").strong().color(Color32::WHITE));
                        ui.label(RichText::new(err).color(Color32::from_rgb(0xFF, 0xC4, 0xBD)));
                    });
                    ui.horizontal(|ui| {
                        ui.label("Port:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.port_text)
                                .desired_width(64.0)
                                .hint_text("8888"),
                        );
                        let start = egui::Button::new(
                            RichText::new("Start proxy").strong().color(Color32::WHITE),
                        )
                        .fill(SELECT)
                        .rounding(4.0);
                        if ui.add(start).clicked() {
                            if let Ok(p) = self.port_text.trim().parse::<u16>() {
                                self.port = p;
                            }
                            self.start_engine();
                        }
                        ui.label(RichText::new(
                            "port is probably taken — close the other proxy (Charles) or pick another port",
                        ).color(DIM));
                    });
                });
            ui.add_space(6.0);
        }
        if self.rows.is_empty() {
            self.empty_state(ui);
            return;
        }

        // Детали снизу (resizable), таблица занимает остальное.
        egui::TopBottomPanel::bottom("detail_panel")
            .resizable(true)
            .default_height(ui.available_height() * 0.45)
            .frame(egui::Frame::none().inner_margin(egui::Margin::same(6.0)))
            .show_inside(ui, |ui| self.detail(ui));

        egui::ScrollArea::both().id_salt("seq").auto_shrink(false).show(ui, |ui| {
            self.table(ui);
        });
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        let rows = self.visible();
        let sel_row = self.sel_row;
        let clicked = egui::Grid::new("seq_grid")
            .num_columns(7)
            .striped(true)
            .spacing([12.0, 4.0])
            .min_col_width(50.0)
            .show(ui, |ui| {
                ui.strong("");
                ui.strong("Method");
                ui.strong("Host");
                ui.strong("Path");
                ui.strong("Status");
                ui.strong("Time");
                ui.strong("Duration");
                ui.end_row();

                let mut clicked = None;
                for r in &rows {
                    let sel = sel_row == Some(r.id);

                    ui.add(icon_img(if r.locked { "lock" } else { "globe" })
                        .tint(if sel { Color32::WHITE } else { DIM })
                        .fit_to_exact_size(egui::vec2(13.0, 13.0)));
                    let mc = Row::method_color(&r.method);
                    if ui.selectable_label(sel, RichText::new(r.method.as_str()).color(Color32::WHITE).background_color(mc)).clicked() { clicked = Some(r.id); }
                    if ui.selectable_label(sel, RichText::new(r.host.as_str()).color(if sel { Color32::WHITE } else { TEXT })).clicked() { clicked = Some(r.id); }
                    if ui.selectable_label(sel, RichText::new(r.path.as_str()).color(if sel { Color32::WHITE } else { TEXT })).clicked() { clicked = Some(r.id); }
                    let st = RichText::new(r.status.to_string()).color(Row::status_color(r.status)).strong();
                    if ui.selectable_label(sel, st).clicked() { clicked = Some(r.id); }
                    if ui.selectable_label(sel, RichText::new(r.time.as_str()).color(DIM)).clicked() { clicked = Some(r.id); }
                    if ui.selectable_label(sel, RichText::new(r.duration.as_str()).color(DIM)).clicked() { clicked = Some(r.id); }
                    ui.end_row();
                }
                clicked
            });
            if let Some(id) = clicked.inner { self.sel_row = Some(id); }
    }



    fn detail(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for (t, l) in [(Tab::Overview, "Overview"), (Tab::Request, "Request"), (Tab::Response, "Response"), (Tab::Timing, "Timing")] {
                if ui.selectable_label(self.tab == t, l).clicked() { self.tab = t; }
            }
            if matches!(self.tab, Tab::Request | Tab::Response) {
                ui.separator();
                ui.checkbox(&mut self.body_pretty, "Pretty");
            }
        });
        ui.separator();

        let Some(r) = self.rows.iter().find(|r| Some(r.id) == self.sel_row).cloned() else {
            ui.weak("Выберите запрос в таблице");
            return;
        };

        egui::ScrollArea::vertical().id_salt("det").auto_shrink(false).show(ui, |ui| {
            match self.tab {
                Tab::Overview => {
                    egui::Grid::new("ov").num_columns(2).spacing([16.0, 3.0]).show(ui, |ui| {
                        ui.weak("URL"); ui.monospace(r.url()); ui.end_row();
                        ui.weak("Method"); ui.monospace(r.method.as_str()); ui.end_row();
                        ui.weak("Status"); ui.monospace(RichText::new(r.status.to_string()).color(Row::status_color(r.status))); ui.end_row();
                        ui.weak("Host"); ui.monospace(r.host.as_str()); ui.end_row();
                        ui.weak("Duration"); ui.monospace(r.duration.as_str()); ui.end_row();
                    });
                }
                Tab::Request => {
                    ui.monospace(format!("{} {} HTTP/1.1", r.method, r.path));
                    section(ui, "Headers");
                    for (k, v) in &r.req_headers {
                        ui.monospace(RichText::new(format!("{k}: {v}")).color(TEXT));
                    }
                    section(ui, "Body");
                    if let Some(b) = &r.req_body {
                        ui.monospace(b.as_str());
                    } else {
                        ui.weak("(пусто)");
                    }
                }
                Tab::Response => {
                    ui.monospace(format!("HTTP/1.1 {}", r.status));
                    section(ui, "Headers");
                    for (k, v) in &r.resp_headers {
                        ui.monospace(RichText::new(format!("{k}: {v}")).color(TEXT));
                    }
                    section(ui, "Body");
                    if self.body_pretty && r.is_json() {
                        if let Some(text) = &r.resp_body {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
                                Self::json_tree(ui, "json", &v, 0);
                                return;
                            }
                        }
                    }
                    if let Some(b) = &r.resp_body {
                        ui.monospace(b.as_str());
                    } else {
                        ui.weak("(пусто)");
                    }
                }
                Tab::Timing => {
                    ui.monospace(format!("Total: {}", r.duration));
                }
            }
        });
    }

    fn json_tree(ui: &mut egui::Ui, key: &str, value: &serde_json::Value, depth: usize) {
        if depth > 20 { ui.weak("…"); return; }
        match value {
            serde_json::Value::Object(map) => {
                egui::CollapsingHeader::new(RichText::new(format!("{key} {{{}}}", map.len())).color(TEXT))
                    .default_open(depth < 2)
                    .show(ui, |ui| {
                        for (k, v) in map { Self::json_tree(ui, k, v, depth + 1); }
                    });
            }
            serde_json::Value::Array(arr) => {
                egui::CollapsingHeader::new(RichText::new(format!("{key} [{}]", arr.len())).color(TEXT))
                    .default_open(depth < 2)
                    .show(ui, |ui| {
                        for (i, v) in arr.iter().enumerate() {
                            Self::json_tree(ui, &i.to_string(), v, depth + 1);
                        }
                    });
            }
            other => {
                let text = match other {
                    serde_json::Value::String(s) => s.clone(),
                    o => o.to_string(),
                };
                ui.horizontal(|ui| {
                    if !key.is_empty() { ui.weak(format!("{key}:")); }
                    ui.monospace(text);
                });
            }
        }
    }
}

/// Файл CA с именем charles-clone (создаётся из ca.cert.pem при первом обращении).
fn ca_file() -> std::io::Result<std::path::PathBuf> {
    let dir = rproxy_cert::default_ca_dir().ok_or_else(|| std::io::Error::other("no home dir"))?;
    let cer = dir.join("charles-clone.cer");
    if !cer.exists() {
        std::fs::copy(dir.join("ca.cert.pem"), &cer)?;
    }
    Ok(cer)
}

/// Наш CA уже в «Доверенных корневых сертификатах» этого компьютера?
#[cfg(windows)]
fn ca_installed() -> bool {
    let Ok(out) = run_hidden("certutil", &["-store", "Root"]) else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout)
        .to_lowercase()
        .contains("charles clone root ca")
}

#[cfg(not(windows))]
fn ca_installed() -> bool {
    false
}

/// Локальный IPv4 этого компьютера (для инструкции «поставь прокси на телефоне»).
/// UDP-сокет ничего не отправляет — connect лишь выбирает маршрут.
fn local_ipv4() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

/// Auto: элевированный certutil добавляет CA в Trusted Root.
fn install_ca_auto(path: &std::path::Path) -> std::io::Result<()> {
    let cmd = format!(
        "Start-Process certutil -ArgumentList '-addstore','-f','Root','{}' -Verb RunAs -Wait",
        path.display()
    );
    run_hidden("powershell", &["-NoProfile", "-Command", &cmd])?;
    Ok(())
}

/// Запуск дочернего процесса БЕЗ консольного окна.
///
/// Приложение собрано с `windows_subsystem = "windows"`, поэтому у него нет своей
/// консоли — и каждый консольный потомок (`reg.exe`, `powershell.exe`) получает
/// новое чёрное окно, которое сразу закрывается. При частых вызовах это выглядит
/// как шторм мигающих терминалов, поэтому глушим окно через CREATE_NO_WINDOW.
fn run_hidden(program: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut c = std::process::Command::new(program);
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c.output()
}

#[cfg(windows)]
const INTERNET_SETTINGS: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Установить/снять системный прокси Windows (HKCU) и обновить WinINET.
///
/// Формат — как у Charles: `ProxyServer` вида
/// `http=127.0.0.1:{port};https=127.0.0.1:{port}` (поле «Port» остаётся пустым),
/// `ProxyOverride=<local>`.
#[cfg(windows)]
fn set_windows_proxy(enable: bool, port: u16) -> std::io::Result<()> {
    let key = INTERNET_SETTINGS;
    if enable {
        snapshot_proxy_settings();
        reg_set_dword(key, "ProxyEnable", 1)?;
        reg_set_sz(
            key,
            "ProxyServer",
            &format!("http=127.0.0.1:{port};https=127.0.0.1:{port}"),
        )?;
        reg_set_sz(key, "ProxyOverride", "<local>")?;
    } else {
        reg_set_dword(key, "ProxyEnable", 0)?;
        restore_proxy_settings();
    }
    // Честное уведомление WinINET (без rundll32-костыля: сигнатуры не совпадают,
    // система уведомление не получала и браузеры ходили напрямую).
    notify_wininet();
    Ok(())
}

#[cfg(not(windows))]
fn set_windows_proxy(_enable: bool, _port: u16) -> std::io::Result<()> {
    Err(std::io::Error::other("system proxy supported on Windows only"))
}

/// Снапшот исходных ProxyEnable/ProxyServer/ProxyOverride (один раз за сессию),
/// чтобы при выключении/выходе вернуть всё как было (как делает Charles при quit).
#[cfg(windows)]
fn snapshot_proxy_settings() {
    static DONE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    DONE.get_or_init(|| {
        let cur = query_proxy_settings();
        let _ = SNAPSHOT.set(cur);
    });
}

#[cfg(windows)]
static SNAPSHOT: std::sync::OnceLock<ProxySettings> = std::sync::OnceLock::new();

#[cfg(windows)]
#[derive(Debug, Clone, Default)]
struct ProxySettings {
    enable: Option<u32>,
    server: Option<String>,
    over: Option<String>,
}

#[cfg(windows)]
fn query_proxy_settings() -> ProxySettings {
    // Один вызов reg вместо трёх: забираем весь ключ и разбираем нужные значения.
    let mut s = ProxySettings::default();
    let Ok(out) = run_hidden("reg", &["query", INTERNET_SETTINGS]) else {
        return s;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut parts = line.trim().split_whitespace();
        let (Some(name), Some(kind)) = (parts.next(), parts.next()) else {
            continue;
        };
        let value = parts.collect::<Vec<_>>().join(" ");
        match name {
            "ProxyEnable" if kind.starts_with("REG_DWORD") => {
                let hex = value.trim_start_matches("0x");
                s.enable = u32::from_str_radix(hex, 16).ok().or_else(|| value.parse().ok());
            }
            "ProxyServer" => s.server = Some(value),
            "ProxyOverride" => s.over = Some(value),
            _ => {}
        }
    }
    s
}

#[cfg(windows)]
fn restore_proxy_settings() {
    if let Some(snap) = SNAPSHOT.get() {
        let key = INTERNET_SETTINGS;
        match snap.enable {
            Some(v) => {
                let _ = reg_set_dword(key, "ProxyEnable", v);
            }
            None => {
                let _ = reg_delete(key, "ProxyEnable");
            }
        }
        match &snap.server {
            Some(v) => {
                let _ = reg_set_sz(key, "ProxyServer", v);
            }
            None => {
                let _ = reg_delete(key, "ProxyServer");
            }
        }
        match &snap.over {
            Some(v) => {
                let _ = reg_set_sz(key, "ProxyOverride", v);
            }
            None => {
                let _ = reg_delete(key, "ProxyOverride");
            }
        }
    }
}

/// Восстановить снапшот при выходе из приложения (чтобы не оставить систему
/// с прокси на мёртвый 127.0.0.1).
#[cfg(windows)]
pub(crate) fn restore_proxy_on_exit() {
    if SNAPSHOT.get().is_some() {
        restore_proxy_settings();
        notify_wininet();
    }
}

#[cfg(not(windows))]
pub(crate) fn restore_proxy_on_exit() {}

#[cfg(windows)]
fn reg_set_dword(key: &str, name: &str, val: u32) -> std::io::Result<()> {
    let v = val.to_string();
    let out = run_hidden("reg", &["add", key, "/v", name, "/t", "REG_DWORD", "/d", &v, "/f"])?;
    if out.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("reg add {name} failed")))
    }
}

#[cfg(windows)]
fn reg_set_sz(key: &str, name: &str, val: &str) -> std::io::Result<()> {
    let out = run_hidden("reg", &["add", key, "/v", name, "/t", "REG_SZ", "/d", val, "/f"])?;
    if out.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("reg add {name} failed")))
    }
}

#[cfg(windows)]
fn reg_delete(key: &str, name: &str) -> std::io::Result<()> {
    let out = run_hidden("reg", &["delete", key, "/v", name, "/f"])?;
    if out.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("reg delete {name} failed")))
    }
}

/// Прямой вызов WinINET (без rundll32): 39 = SETTINGS_CHANGED, 37 = REFRESH.
#[cfg(windows)]
fn notify_wininet() {
    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionA(
            h: *mut std::ffi::c_void,
            opt: u32,
            buf: *mut std::ffi::c_void,
            len: u32,
        ) -> i32;
    }
    unsafe {
        InternetSetOptionA(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0);
        InternetSetOptionA(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0);
    }
}

fn list_editor(ui: &mut egui::Ui, items: &mut Vec<String>, draft: &mut String, hint: &str) {
    let mut remove: Option<usize> = None;
    egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
        for (i, it) in items.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.checkbox(&mut true, it);
                if ui.small_button("x").clicked() {
                    remove = Some(i);
                }
            });
        }
    });
    if let Some(i) = remove {
        items.remove(i);
    }
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(draft).hint_text(hint).desired_width(140.0));
        if ui.button("+").clicked() && !draft.trim().is_empty() {
            items.push(draft.trim().to_string());
            draft.clear();
        }
        if ui.button("-").clicked() {
            items.pop();
        }
    });
}

fn section(ui: &mut egui::Ui, label: &str) {
    ui.add_space(2.0);
    ui.label(RichText::new(label).strong().color(DIM));
    ui.separator();
}

/// Скруглённая карточка-секция с рамкой, как блоки "Build New Pack" / "Open / Verify Pack"
/// в референсной проге — используем в диалогах вместо плоского CentralPanel.
fn card<R>(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::default()
        .fill(HEADER)
        .stroke(egui::Stroke::new(1.0, MENU_BORDER))
        .rounding(8.0)
        .inner_margin(egui::Margin::same(12.0))
        .show(ui, |ui| {
            ui.label(RichText::new(title).strong());
            ui.add_space(4.0);
            body(ui)
        })
        .inner
}

/// Файл настроек GUI (~/.rproxy/gui.conf). Сейчас один флаг — перехватывать ли
/// системный прокси Windows при старте.
fn pref_file() -> Option<std::path::PathBuf> {
    rproxy_cert::default_ca_dir().map(|d| d.join("gui.conf"))
}

/// Запоминаем выбор пользователя, чтобы автоперехват не включался «сам собой»:
/// иначе после аварийного закрытия система остаётся с прокси на мёртвый порт
/// и сеть «падает» целиком.
fn sysproxy_pref() -> bool {
    pref_file()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.lines().any(|l| l.trim() == "system_proxy=1"))
        .unwrap_or(false)
}

fn set_sysproxy_pref(on: bool) {
    let Some(path) = pref_file() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, format!("system_proxy={}\n", u8::from(on)));
}

fn save_ca() -> std::io::Result<std::path::PathBuf> {
    let dir = rproxy_cert::default_ca_dir().ok_or_else(|| std::io::Error::other("no home dir"))?;
    let dst = std::path::PathBuf::from("rproxy-ca.pem");
    std::fs::copy(dir.join("ca.cert.pem"), &dst)?;
    Ok(dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Кнопка «Send a test request» не должна ни виснуть, ни врать:
    /// запрос реально проходит через движок и возвращается 200.
    /// Тест гоняет ровно тот же путь, что и приложение: spawn_engine.
    #[test]
    fn self_test_roundtrip_through_proxy() {
        let (tx, rx) = channel::<GuiEv>();
        let bus = EventBus::new();
        let mut sub = bus.subscribe();
        let hub = Arc::new(rproxy_core::BreakpointHub::default());
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        spawn_engine(port, &bus, &hub, None, &tx).expect("engine must start");
        std::thread::sleep(std::time::Duration::from_millis(150));

        let res = self_test(port);
        let mut details = Vec::new();
        while let Ok(ev) = sub.try_recv() {
            if let ProxyEvent::ExchangeCompleted(ex) = ev {
                details.push(format!("state={:?} status={:?} error={:?}", ex.state, ex.response_status, ex.error));
            }
        }
        match res {
            Ok(()) => {}
            Err(e) => panic!("self-test failed: {e}; exchanges: {details:?}"),
        }
        drop(rx);
    }
}