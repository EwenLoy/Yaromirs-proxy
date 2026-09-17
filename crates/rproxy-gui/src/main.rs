use eframe::egui;
use egui::{Color32, RichText};
use rproxy_core::{EventBus, ProxyEvent, ProxyServer};
use std::sync::mpsc::{channel, Receiver};
use std::time::SystemTime;

const BG: Color32 = Color32::from_rgb(0x2B, 0x2B, 0x2B);
const PANEL: Color32 = Color32::from_rgb(0x33, 0x33, 0x33);
const SELECT: Color32 = Color32::from_rgb(0x2F, 0x6F, 0xED);
const TEXT: Color32 = Color32::from_rgb(0xD4, 0xD4, 0xD4);
const DIM: Color32 = Color32::from_rgb(0x8A, 0x8A, 0x8A);

fn main() -> eframe::Result<()> {
    let port: u16 = std::env::var("RPROXY_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8888);
    let (tx, rx) = channel::<rproxy_core::Exchange>();
    let bus = EventBus::new();

    let bus2 = bus.clone();
    std::thread::Builder::new().name("rproxy-engine".into()).spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio");
        rt.block_on(async move {
            let mut sub = bus2.subscribe();
            tokio::spawn(async move {
                loop {
                    match sub.recv().await {
                        Ok(ProxyEvent::ExchangeCompleted(ex)) => { let _ = tx.send(ex); }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(_) => continue,
                    }
                }
            });
            let server = ProxyServer::new(bus2, rproxy_core::Pipeline::new()).with_mitm();
            let _ = server.run(&format!("127.0.0.1:{port}")).await;
        });
    }).expect("engine thread");

    eframe::run_native(
        "rproxy",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1240.0, 780.0])
                .with_min_inner_size([900.0, 560.0]),
            ..Default::default()
        },
        Box::new(move |cc| {
            setup_style(&cc.egui_ctx);
            Ok(Box::new(App::new(rx, port)))
        }),
    )
}

fn setup_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals.dark_mode = true;
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = Color32::from_rgb(0x24, 0x24, 0x24);
    style.visuals.selection.bg_fill = SELECT;
    style.visuals.selection.stroke = egui::Stroke::NONE;
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x3E, 0x3E, 0x3E);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(0x46, 0x46, 0x46);
    style.visuals.widgets.inactive.bg_fill = Color32::TRANSPARENT;
    style.visuals.widgets.noninteractive.bg_fill = Color32::TRANSPARENT;
    style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.override_text_color = Some(TEXT);
    style.spacing.item_spacing = egui::vec2(6.0, 3.0);
    style.spacing.button_padding = egui::vec2(6.0, 2.0);
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
struct Host {
    name: String,
    secure: bool,
    count: u32,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab { Overview, Request, Response, Timing }

struct App {
    port: u16,
    recording: bool,
    ssl_hint: bool,
    filter: String,
    sel_host: Option<String>,
    tab: Tab,
    sel_row: Option<u32>,
    body_pretty: bool,
    rows: Vec<Row>,
    hosts: Vec<Host>,
    exchanges: Vec<rproxy_core::Exchange>,
    about: bool,
    rx: Receiver<rproxy_core::Exchange>,
}

fn now_str() -> String {
    let d = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let (h, m, s) = ((d.as_secs() / 3600) % 24, (d.as_secs() / 60) % 60, d.as_secs() % 60);
    format!("{h:02}:{m:02}:{s:02}.{:03}", d.subsec_millis())
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
    fn new(rx: Receiver<rproxy_core::Exchange>, port: u16) -> Self {
        Self {
            port, recording: true, ssl_hint: true, filter: String::new(), sel_host: None,
            tab: Tab::Overview, sel_row: None, body_pretty: true, rows: Vec::new(),
            hosts: Vec::new(), exchanges: Vec::new(), about: false, rx,
        }
    }

    fn poll(&mut self) {
        while let Ok(ex) = self.rx.try_recv() {
            if self.recording {
                self.rows.push(Row::from(&ex));
                self.exchanges.push(ex);
            }
        }
        self.hosts.clear();
        for r in &self.rows {
            match self.hosts.iter_mut().find(|h| h.name == r.host) {
                Some(h) => h.count += 1,
                None => self.hosts.push(Host { name: r.host.clone(), secure: r.locked, count: 1 }),
            }
        }
        self.hosts.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));
    }

    fn visible(&self) -> Vec<&Row> {
        let f = self.filter.to_lowercase();
        self.rows.iter()
            .filter(|r| self.sel_host.as_ref().map_or(true, |h| &r.host == h))
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
        self.poll();
        self.menus(ctx);
        self.toolbar(ctx);
        egui::SidePanel::left("hosts")
            .resizable(true)
            .default_width(260.0)
            .min_width(180.0)
            .show(ctx, |ui| self.tree(ui));
        self.status_bar(ctx);
        egui::CentralPanel::default().show(ctx, |ui| self.central(ui));
        if self.about {
            egui::Window::new("About rproxy").collapsible(false).show(ctx, |ui| {
                ui.label(RichText::new("rproxy").heading());
                ui.label("Open-source web debugging proxy (Charles Proxy alternative)");
                ui.label(format!("Proxy: http://127.0.0.1:{}", self.port));
                ui.label("MITM HTTPS: enabled (CA in %USERPROFILE%\\.rproxy\\ca.cert.pem)");
            });
        }
        if self.recording {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

impl App {
    fn menus(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Clear Session").clicked() {
                        self.rows.clear(); self.exchanges.clear();
                        self.sel_row = None; self.sel_host = None;
                        ui.close_menu();
                    }
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
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Edit", |ui| {
                    let can = self.rows.iter().any(|r| Some(r.id) == self.sel_row);
                    if ui.add_enabled(can, egui::Button::new("Copy URL")).clicked() {
                        if let Some(r) = self.rows.iter().find(|r| Some(r.id) == self.sel_row) {
                            ctx.copy_text(r.url());
                        }
                        ui.close_menu();
                    }
                });
                ui.menu_button("Proxy", |ui| {
                    let rec = if self.recording { "Stop recording" } else { "Start recording" };
                    if ui.button(rec).clicked() { self.recording = !self.recording; ui.close_menu(); }
                    ui.checkbox(&mut self.ssl_hint, "SSL proxying");
                    ui.add_enabled(false, egui::Checkbox::new(&mut false, "Windows proxy"))
                        .on_hover_text("Планируется (M10)");
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("About rproxy").clicked() { self.about = true; ui.close_menu(); }
                    if ui.button("Save CA certificate…").clicked() {
                        match save_ca() {
                            Ok(p) => println!("[rproxy] CA saved: {}", p.display()),
                            Err(e) => eprintln!("[rproxy] CA save failed: {e}"),
                        }
                        ui.close_menu();
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak(RichText::new("rproxy 0.1.0").color(DIM));
                });
            });
        });
    }

    fn toolbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                if ui.button("🗑").on_hover_text("Clear session").clicked() {
                    self.rows.clear(); self.exchanges.clear(); self.sel_row = None;
                }
                if ui.button("✏").on_hover_text("Compose (M6)").clicked() {}
                if ui.button("⟳").on_hover_text("Repeat (M6)").clicked() {}
                ui.separator();
                let rec = if self.recording { "⏸" } else { "⏺" };
                if ui.button(rec).on_hover_text("Record").clicked() { self.recording = !self.recording; }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⛔").on_hover_text("Breakpoints (M6)").clicked() {}
                    if ui.button("🐢").on_hover_text("Throttle (M8)").clicked() {}
                    ui.separator();
                    if ui.button("💾").on_hover_text("Save session as HAR").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("HAR", &["har"]).set_file_name("session.har").save_file()
                        {
                            let _ = rproxy_export::write_har(&path, &self.exchanges);
                        }
                    }
                });
            });
            ui.add_space(2.0);
        });
    }


    fn tree(&mut self, ui: &mut egui::Ui) {
        let hosts = self.hosts.clone();
        let plain: Vec<&Host> = hosts.iter().filter(|h| !h.secure).collect();
        let enc: Vec<&Host> = hosts.iter().filter(|h| h.secure).collect();

        ui.add_space(4.0);
        egui::ScrollArea::vertical().id_salt("tree").auto_shrink(false).show(ui, |ui| {
            for h in &plain {
                self.host_row(ui, &h.name, h.secure, h.count);
            }
            if !enc.is_empty() {
                egui::CollapsingHeader::new(
                    RichText::new(format!("🔒 Encrypted ({})", enc.len())).color(SELECT),
                )
                .default_open(true)
                .show(ui, |ui| {
                    for h in &enc {
                        self.host_row(ui, &h.name, h.secure, h.count);
                    }
                });
            }
            if hosts.is_empty() {
                ui.weak("No traffic yet");
                ui.weak(format!("Proxy: http://127.0.0.1:{}", self.port));
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

    fn host_row(&mut self, ui: &mut egui::Ui, name: &str, secure: bool, count: u32) {
        let selected = self.sel_host.as_deref() == Some(name);
        let icon = if secure { "🔒" } else { "🌐" };
        ui.horizontal(|ui| {
            let label = RichText::new(format!("{icon} {name}"))
                .color(if selected { Color32::WHITE } else { TEXT });
            if ui.selectable_label(selected, label).clicked() {
                self.sel_host = if selected { None } else { Some(name.to_string()) };
                self.sel_row = None;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.weak(RichText::new(count.to_string()).color(DIM));
            });
        });
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(
                    if self.recording { "Recording started" } else { "Recording stopped" },
                ).color(DIM));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.recording {
                        ui.label(RichText::new(" Recording ")
                            .background_color(Color32::from_rgb(0x2E, 0x9E, 0x4B))
                            .color(Color32::WHITE));
                    }
                });
            });
            ui.add_space(2.0);
        });
    }


    fn central(&mut self, ui: &mut egui::Ui) {
        if self.rows.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() * 0.35);
                ui.label(RichText::new("No traffic yet").size(18.0).color(DIM));
                ui.label(RichText::new(format!("Route apps via http://127.0.0.1:{}", self.port)).color(DIM));
            });
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

                    if ui.selectable_label(sel, if r.locked { "🔒" } else { "🌐" }).clicked() { clicked = Some(r.id); }
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
                egui::CollapsingHeader::new(RichText::new(format!("📁 {key} {{{}}}", map.len())).color(TEXT))
                    .default_open(depth < 2)
                    .show(ui, |ui| {
                        for (k, v) in map { Self::json_tree(ui, k, v, depth + 1); }
                    });
            }
            serde_json::Value::Array(arr) => {
                egui::CollapsingHeader::new(RichText::new(format!("📁 {key} [{}]", arr.len())).color(TEXT))
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

fn section(ui: &mut egui::Ui, label: &str) {
    ui.add_space(2.0);
    ui.label(RichText::new(label).strong().color(DIM));
    ui.separator();
}

fn save_ca() -> std::io::Result<std::path::PathBuf> {
    let dir = rproxy_cert::default_ca_dir().ok_or_else(|| std::io::Error::other("no home dir"))?;
    let dst = std::path::PathBuf::from("rproxy-ca.pem");
    std::fs::copy(dir.join("ca.cert.pem"), &dst)?;
    Ok(dst)
}
