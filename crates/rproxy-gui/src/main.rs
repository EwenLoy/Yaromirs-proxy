use eframe::egui;
use egui::{Color32, RichText};
use rproxy_core::{EventBus, ProxyEvent, ProxyServer};
use std::sync::mpsc::{channel, Receiver};
use std::time::SystemTime;

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
            eprintln!("[rproxy-gui] proxy on http://127.0.0.1:{port} (HTTP + MITM HTTPS)");
            let _ = server.run(&format!("127.0.0.1:{port}")).await;
        });
    }).expect("engine thread");

    eframe::run_native(
        "rproxy",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 800.0]),
            ..Default::default()
        },
        Box::new(move |cc| {
            cc.egui_ctx.set_pixels_per_point(1.0);
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(App::new(rx, port)))
        }),
    )
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
    rows: Vec<Row>,
    hosts: Vec<Host>,
    about: bool,
    rx: Receiver<rproxy_core::Exchange>,
}

fn now_str() -> String {
    let d = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let (h, m, s) = ((d.as_secs() / 3600) % 24, (d.as_secs() / 60) % 60, d.as_secs() % 60);
    format!("{h:02}:{m:02}:{s:02}.{:03}", d.subsec_millis())
}

impl Row {
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
        Self {
            id: ex.id.0 as u32,
            locked,
            method,
            host,
            path,
            status: ex.response_status.unwrap_or(0),
            time: now_str(),
            duration: ex.timing.total().map(|d| format!("{d:.1?}")).unwrap_or_else(|| "-".into()),
        }
    }
    fn url(&self) -> String {
        format!("{}://{}{}", if self.locked { "https" } else { "http" }, self.host, self.path)
    }
}

impl App {
    fn new(rx: Receiver<rproxy_core::Exchange>, port: u16) -> Self {
        Self {
            port, recording: true, ssl_hint: true, filter: String::new(), sel_host: None,
            tab: Tab::Overview, sel_row: None, rows: Vec::new(), hosts: Vec::new(),
            about: false, rx,
        }
    }

    fn poll(&mut self) {
        while let Ok(ex) = self.rx.try_recv() {
            if self.recording {
                self.rows.push(Row::from(&ex));
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
                || r.method.to_lowercase().contains(&f))
            .collect()
    }
}


impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.poll();
        self.menus(ctx);
        self.toolbar(ctx);
        egui::SidePanel::left("hosts").resizable(true).default_width(280.0).show(ctx, |ui| self.tree(ui));
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
                        self.rows.clear();
                        self.sel_row = None;
                        self.sel_host = None;
                        ui.close_menu();
                    }
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Edit", |ui| {
                    let can_copy = self.rows.iter().any(|r| Some(r.id) == self.sel_row);
                    if ui.add_enabled(can_copy, egui::Button::new("Copy URL")).clicked() {
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
                            Ok(p) => println!("[rproxy] CA сохранён: {}", p.display()),
                            Err(e) => eprintln!("[rproxy] CA save failed: {e}"),
                        }
                        ui.close_menu();
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak("rproxy");
                });
            });
        });
    }

    fn toolbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("🗑").on_hover_text("Clear").clicked() {
                    self.rows.clear();
                    self.sel_row = None;
                }
                if ui.button("✏").on_hover_text("Compose (M6)").clicked() {}
                if ui.button("⟳").on_hover_text("Repeat (M6)").clicked() {}
                ui.separator();
                let rec = if self.recording { "⏸" } else { "⏺" };
                if ui.button(rec).on_hover_text("Record").clicked() { self.recording = !self.recording; }
                ui.separator();
                if ui.button("🐢").on_hover_text("Throttle (M8)").clicked() {}
                if ui.button("⛔").on_hover_text("Breakpoints (M6)").clicked() {}
            });
        });
    }

    fn tree(&mut self, ui: &mut egui::Ui) {
        let hosts = self.hosts.clone(); // избежать borrow-конфликта с host_row
        let n_enc = hosts.iter().filter(|h| h.secure).count();
        ui.add_space(4.0);
        for h in hosts.iter().filter(|h| !h.secure) {
            self.host_row(ui, &h.name, h.secure);
        }
        if n_enc > 0 {
            egui::CollapsingHeader::new(RichText::new(format!("🔒 Encrypted ({n_enc})")).strong())
                .default_open(true)
                .show(ui, |ui| {
                    for h in hosts.iter().filter(|h| h.secure) {
                        self.host_row(ui, &h.name, h.secure);
                    }
                });
        }
        if self.hosts.is_empty() {
            ui.weak("No traffic yet");
            ui.weak(format!("Route via http://127.0.0.1:{}", self.port));
        }
        if !self.hosts.is_empty() && ui.button("Show all traffic").clicked() {
            self.sel_host = None;
        }

        // Фильтр — низ панели, как в Charles.
        egui::TopBottomPanel::bottom("tree_filter").show_inside(ui, |ui| {
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter"));
        });
    }

    fn host_row(&mut self, ui: &mut egui::Ui, name: &str, secure: bool) {
        let selected = self.sel_host.as_deref() == Some(name);
        let icon = if secure { "🔒" } else { "🌐" };
        if ui.selectable_label(selected, format!("{icon} {name}")).clicked() {
            self.sel_host = if selected { None } else { Some(name.to_string()) };
            self.sel_row = None;
        }
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(if self.recording { "Recording started" } else { "Recording stopped" });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.recording {
                        ui.label(RichText::new(" Recording ")
                            .background_color(Color32::from_rgb(46, 158, 75))
                            .color(Color32::WHITE));
                    }
                });
            });
        });
    }


    fn central(&mut self, ui: &mut egui::Ui) {
        if self.visible().is_empty() {
            ui.centered_and_justified(|ui| {
                ui.weak(format!("No traffic — route apps via http://127.0.0.1:{}", self.port));
            });
            return;
        }
        egui::ScrollArea::both().id_salt("seq")
            .max_height(ui.available_height() * 0.55)
            .show(ui, |ui| self.table(ui));
        ui.separator();
        self.detail(ui);
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("seq_grid").num_columns(7).striped(true).min_col_width(60.0).show(ui, |ui| {
            for h in ["", "Method", "Host", "Path", "Status", "Time", "Duration"] {
                ui.label(RichText::new(h).strong());
            }
            ui.end_row();
            let mut clicked = None;
            for r in self.visible() {
                let sel = self.sel_row == Some(r.id);
                if ui.selectable_label(sel, if r.locked { "🔒" } else { "🌐" }).clicked() { clicked = Some(r.id); }
                let mc = match r.method.as_str() {
                    "GET" => Color32::from_rgb(58, 143, 214),
                    "POST" => Color32::from_rgb(58, 161, 90),
                    "PUT" => Color32::from_rgb(181, 134, 42),
                    "DELETE" => Color32::from_rgb(192, 70, 63),
                    "PATCH" => Color32::from_rgb(122, 92, 201),
                    "CONNECT" => Color32::from_rgb(120, 120, 130),
                    _ => Color32::GRAY,
                };
                if ui.selectable_label(sel, RichText::new(r.method.as_str()).color(Color32::WHITE).background_color(mc)).clicked() { clicked = Some(r.id); }
                if ui.selectable_label(sel, r.host.as_str()).clicked() { clicked = Some(r.id); }
                if ui.selectable_label(sel, r.path.as_str()).clicked() { clicked = Some(r.id); }
                let sc = match r.status {
                    200..=299 => Color32::from_rgb(46, 158, 75),
                    300..=399 => Color32::from_rgb(201, 138, 26),
                    0 => Color32::GRAY,
                    _ => Color32::from_rgb(208, 64, 58),
                };
                if ui.selectable_label(sel, RichText::new(r.status.to_string()).color(sc).strong()).clicked() { clicked = Some(r.id); }
                if ui.selectable_label(sel, r.time.as_str()).clicked() { clicked = Some(r.id); }
                if ui.selectable_label(sel, r.duration.as_str()).clicked() { clicked = Some(r.id); }
                ui.end_row();
            }
            if let Some(id) = clicked { self.sel_row = Some(id); }
        });
    }

    fn detail(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for (t, l) in [(Tab::Overview, "Overview"), (Tab::Request, "Request"), (Tab::Response, "Response"), (Tab::Timing, "Timing")] {
                if ui.selectable_label(self.tab == t, l).clicked() { self.tab = t; }
            }
        });
        ui.separator();
        let Some(r) = self.rows.iter().find(|r| Some(r.id) == self.sel_row) else {
            ui.weak("Выберите запрос в таблице");
            return;
        };
        egui::ScrollArea::vertical().id_salt("det").show(ui, |ui| match self.tab {
            Tab::Overview => {
                egui::Grid::new("ov").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
                    ui.weak("URL"); ui.monospace(r.url()); ui.end_row();
                    ui.weak("Method"); ui.monospace(r.method.as_str()); ui.end_row();
                    ui.weak("Status"); ui.monospace(r.status.to_string()); ui.end_row();
                    ui.weak("Host"); ui.monospace(r.host.as_str()); ui.end_row();
                    ui.weak("Duration"); ui.monospace(r.duration.as_str()); ui.end_row();
                });
            }
            Tab::Request => {
                ui.monospace(format!("{} {} HTTP/1.1", r.method, r.path));
                ui.monospace(format!("Host: {}", r.host));
                ui.weak("(тела запросов появятся при захвате тела в ядре)");
            }
            Tab::Response => {
                ui.monospace(format!("HTTP/1.1 {}", r.status));
                ui.weak("(тела ответов появятся при захвате тела в ядре)");
            }
            Tab::Timing => {
                ui.monospace(format!("Total: {}", r.duration));
            }
        });
    }
}

fn save_ca() -> std::io::Result<std::path::PathBuf> {
    let dir = rproxy_cert::default_ca_dir().ok_or_else(|| std::io::Error::other("no home dir"))?;
    let dst = std::path::PathBuf::from("rproxy-ca.pem");
    std::fs::copy(dir.join("ca.cert.pem"), &dst)?;
    Ok(dst)
}

