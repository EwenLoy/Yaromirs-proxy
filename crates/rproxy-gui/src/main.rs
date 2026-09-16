use eframe::egui;
use egui::{Color32, RichText};
use rproxy_core::{EventBus, ProxyEvent, ProxyServer};
use std::sync::mpsc::{channel, Receiver};
use std::time::SystemTime;

fn main() -> eframe::Result<()> {
    // Порт прокси: RPROXY_PORT или 8888.
    let port: u16 = std::env::var("RPROXY_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8888);

    let (tx, rx) = channel::<rproxy_core::Exchange>();
    let bus = EventBus::new();

    // Фоновый поток: tokio runtime + ProxyServer + пересылка событий в GUI.
    let bus_for_server = bus.clone();
    std::thread::Builder::new()
        .name("rproxy-engine".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async move {
                // Подписчик на шину -> std-канал в GUI.
                let mut sub = bus_for_server.subscribe();
                tokio::spawn(async move {
                    loop {
                        match sub.recv().await {
                            Ok(ProxyEvent::ExchangeCompleted(ex)) => {
                                let _ = tx.send(ex);
                            }
                            Ok(_) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            Err(_) => continue,
                        }
                    }
                });
                let server = ProxyServer::new(bus_for_server, rproxy_core::Pipeline::new());
                let addr = format!("127.0.0.1:{port}");
                eprintln!("[rproxy-gui] proxy listening on http://{addr} (HTTP forward + CONNECT)");
                if let Err(e) = server.run(&addr).await {
                    eprintln!("[rproxy-gui] proxy server error: {e}");
                }
            });
        })
        .expect("spawn engine thread");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1180.0, 760.0]),
        ..Default::default()
    };
    eframe::run_native(
        "rproxy",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_pixels_per_point(1.0);
            Ok(Box::new(RProxyApp::new(rx, port)))
        }),
    )
}

// ---------- Модель данных ----------

#[derive(Clone)]
struct ExchangeRow {
    id: u32,
    locked: bool, // CONNECT/HTTPS-туннель
    method: String,
    host: String,
    path: String,
    status: u16, // 0 = ответа ещё нет
    protocol: String,
    size: String,
    time: String,
    duration: String,
}

struct TreeHost {
    name: String,
    secure: bool,
    count: u32,
    paths: Vec<String>,
}

#[derive(PartialEq, Clone, Copy)]
enum SidebarTab {
    Structure,
    Sequence,
}

#[derive(PartialEq, Clone, Copy)]
enum DetailTab {
    Overview,
    Request,
    Response,
    Timing,
    Tls,
}

struct RProxyApp {
    port: u16,
    recording: bool,
    ssl_proxying: bool,
    filter_text: String,
    sidebar_tab: SidebarTab,
    detail_tab: DetailTab,
    selected_row: Option<u32>,
    rows: Vec<ExchangeRow>,
    hosts: Vec<TreeHost>,
    rx: Receiver<rproxy_core::Exchange>,
}

fn fmt_wall_time() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!("{h:02}:{m:02}:{s:02}.{millis:03}")
}

impl ExchangeRow {
    fn from_exchange(ex: &rproxy_core::Exchange) -> Self {
        let (method, host, path, locked) = match &ex.request {
            Some(req) if req.is_connect => {
                ("CONNECT".to_string(), req.uri.clone(), "*".to_string(), true)
            }
            Some(req) => {
                let rest = req.uri.as_str();
                let (host, path) = if let Some(rest) = rest.strip_prefix("http://") {
                    match rest.split_once('/') {
                        Some((h, p)) => (h.to_string(), format!("/{p}")),
                        None => (rest.to_string(), "/".to_string()),
                    }
                } else {
                    (rest.to_string(), "/".to_string())
                };
                (req.method.clone(), host, path, false)
            }
            None => ("-".to_string(), "-".to_string(), "-".to_string(), false),
        };
        ExchangeRow {
            id: ex.id.0 as u32,
            locked,
            method,
            host,
            path,
            status: ex.response_status.unwrap_or(0),
            protocol: match ex.protocol {
                rproxy_core::Protocol::ConnectTunnel => "TUNNEL".to_string(),
                rproxy_core::Protocol::Http1 => "HTTP/1.1".to_string(),
                rproxy_core::Protocol::Http2 => "HTTP/2".to_string(),
                _ => "-".to_string(),
            },
            size: "-".to_string(), // тела в M0 не буферизуются
            time: fmt_wall_time(),
            duration: ex
                .timing
                .total()
                .map(|d| format!("{d:.1?}"))
                .unwrap_or_else(|| "-".to_string()),
        }
    }
}

impl RProxyApp {
    fn new(rx: Receiver<rproxy_core::Exchange>, port: u16) -> Self {
        Self {
            port,
            recording: true,
            ssl_proxying: true,
            filter_text: String::new(),
            sidebar_tab: SidebarTab::Structure,
            detail_tab: DetailTab::Overview,
            selected_row: None,
            rows: Vec::new(),
            hosts: Vec::new(),
            rx,
        }
    }

    /// Забираем новые события из шины и обновляем таблицы.
    fn poll_events(&mut self) {
        while let Ok(ex) = self.rx.try_recv() {
            if self.recording {
                self.rows.push(ExchangeRow::from_exchange(&ex));
            }
        }
        self.rebuild_hosts();
    }

    fn rebuild_hosts(&mut self) {
        let mut hosts: Vec<TreeHost> = Vec::new();
        for row in &self.rows {
            if let Some(h) = hosts.iter_mut().find(|h| h.name == row.host) {
                h.count += 1;
                if !h.paths.contains(&row.path) {
                    h.paths.push(row.path.clone());
                }
            } else {
                hosts.push(TreeHost {
                    name: row.host.clone(),
                    secure: row.locked,
                    count: 1,
                    paths: vec![row.path.clone()],
                });
            }
        }
        hosts.sort_by(|a, b| b.count.cmp(&a.count));
        self.hosts = hosts;
    }

    fn filtered_rows(&self) -> Vec<&ExchangeRow> {
        let f = self.filter_text.to_lowercase();
        if f.is_empty() {
            self.rows.iter().collect()
        } else {
            self.rows
                .iter()
                .filter(|r| {
                    r.host.to_lowercase().contains(&f)
                        || r.path.to_lowercase().contains(&f)
                        || r.method.to_lowercase().contains(&f)
                })
                .collect()
        }
    }
}

impl eframe::App for RProxyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();
        self.toolbar(ctx);
        self.sidebar(ctx);
        self.status_bar(ctx);
        self.central(ctx);
        // Живое обновление, пока идёт запись.
        if self.recording {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

impl RProxyApp {
    fn toolbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add_space(4.0);

                let rec_label = if self.recording { "⏺ Record" } else { "⏸ Record" };
                if ui.selectable_label(self.recording, rec_label).clicked() {
                    self.recording = !self.recording;
                }

                if ui.button("🧹 Clear").clicked() {
                    self.rows.clear();
                }

                ui.separator();

                if ui
                    .add(egui::Button::new(RichText::new("💾 Save All").strong()).fill(Color32::from_rgb(47, 111, 237)))
                    .clicked()
                {
                    // TODO: вызвать rproxy_export::save_all(&self.rows, path)
                    println!("Save All clicked — здесь будет сохранение сессии в HAR/.rpz");
                }

                if ui.button("📂 Open").clicked() {}

                ui.separator();

                if ui.selectable_label(self.ssl_proxying, "🔒 SSL Proxying").clicked() {
                    self.ssl_proxying = !self.ssl_proxying;
                }
                if ui.button("🧭 Map Remote").clicked() {}
                if ui.button("✏ Rewrite").clicked() {}
                if ui.button("🐢 Throttle").clicked() {}
                if ui.button("⛔ Breakpoints").clicked() {}

                // Поиск справа
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(4.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.filter_text)
                            .hint_text("🔍 Filter…")
                            .desired_width(200.0),
                    );
                });
            });
            ui.add_space(4.0);
        });
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("sidebar")
            .resizable(true)
            .default_width(260.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(self.sidebar_tab == SidebarTab::Structure, "Structure")
                        .clicked()
                    {
                        self.sidebar_tab = SidebarTab::Structure;
                    }
                    if ui
                        .selectable_label(self.sidebar_tab == SidebarTab::Sequence, "Sequence")
                        .clicked()
                    {
                        self.sidebar_tab = SidebarTab::Sequence;
                    }
                });
                ui.separator();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for host in &self.hosts {
                        let icon = if host.secure { "🔒" } else { "🌐" };
                        ui.horizontal(|ui| {
                            ui.label(format!("▾ {icon} {}", host.name));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.weak(format!("{}", host.count));
                            });
                        });
                        for path in &host.paths {
                            ui.horizontal(|ui| {
                                ui.add_space(20.0);
                                ui.label(format!("📄 {path}"));
                            });
                        }
                    }
                });
            });
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let (dot_color, text) = if self.recording {
                    (
                        Color32::from_rgb(46, 158, 75),
                        format!("Proxy running on 127.0.0.1:{}", self.port),
                    )
                } else {
                    (Color32::from_rgb(208, 64, 58), "Recording paused".to_string())
                };
                let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 4.0, dot_color);
                ui.label(text);

                ui.separator();
                ui.label(format!(
                    "SSL Proxying: {}",
                    if self.ssl_proxying { "on" } else { "off" }
                ));
                ui.separator();
                ui.label("Throttle: off");
                ui.separator();
                ui.label(format!("{} requests", self.rows.len()));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak("rproxy v0.1.0 (M0: HTTP forward + CONNECT passthrough)");
                });
            });
        });
    }

    fn central(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // верхняя часть — таблица Sequence
            let table_height = ui.available_height() * 0.55;
            egui::ScrollArea::both()
                .id_salt("seq_table")
                .max_height(table_height)
                .show(ui, |ui| {
                    self.sequence_table(ui);
                });

            ui.separator();

            // нижняя часть — детали выбранного запроса
            self.detail_panel(ui);
        });
    }

    fn sequence_table(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("sequence_grid")
            .num_columns(9)
            .striped(true)
            .min_col_width(60.0)
            .show(ui, |ui| {
                // заголовки
                for h in ["", "Method", "Host", "Path", "Status", "Protocol", "Size", "Time", "Duration"] {
                    ui.label(RichText::new(h).strong());
                }
                ui.end_row();

                let mut clicked_id: Option<u32> = None;

                for row in self.filtered_rows() {
                    let is_selected = self.selected_row == Some(row.id);

                    let lock_icon = if row.locked { "🔒" } else { "🌐" };
                    if ui.selectable_label(is_selected, lock_icon).clicked() {
                        clicked_id = Some(row.id);
                    }

                    let method_color = match row.method.as_str() {
                        "GET" => Color32::from_rgb(58, 143, 214),
                        "POST" => Color32::from_rgb(58, 161, 90),
                        "PUT" => Color32::from_rgb(181, 134, 42),
                        "DELETE" => Color32::from_rgb(192, 70, 63),
                        "PATCH" => Color32::from_rgb(122, 92, 201),
                        "CONNECT" => Color32::from_rgb(120, 120, 130),
                        _ => Color32::GRAY,
                    };
                    if ui
                        .selectable_label(
                            is_selected,
                            RichText::new(row.method.as_str()).color(Color32::WHITE).background_color(method_color),
                        )
                        .clicked()
                    {
                        clicked_id = Some(row.id);
                    }

                    if ui.selectable_label(is_selected, row.host.as_str()).clicked() {
                        clicked_id = Some(row.id);
                    }
                    if ui.selectable_label(is_selected, row.path.as_str()).clicked() {
                        clicked_id = Some(row.id);
                    }

                    let status_color = match row.status {
                        200..=299 => Color32::from_rgb(46, 158, 75),
                        300..=399 => Color32::from_rgb(201, 138, 26),
                        0 => Color32::GRAY,
                        _ => Color32::from_rgb(208, 64, 58),
                    };
                    if ui
                        .selectable_label(is_selected, RichText::new(row.status.to_string()).color(status_color).strong())
                        .clicked()
                    {
                        clicked_id = Some(row.id);
                    }

                    if ui.selectable_label(is_selected, row.protocol.as_str()).clicked() {
                        clicked_id = Some(row.id);
                    }
                    if ui.selectable_label(is_selected, row.size.as_str()).clicked() {
                        clicked_id = Some(row.id);
                    }
                    if ui.selectable_label(is_selected, row.time.as_str()).clicked() {
                        clicked_id = Some(row.id);
                    }
                    if ui.selectable_label(is_selected, row.duration.as_str()).clicked() {
                        clicked_id = Some(row.id);
                    }

                    ui.end_row();
                }

                if let Some(id) = clicked_id {
                    self.selected_row = Some(id);
                }
            });
    }

    fn detail_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for (tab, label) in [
                (DetailTab::Overview, "Overview"),
                (DetailTab::Request, "Request"),
                (DetailTab::Response, "Response"),
                (DetailTab::Timing, "Timing"),
                (DetailTab::Tls, "TLS"),
            ] {
                if ui.selectable_label(self.detail_tab == tab, label).clicked() {
                    self.detail_tab = tab;
                }
            }
        });
        ui.separator();

        let Some(selected) = self.rows.iter().find(|r| Some(r.id) == self.selected_row).cloned() else {
            ui.weak("Выберите запрос в таблице выше");
            return;
        };

        egui::ScrollArea::vertical().id_salt("detail_scroll").show(ui, |ui| {
            match self.detail_tab {
                DetailTab::Overview => {
                    egui::Grid::new("overview_grid").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
                        ui.weak("URL");
                        ui.monospace(format!(
                            "{}://{}{}",
                            if selected.locked { "https" } else { "http" },
                            selected.host,
                            selected.path
                        ));
                        ui.end_row();

                        ui.weak("Method");
                        ui.monospace(selected.method.as_str());
                        ui.end_row();

                        ui.weak("Status");
                        ui.monospace(selected.status.to_string());
                        ui.end_row();

                        ui.weak("Protocol");
                        ui.monospace(selected.protocol.as_str());
                        ui.end_row();

                        ui.weak("Duration");
                        ui.monospace(selected.duration.as_str());
                        ui.end_row();
                    });
                }
                DetailTab::Request => {
                    ui.monospace(format!(
                        "{} {} HTTP/1.1",
                        selected.method,
                        if selected.locked { selected.host.as_str() } else { selected.path.as_str() }
                    ));
                    ui.monospace(format!("Host: {}", selected.host));
                    ui.weak("(тела запросов появятся в M1+ — MITM-перехват)");
                }
                DetailTab::Response => {
                    ui.monospace(format!("HTTP/1.1 {}", selected.status));
                    ui.weak("(тела ответов появятся в M1+ — MITM-перехват)");
                }
                DetailTab::Timing => {
                    ui.monospace(format!("Total: {}", selected.duration));
                    ui.weak("(DNS/connect/TLS-тайминги появятся в M1+)");
                }
                DetailTab::Tls => {
                    if selected.locked {
                        ui.weak("HTTPS-туннель (CONNECT). Расшифровка — после M1 (MITM + root CA).");
                    } else {
                        ui.weak("Соединение не защищено TLS");
                    }
                }
            }
        });
    }
}

