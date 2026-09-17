//! Тулы (tech-plan.md §5, M3): Block List, No Caching, Block Cookies, Map Local, Map Remote.
//! Каждый тул = interceptor в pipeline; конфиг — TOML (`rproxy --tools tools.toml`).

use crate::model::{ExchangeCtx, HttpRequest, HttpResponse};
use crate::pipeline::{InterceptAction, Pipeline, RequestInterceptor, ResponseInterceptor};
use serde::Deserialize;

#[derive(Deserialize, Debug, Default, Clone)]
pub struct ToolsConfig {
    #[serde(default)]
    pub block: Vec<Rule>,
    #[serde(default)]
    pub no_caching: bool,
    #[serde(default)]
    pub block_cookies: bool,
    #[serde(default)]
    pub map_local: Vec<MapLocalRule>,
    #[serde(default)]
    pub map_remote: Vec<Rule>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Rule {
    #[serde(rename = "match")]
    pub pattern: String,
    /// Block List: статус ответа (по умолчанию 403). Map Remote: на что заменить.
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default, rename = "replace")]
    pub replace: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct MapLocalRule {
    #[serde(rename = "match")]
    pub pattern: String,
    pub file: String,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub content_type: Option<String>,
}

// ---------------- Block List ----------------

pub struct BlockTool(pub Vec<Rule>);

#[async_trait::async_trait]
impl RequestInterceptor for BlockTool {
    async fn on_request(&self, req: &mut HttpRequest, _ctx: &ExchangeCtx) -> InterceptAction {
        for r in &self.0 {
            if req.uri.contains(&r.pattern) {
                return InterceptAction::ShortCircuit(HttpResponse::text(
                    r.status.unwrap_or(403),
                    format!("blocked by rproxy: {}", r.pattern),
                ));
            }
        }
        InterceptAction::Continue
    }
}

// ---------------- Map Local ----------------

pub struct MapLocalTool(pub Vec<MapLocalRule>);

fn guess_mime(file: &str) -> String {
    match file.rsplit('.').next() {
        Some("json") => "application/json",
        Some("html" | "htm") => "text/html",
        Some("xml") => "application/xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        _ => "application/octet-stream",
    }
    .into()
}

#[async_trait::async_trait]
impl RequestInterceptor for MapLocalTool {
    async fn on_request(&self, req: &mut HttpRequest, _ctx: &ExchangeCtx) -> InterceptAction {
        for r in &self.0 {
            if req.uri.contains(&r.pattern) {
                return match std::fs::read(&r.file) {
                    Ok(body) => InterceptAction::ShortCircuit(HttpResponse {
                        status: r.status.unwrap_or(200),
                        reason: None,
                        headers: vec![(
                            "content-type".into(),
                            r.content_type.clone().unwrap_or_else(|| guess_mime(&r.file)),
                        )],
                        body: body.into(),
                    }),
                    Err(e) => InterceptAction::ShortCircuit(HttpResponse::text(
                        500,
                        format!("map_local: cannot read {}: {e}", r.file),
                    )),
                };
            }
        }
        InterceptAction::Continue
    }
}

// ---------------- Map Remote ----------------

pub struct MapRemoteTool(pub Vec<Rule>);

#[async_trait::async_trait]
impl RequestInterceptor for MapRemoteTool {
    async fn on_request(&self, req: &mut HttpRequest, _ctx: &ExchangeCtx) -> InterceptAction {
        for r in &self.0 {
            let Some(replace) = &r.replace else { continue };
            if req.uri.contains(&r.pattern) {
                req.uri = req.uri.replacen(&r.pattern, replace, 1);
                let new_authority = req.uri
                    .strip_prefix("https://")
                    .or_else(|| req.uri.strip_prefix("http://"))
                    .and_then(|rest| rest.split('/').next())
                    .map(str::to_string);
                if let Some(a) = new_authority {
                    for (k, v) in &mut req.headers {
                        if k.eq_ignore_ascii_case("host") {
                            *v = a.clone();
                        }
                    }
                }
            }
        }
        InterceptAction::Continue
    }
}

// ---------------- No Caching ----------------

pub struct NoCachingTool;

#[async_trait::async_trait]
impl RequestInterceptor for NoCachingTool {
    async fn on_request(&self, req: &mut HttpRequest, _ctx: &ExchangeCtx) -> InterceptAction {
        req.headers.retain(|(k, _)| {
            !k.eq_ignore_ascii_case("if-none-match") && !k.eq_ignore_ascii_case("if-modified-since")
        });
        req.headers
            .push(("cache-control".into(), "no-cache".into()));
        InterceptAction::Continue
    }
}

#[async_trait::async_trait]
impl ResponseInterceptor for NoCachingTool {
    async fn on_response(&self, resp: &mut HttpResponse, _ctx: &ExchangeCtx) -> InterceptAction {
        resp.headers.retain(|(k, _)| {
            !k.eq_ignore_ascii_case("etag")
                && !k.eq_ignore_ascii_case("last-modified")
                && !k.eq_ignore_ascii_case("expires")
        });
        resp.headers
            .push(("cache-control".into(), "no-store".into()));
        InterceptAction::Continue
    }
}

// ---------------- Block Cookies ----------------

pub struct BlockCookiesTool;

#[async_trait::async_trait]
impl RequestInterceptor for BlockCookiesTool {
    async fn on_request(&self, req: &mut HttpRequest, _ctx: &ExchangeCtx) -> InterceptAction {
        req.headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
        InterceptAction::Continue
    }
}

// ---------------- Сборка pipeline из конфига ----------------

pub fn build_pipeline(cfg: &ToolsConfig) -> Pipeline {
    let mut p = Pipeline::new();
    for r in &cfg.block {
        p = p.with_request_interceptor(Box::new(BlockTool(vec![r.clone()])));
    }
    if !cfg.map_local.is_empty() {
        p = p.with_request_interceptor(Box::new(MapLocalTool(cfg.map_local.clone())));
    }
    if !cfg.map_remote.is_empty() {
        p = p.with_request_interceptor(Box::new(MapRemoteTool(cfg.map_remote.clone())));
    }
    if cfg.no_caching {
        p = p.with_request_interceptor(Box::new(NoCachingTool));
        p = p.with_response_interceptor(Box::new(NoCachingTool));
    }
    if cfg.block_cookies {
        p = p.with_request_interceptor(Box::new(BlockCookiesTool));
        p = p.with_response_interceptor(Box::new(BlockCookiesTool));
    }
    p
}

pub fn load_pipeline(path: &std::path::Path) -> Result<Pipeline, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let cfg: ToolsConfig =
        toml::from_str(&text).map_err(|e| format!("invalid TOML in {}: {e}", path.display()))?;
    Ok(build_pipeline(&cfg))
}

pub fn example_toml() -> &'static str {
    r#"# rproxy tools config (TOML)

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
"#
}


#[async_trait::async_trait]
impl ResponseInterceptor for BlockCookiesTool {
    async fn on_response(&self, resp: &mut HttpResponse, _ctx: &ExchangeCtx) -> InterceptAction {
        resp.headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("set-cookie"));
        InterceptAction::Continue
    }
}

