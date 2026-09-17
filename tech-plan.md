# Тех. план: открытый аналог Charles Proxy на Rust (egui + CLI)

Кодовое имя проекта: **rproxy** (репо: Yaromirs-proxy).

> **Статус (17.09.2026):** M0 ✅ и M1 ✅ выполнены.
> Работает: HTTP/1.1 forward proxy, CONNECT passthrough и MITM-расшифровка HTTPS
> (rcgen root CA в `~/.rproxy`, leaf-сертификаты per-host), event bus, interceptor-pipeline,
> CLI `rproxy run`, live GUI (Charles-style: дерево хостов с Encrypted-группой, фильтр,
> таблица Sequence, детали). Тесты: 5/5 (forward, CONNECT, pipeline ShortCircuit, CA/leaf, MITM e2e).

Базируется на анализе актуальной версии Charles Proxy **5.2.1** и на
конкурентном анализе Proxyman (актуальная версия с MCP) — см. §2.1.

---

## 1. Что умеет актуальный Charles Proxy (референс)

### 1.1 Проксирование / протоколы
- HTTP/1.1, HTTP/2 (включая gRPC-трейлеры, flow control, конкурентность стримов)
- HTTP/3 / QUIC — частичная поддержка (распознавание draft-версий, импорт HAR)
- WebSocket (включая deflate-расширения)
- SOCKS5 proxy (с корректным negotiation)
- SSL/TLS proxying (MITM) с собственным root CA, генерируемым на каждую установку
- Reverse Proxy и Port Forwarding
- Transparent proxying (перехват по Host-заголовку без явной настройки клиента)
- External Proxy (форвардинг через ещё один proxy, включая NTLM-авторизацию)
- IPv6
- Happy Eyeballs (RFC 8305) для dual-stack хостов
- 1xx interim responses (в т.ч. 103 Early Hints) как отдельные связанные транзакции
- zstd / Brotli / gzip content-encoding
- Protobuf (в т.ч. пользовательские .proto дескрипторы)
- DNS Spoofing (переопределение резолвинга для домена)
- Внешний DNS resolver

### 1.2 UI / просмотр трафика
- Structure view (дерево по доменам/путям) и Sequence view (хронологический список)
- Кастомизируемые колонки в Sequence view (в т.ч. значения произвольных заголовков)
- Filter / Focus (фокус на конкретных хостах)
- Highlight Rules — правила автоматической подсветки запросов
- Find (по всей сессии и в рамках одного запроса/ответа)
- Вьюеры содержимого: JSON (tree + text), XML (tree, folding), HTML/CSS/JS pretty-print,
  Image viewer, SOAP, AMF, Protobuf, Multipart, Form (urlencoded), Auth (Basic/Bearer/OAuth/NTLM)
- Raw viewer с построчными номерами и line wrap
- Timing/Overview: DNS lookup, TCP connect, SSL handshake, TLS детали (cipher, session resumption,
  сертификаты, extensions), keep-alive статус
- Flow chart — визуализация профиля соединения во времени
- Active Connections view
- Error Log с фильтрацией и экспортом в файл
- Dark mode, HiDPI

### 1.3 Инструменты для изменения/симуляции трафика
- **Breakpoints** — приостановка запроса/ответа для ручного редактирования перед отправкой
- **Compose** — создание запросов с нуля (включая multipart с файлами/картинками)
- **Repeat** / **Repeat Advanced** — повтор запроса(ов) с задержками, N раз
- **Edit** — редактирование и повторная отправка перехваченного запроса
- **Map Remote** — перенаправление запросов на другой хост/порт (в т.ч. вложенные папки маппинга,
  опция Preserve base path)
- **Map Local** — подмена ответа локальным файлом
- **Rewrite** — правила переписывания заголовков/URL/тела/статуса запроса или ответа
- **DNS Spoofing** — переопределение DNS для домена
- **Block List** / **Whitelist** — блокировка (graceful или terminate) по паттерну
- **No Caching** — принудительное отключение кэширующих заголовков
- **Block Cookies**
- **Throttling / Chaos** — симуляция плохой сети (задержки, потери, ограничение скорости, наборы
  профилей: 3G/Edge/Cable и т.п.)
- **Mirror** — сохранение проходящего трафика (включая partial responses для стриминга) на диск
- **Auto Save**
- **Client Process tool** — определение, какой локальный процесс инициировал запрос
- **Validate** — валидация HTML/CSS
- **Profiles** — сохранённые наборы настроек, переключаемые целиком

### 1.4 Данные и интеграции
- Сохранение сессии в собственном формате `.chlz` (zip-based, с 5.0), устаревший `.chls`
- Импорт/экспорт **HAR**, экспорт в **XML**, **JSON**, **CSV**
- Импорт **Fiddler SAZ**, **PCAP** (Wireshark/tcpdump)
- Export/Copy as cURL
- Публикация трассировки как Gist
- Import/Export настроек приложения (root CA сертификат — отдельно, для расшаривания в команде)

### 1.5 CLI
Charles сейчас предоставляет line-мод и небольшой набор command-line тулов:
- `charles` с флагами запуска (`--debug`, `-v` и т.п.), headless-режим на Linux
- `charles filter` — фильтрация запросов/ответов из сохранённой сессии (появилось в 5.1.1b2/5.2)
- Отдельные утилиты: экспорт SSL-сертификата, PCAP/HAR convert

**Важно:** в Charles CLI — это вспомогательный слой над GUI-приложением, а не полноценный
самостоятельный movide работы (нет полнофункционального headless-прокси с фильтрами/breakpoints
из командной строки). Здесь наш проект может **превзойти** Charles: сделать CLI полностью
равноправным первоклассным интерфейсом (в духе `mitmdump`/`mitmproxy`).

---

## 2. Итоговый scope нашего проекта

Полностью покрыть 1.1–1.4 реалистично поэтапно; закладываем архитектуру так, чтобы каждая
фича Charles ложилась в готовый "слот" (trait/plugin), а не требовала переписывания ядра.

### Явно вне MVP (Charles-специфичные легаси-вещи, низкий ROI)
- AMF, SOAP viewer (Flash-эра, почти не встречается)
- Gist publish
- PCAP import (можно добавить позже через `pcap`/`pnet`)
- Client Process tool (платформозависимо, сложно, низкий приоритет)
- Импорт Fiddler SAZ

### 2.1 Конкурентный анализ (сентябрь 2026) — что изменилось

**Proxyman** (6.x):
- Добавил **нативный MCP v2** — это флагманская фича. MCP HTTP-сервер внутри приложения
  + stdio-сервер для агентов; поддержаны Claude Code, Codex, Cursor.
  Агент может: читать/фильтровать захваченный трафик, создавать Breakpoints / Map Local /
  Map Remote / Rewrite-скрипты, включать SSL proxying, ставить root CA, экспортировать cURL,
  генерировать код из запроса (18+ языков), создавать Reverse Proxy / DNS Spoofing.
  Есть SKILL.md для агентов, token-auth, автоматическое редактирование секретов в ответах.
- **Python capture** — 1-click терминал, перехватывающий HTTPS из
  requests/aiohttp/httpx/urllib3. JS-скриптинг с npm-аддонами. Windows/Linux версии.
- Ограничение: MCP привязан к **открытому десктоп-приложению** ("Keep Proxyman open"),
  и по сути это macOS-first продукт.

**Charles 5.2.1**:
- **Официального MCP нет**. AI-фич нет. Есть сторонний `charles-mcp` (PyPI, ~300★),
  который подключается к запущенному Charles-приложению — народный проект, не вендор.
- CLI остаётся вспомогательным слоем над GUI (см. §1.5).

**Вывод для rproxy:**
1. «AI-агент управляет прокси» — уже **table stakes** ниши, а не фишка.
2. Уязвимое место обоих конкурентов — привязка к открытому GUI-приложению.
   Наш архитектурный принцип (headless daemon + много клиентов, §3.1) бьёт точно туда:
   **rproxy может быть MCP-сервером без GUI вообще** — в CI, Docker, на сервере.
3. Позиционирование: *«the first proxy built for AI agents and CI — headless by design»*.
   Поэтому в roadmap добавлен этап **M2.5 — MCP-сервер** (§9).

---

## 3. Архитектура workspace

```
rproxy/
├── Cargo.toml                     # workspace
├── crates/
│   ├── rproxy-core/                # ядро: proxy engine, протоколы, event bus
│   │   ├── net/                    # TCP/UDP listener, HTTP1/H2/H3, WebSocket, SOCKS5
│   │   ├── tls/                    # MITM TLS termination
│   │   ├── model/                  # Exchange, Request, Response, Timing, Connection
│   │   ├── pipeline/               # цепочка обработки (traits ниже)
│   │   └── events.rs                # broadcast bus для подписчиков (GUI/CLI/экспортеры)
│   ├── rproxy-cert/                 # генерация root CA + leaf certs (rcgen), keystore
│   ├── rproxy-storage/              # сессии в памяти + persistent (sqlite), .rpz формат
│   ├── rproxy-codec/                 # парсеры содержимого: JSON/XML/Protobuf/HTML/CSS/JS/images
│   ├── rproxy-tools/                 # реализация тулов Charles как плагинов (см. §5)
│   ├── rproxy-export/                # HAR / cURL / JSON / XML / CSV im-/export
│   ├── rproxy-cli/                   # бинарник: daemon-режим + TUI (ratatui) + subcommands
│   ├── rproxy-gui/                   # бинарник: egui/eframe desktop app
│   └── rproxy-ipc/                   # (опц.) протокол управления: gui и cli могут управлять
│                                      #  одним и тем же фоновым daemon-процессом
```

### 3.1 Ключевой архитектурный принцип
**GUI и CLI — это два клиента одного и того же proxy-engine.** Ядро ничего не знает о UI.
Это даёт:
- Возможность запустить `rproxy daemon` в фоне и подключаться к нему и через TUI, и через GUI
  (по аналогии с `mitmproxy` + `mitmweb`), через локальный IPC (unix socket / named pipe, или
  gRPC/WebSocket на localhost).
- CLI не деградирует до "логгера" — у него те же тулы (Map Remote, Rewrite, Breakpoints, Throttle),
  просто в текстовом/интерактивном виде.

### 3.2 Модель данных (rproxy-core::model)

```rust
pub struct Exchange {
    pub id: ExchangeId,
    pub connection_id: ConnectionId,
    pub protocol: Protocol,           // Http1, Http2, Http3, WebSocket, Socks5, RawTcp
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub timing: Timing,               // dns, connect, tls_handshake, ttfb, total
    pub tls_info: Option<TlsInfo>,    // cipher, version, cert chain, sni, resumed
    pub client_process: Option<ProcessInfo>,
    pub notes: String,
    pub tags: Vec<Tag>,               // для Highlight Rules / Focus
    pub state: ExchangeState,         // InProgress, Complete, Failed, Blocked, BreakpointHeld
}

pub struct Connection {
    pub id: ConnectionId,
    pub client_addr: SocketAddr,
    pub remote_addr: Option<SocketAddr>,
    pub host: String,
    pub is_tunneled: bool,            // CONNECT/HTTPS
    pub kept_alive_count: u32,
}
```

### 3.3 Pipeline (обработка трафика как цепочка traits)

Это прямой аналог тулов Charles — Map Remote/Local, Rewrite, Block, Throttle, No Caching,
Block Cookies, Breakpoints — все реализуются одним интерфейсом и применяются по порядку:

```rust
#[async_trait]
pub trait RequestInterceptor: Send + Sync {
    async fn on_request(&self, req: &mut HttpRequest, ctx: &ExchangeCtx) -> InterceptAction;
}

#[async_trait]
pub trait ResponseInterceptor: Send + Sync {
    async fn on_response(&self, resp: &mut HttpResponse, ctx: &ExchangeCtx) -> InterceptAction;
}

pub enum InterceptAction {
    Continue,
    Block { status: u16 },
    Hold,          // для Breakpoints — ждём решения оператора
    ShortCircuit(HttpResponse), // для Map Local / Block List
}
```

Порядок пайплайна конфигурируется явно (как порядок тулов в Charles), храним как
`Vec<Box<dyn RequestInterceptor>>` + аналогично для response.

### 3.4 Событийная шина

```rust
pub enum ProxyEvent {
    ExchangeStarted(Exchange),
    ExchangeUpdated(Exchange),     // прогресс стрима, чанки
    ExchangeCompleted(Exchange),
    ConnectionOpened(Connection),
    ConnectionClosed(ConnectionId),
    BreakpointHit(ExchangeId),
    Error(ProxyError),
}
```
`tokio::sync::broadcast::Sender<ProxyEvent>` живёт в ядре; GUI подписывается для live-обновления
таблицы, CLI — для daemon-логов/TUI/экспорта в файл (Mirror/Auto Save реализуются как подписчики).

---

## 4. Сетевой слой (rproxy-core::net)

| Компонент          | Крейт                                  | Комментарий |
|---------------------|------------------------------------------|-------------|
| Async runtime       | `tokio`                                  | |
| HTTP/1.1 + HTTP/2    | `hyper` 1.x + `hyper-util`               | сервер и клиент части |
| HTTP/3 / QUIC        | `quinn` + `h3`                           | этап 2, не MVP |
| TLS                 | `rustls` + `tokio-rustls`                | и клиент, и MITM-сервер термация |
| Генерация сертификатов | `rcgen`                              | root CA + leaf on-the-fly, кэш по SNI |
| WebSocket           | `tokio-tungstenite`                       | поверх апгрейженного HTTP/1 соединения |
| SOCKS5              | свой минимальный имплементатор или `fast-socks5` | |
| DNS                  | `hickory-resolver` (бывший trust-dns)     | нужен для DNS Spoofing и внешнего resolver |
| Сжатие              | `flate2` (gzip), `brotli`, `zstd`         | распаковка для показа в UI, не трогаем on-wire если не нужно |
| Happy Eyeballs      | своя реализация на tokio::select! по RFC 8305 | этап 2 |

MITM-механизм:
1. Клиент шлёт `CONNECT host:443` → proxy отвечает `200`, поднимает TLS-сервер локально с
   сертификатом, подписанным нашим CA (генерируется/кэшируется по SNI).
2. Одновременно как клиент открывает реальное TLS-соединение к `host:443`.
3. Расшифрованные данные с обеих сторон проходят через HTTP/1 или HTTP/2 codec и публикуются
   как `Exchange`.

---

## 5. Тулы (rproxy-tools) — маппинг фич Charles на реализацию

| Charles Tool          | Реализация в rproxy |
|------------------------|----------------------|
| No Caching             | `RequestInterceptor`, вставляет `Cache-Control: no-cache` и убирает `If-*` |
| Block Cookies          | strip `Cookie`/`Set-Cookie` |
| Map Remote              | `RequestInterceptor`: правило host/path → host/path (с nested-папками и preserve-base-path) |
| Map Local                | `RequestInterceptor` → `ShortCircuit`, читает файл с диска |
| Rewrite                  | набор правил (regex/exact) над заголовками/URL/статусом/телом, request и response |
| Block List / Whitelist   | matcher по glob/regex → `Block` или terminate соединения |
| DNS Spoofing              | подмена в `hickory-resolver` слое перед подключением |
| Mirror                    | подписчик на `ProxyEvent`, пишет тело на диск по шаблону пути |
| Auto Save                  | подписчик на `ExchangeCompleted`, периодически сериализует сессию |
| Repeat / Repeat Advanced   | клиент-компонент: берёт `Exchange.request`, шлёт заново N раз с задержкой |
| Edit                        | GUI/CLI дают отредактировать `HttpRequest`, дальше как обычный запрос |
| Compose                     | UI-фича без изменений в ядре — просто конструирование `HttpRequest` с нуля |
| Breakpoints                  | `InterceptAction::Hold` + канал ожидания решения оператора (Continue/Edit/Drop) |
| Throttling / Chaos            | обёртка над сокетом: искусственная задержка, bandwidth cap, packet loss (в перспективе) |
| Validate                       | этап 2, дергаем внешние html/css валидаторы или свои линтеры |
| Highlight Rules / Focus          | не сетевые, а UI/фильтрационные правила — общий модуль `rproxy-core::filter` |
| Client Process                    | пропускаем в MVP (платформозависимо: `/proc/net/tcp` на Linux, аналоги на Win/Mac) |

Каждый тул = независимый крейт-модуль с конфигом (сериализуемым в TOML/JSON), включаемый в
пайплайн через профиль (Profiles — просто сохранённый набор конфигов тулов + фильтров).

---

## 6. Хранилище и форматы (rproxy-storage / rproxy-export)

- **Runtime-хранилище**: in-memory ring-buffer (ограничение по кол-ву/памяти), большие тела
  — сразу на диск во временный файл (аналог того, что Proxyman сделал в 2026 — "Large body
  storage": тела не в RAM).
- **Persistent-сессия**: собственный формат `.rpz` — zip с манифестом (JSON) + телами запросов/
  ответов как отдельные файлы внутри (аналог `.chlz`), либо `sqlite` для сценария "долгая запись
  + произвольные запросы к истории".
- **Экспорт**:
  - HAR (совместимость с DevTools/Postman) — топ-приоритет
  - cURL command (copy as cURL)
  - JSON / CSV произвольных полей Sequence-таблицы
  - **Импорт** `.chlz`/`.chls` от Charles — отличная фича для миграции пользователей (просто
    парсим zip + XML/JSON манифест Charles, конвертируем в `Exchange`)
  - PCAP импорт — этап 2/3

---

## 7. CLI (rproxy-cli)

Два уровня использования:

### 7.1 Daemon / one-shot режим (аналог `mitmdump`)
```
rproxy run --port 8888 --record session.rpz
rproxy run --port 8888 --map-remote "api.old.com=>api.new.com" --throttle 3g
rproxy run --port 8888 --filter 'host~example.com && status>=400'
```
Вывод — построчный лог в stdout (или JSON lines для скриптинга) + опциональная запись сессии.

### 7.2 TUI (аналог htop, через `ratatui`)
```
rproxy tui --port 8888
```
- Таблица запросов live (Sequence view), сортировка/фильтр
- Детальный просмотр запроса/ответа (headers, pretty body) по Enter
- Breakpoints: пауза, редактирование в `$EDITOR`, продолжить/дропнуть
- Горячие клавиши для тулов: `m` Map Remote, `r` Rewrite, `b` Block, `t` Throttle

### 7.3 Управляющие/утилитарные команды
```
rproxy cert install          # установка root CA в системное хранилище (как charles ssl cert export)
rproxy cert export --out ca.pem
rproxy filter session.rpz --query '...' --out filtered.har   # аналог "charles filter"
rproxy convert session.har session.rpz
rproxy replay session.rpz --repeat 5 --delay 200ms           # аналог Repeat Advanced
```

### 7.4 Режим подключения к уже запущенному daemon
`rproxy run --port 8888 --detach` поднимает движок как фон, слушает управляющий IPC-сокет;
`rproxy tui --attach` и `rproxy-gui` могут подключиться к нему одновременно — то, чего у Charles
нет вообще (там GUI = единственный процесс).

---

## 8. GUI (rproxy-gui, egui/eframe)

Экран (аналог главного окна Charles):

```
┌──────────────┬───────────────────────────────────────────┐
│ Structure     │ Sequence (таблица, кастомные колонки)      │
│ (дерево       │─────────────────────────────────────────── │
│  по доменам)  │ Overview | Request | Response | Timing | TLS│
│               │  (вкладки деталей выбранного Exchange)      │
├──────────────┴───────────────────────────────────────────┤
│ Status bar: recording • throttle: 3G • filter active        │
└──────────────────────────────────────────────────────────┘
```

- Live-обновление через подписку на `ProxyEvent` (poll в `eframe::App::update`, ~30-60 FPS ограничение)
- Виртуализация списка (`egui::ScrollArea` + ручная виндовизация строк) для больших сессий
- Вьюеры содержимого — плагинная система по mime-type (JSON tree, XML tree с folding,
  image preview, hex/raw, protobuf через дескрипторы)
- Подсветка синтаксиса — `syntect` (или ручная легковесная подсветка для JSON/XML/HTTP)
- Диалоги тулов (Map Remote/Local, Rewrite, Block, Throttle, DNS Spoof) как модальные окна над
  тем же конфигом, что использует ядро — никакой дублирующей логики
- Breakpoint UI: всплывающая панель с редактируемым запросом и кнопками Continue/Drop
- Dark/light theme (egui из коробки поддерживает переключение)
- Flow chart / Active Connections — через `egui_plot`

---

## 9. Порядок разработки (roadmap) — актуальная редакция

**M0 — Ядро прокси (без MITM)** ✅ done
- CONNECT tunnel passthrough, HTTP/1.1 forward proxy, базовая модель Exchange, event bus ✅

**M1 — MITM + сертификаты** ✅ done
- rcgen root CA (persist в `~/.rproxy`), динамические leaf-сертификаты по host,
  TLS-терминация в CONNECT (rustls), расшифрованные HTTPS-запросы в шине и GUI ✅

**M2 — Захват тел + HAR** ⏳ в работе
- Буферизация тел запросов/ответов (с лимитами, большие — на диск), распаковка
  gzip/deflate/br для отображения
- Viewers в GUI: реальные Request/Response bodies, JSON pretty
- Экспорт HAR; `rproxy run --record session.rpz` (формат .rpz = zip+JSON)

**M2.5 — MCP-сервер** ⏳ (новый этап, см. §2.1)
- `rproxy run --mcp`: stdio JSON-RPC (MCP) поверх daemon — headless, без GUI
- Тулы первой волны: `get_flows` (список/фильтр), `get_flow` (детали+тело),
  `export_flow_curl`, `toggle_recording`, `clear_session`, `get_status`
- Каждый последующий тул ядра (M3-M6) автоматически получает MCP-обёртку
- Дифференциатор: агент управляет прокси в CI/Docker/SSH — без открытого GUI
  (что невозможно ни в Proxyman, ни в Charles)
- Позже: SKILL.md, ресурсы/промпты, redaction секретов (как у Proxyman v2)

**M3 — Базовые тулы**
- Block List, No Caching, Block Cookies, Map Local, Map Remote, Rewrite
- (каждый = interceptor + конфиг TOML + опция в CLI + MCP-тул)

**M4 — GUI MVP**
- Полные viewers тел (JSON tree, raw, hex), поиск по сессии, Highlight Rules

**M5 — TUI**
- `ratatui` интерфейс: таблица, детали, breakpoints через `$EDITOR`

**M6 — Breakpoints + Compose + Repeat**
- `InterceptAction::Hold` + канал решения оператора (GUI/TUI/MCP: `approve_flow`)

**M7 — HTTP/2, WebSocket полноценно**
- h2 к origin (сейчас origin — HTTP/1.1), gRPC-трейлеры, WS-фреймы во viewer

**M8 — Throttling/Chaos, DNS Spoofing, Mirror, Auto Save, Profiles**

**M9 — Импорт/экспорт совместимости**
- `.chlz`/`.chls` импорт, HAR импорт, cURL copy (уже частично в M2/M2.5), CSV

**M10 — Полировка**
- HTTP/3 (quinn/h3), Windows system proxy (реестр), Client Process, IPv6/SOCKS5,
  Happy Eyeballs

---

## 10. Стек библиотек — сводная таблица

| Назначение | Крейт |
|---|---|
| Async runtime | `tokio` |
| HTTP | `hyper`, `hyper-util`, `http`, `http-body-util` |
| TLS | `rustls`, `tokio-rustls`, `rcgen` |
| WebSocket | `tokio-tungstenite` |
| HTTP/3 (позже) | `quinn`, `h3` |
| DNS | `hickory-resolver` |
| SOCKS5 | `fast-socks5` или свой |
| Сжатие | `flate2`, `brotli`, `zstd` |
| Сериализация | `serde`, `serde_json`, `quick-xml`, `toml` |
| Protobuf | `prost` + динамический дескриптор-реестр |
| Хранилище | `rusqlite` или `redb`/`sled`, `zip` для `.rpz`/`.chlz` |
| GUI | `eframe`/`egui`, `egui_plot`, `syntect` |
| CLI/TUI | `clap`, `ratatui`, `crossterm` |
| IPC daemon↔клиенты | `tonic` (gRPC) или свой протокол на `tokio::net::UnixListener` / named pipe |
| Логи | `tracing`, `tracing-subscriber` |

---

## 11. Открытые вопросы для решения на старте
1. Формат конфигурации профилей/правил — TOML (человекочитаемо, удобно для CLI) или JSON
   (совместимо с экспортом Charles)? → предлагается TOML для конфигов, JSON внутри `.rpz`.
2. Нужна ли поддержка мобильных клиентов "из коробки" (как Charles for iOS) — вероятно, нет
   в первой версии; достаточно того, что телефон может использовать rproxy как обычный HTTP-proxy.
3. Лицензия: MIT/Apache-2.0 — стандарт для открытых Rust-проектов. → **Решено: MIT** (2026-09).

### 11.1 Решено в ходе работы
- MITM по умолчанию включён в GUI/CLI (`with_mitm()`), CA в `~/.rproxy`; верификация
  сертификата origin отключена до появления настройки (debug proxy по умолчанию).
- Origin-соединения в MITM — HTTP/1.1 (h2 к origin — M7).
- GUI в стиле Charles: меню-бар, иконочный тулбар, дерево хостов с Encrypted-группой,
  Filter внизу панели, статус-бар «Recording». Тела запросов/ответов — с M2.
- MCP-этап M2.5 вставлен после захвата тел (см. §2.1, §9): без тел MCP-тулам читать нечего.
