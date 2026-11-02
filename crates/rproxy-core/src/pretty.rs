//! Pretty-print тел ответов: JSON, JavaScript, CSS, HTML.
//!
//! Идея взята из проекта unminify-js (github.com/EwenLoy/unminify-js):
//! сначала определить язык (по Content-Type, затем эвристикой по тексту),
//! потом отдать соответствующему форматтеру. Сами форматтеры здесь свои —
//! компактные токенайзеры на Rust, без порта Chromium devtools.
//!
//! Форматтеры сохраняют строки, шаблонные литералы, регулярки и комментарии
//! как есть: они не пытаются «понять» код, а расставляют отступы и переводы строк.

use serde_json::Value;

/// Язык тела, для которого нашёлся форматтер.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Json,
    Js,
    Css,
    Html,
}

impl Lang {
    pub fn name(self) -> &'static str {
        match self {
            Lang::Json => "JSON",
            Lang::Js => "JavaScript",
            Lang::Css => "CSS",
            Lang::Html => "HTML",
        }
    }
}

/// Определить язык по Content-Type, затем по содержимому.
pub fn detect(content_type: Option<&str>, body: &str) -> Option<Lang> {
    if let Some(ct) = content_type {
        let ct = ct.to_ascii_lowercase();
        if ct.contains("json") {
            return Some(Lang::Json);
        }
        if ct.contains("javascript") || ct.contains("ecmascript") {
            return Some(Lang::Js);
        }
        if ct.contains("css") {
            return Some(Lang::Css);
        }
        if ct.contains("html") {
            return Some(Lang::Html);
        }
    }
    let t = body.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        return Some(Lang::Json);
    }
    if t.starts_with("<!doctype") || t.starts_with("<!DOCTYPE") || t.starts_with('<') {
        return Some(Lang::Html);
    }
    let head: String = t.chars().take(300).collect();
    if head.contains("function")
        || head.contains("=>")
        || head.starts_with("var ")
        || head.starts_with("const ")
        || head.starts_with("let ")
        || head.starts_with("(function")
        || head.contains("window.")
        || head.contains("document.")
    {
        return Some(Lang::Js);
    }
    None
}

/// Отформатировать тело. `None` — либо язык не распознан, либо тело не разбирается.
pub fn pretty_print(content_type: Option<&str>, body: &str) -> Option<(Lang, String)> {
    let lang = detect(content_type, body)?;
    let text = match lang {
        Lang::Json => pretty_json(body)?,
        Lang::Js => pretty_js(body),
        Lang::Css => pretty_css(body),
        Lang::Html => pretty_html(body),
    };
    Some((lang, text))
}

// ---------------- JSON ----------------

fn pretty_json(src: &str) -> Option<String> {
    let v: Value = serde_json::from_str(src).ok()?;
    serde_json::to_string_pretty(&v).ok()
}

// ---------------- общие помощники ----------------

fn push_indent(out: &mut String, depth: i32) {
    for _ in 0..depth.max(0) {
        out.push_str("  ");
    }
}

/// Начать новую строку с отступом `depth`. Идемпотентна: повторный вызов на уже
/// пустой (с отступом) строке ничего не ломает.
fn newline(out: &mut String, depth: i32) {
    while out.ends_with(' ') || out.ends_with('\t') {
        out.pop();
    }
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if out.is_empty() || out.ends_with('\n') {
        push_indent(out, depth);
    }
}

fn starts_with_at(chars: &[char], i: usize, pat: &str) -> bool {
    let mut j = i;
    for pc in pat.chars() {
        if j >= chars.len() || chars[j] != pc {
            return false;
        }
        j += 1;
    }
    true
}

// ---------------- JavaScript ----------------

fn pretty_js(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len() + src.len() / 4);
    let mut depth: i32 = 0;
    let mut i = 0usize;
    let mut prev: char = '\0'; // последний значимый символ вывода (для regex/пробелов)

    while i < chars.len() {
        let c = chars[i];

        // комментарии
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            let start = i;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            if !out.ends_with('\n') && !out.is_empty() {
                newline(&mut out, depth);
            }
            out.push_str(text.trim_end());
            newline(&mut out, depth);
            prev = '\0';
            continue;
        }
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            let start = i;
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            let text: String = chars[start..i].iter().collect();
            if !out.ends_with('\n') && !out.is_empty() {
                newline(&mut out, depth);
            }
            out.push_str(&text);
            newline(&mut out, depth);
            prev = '\0';
            continue;
        }

        // строки и шаблонные литералы
        if c == '"' || c == '\'' || c == '`' {
            let quote = c;
            let start = i;
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' {
                    i += 2;
                    continue;
                }
                if chars[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
            let text: String = chars[start..i.min(chars.len())].iter().collect();
            out.push_str(&text);
            prev = quote;
            continue;
        }

        // регулярное выражение: '/' в позиции, где ожидается выражение
        if c == '/' && is_regex_position(prev) {
            let start = i;
            i += 1;
            let mut in_class = false;
            while i < chars.len() {
                match chars[i] {
                    '\\' => i += 2,
                    '[' => {
                        in_class = true;
                        i += 1;
                    }
                    ']' => {
                        in_class = false;
                        i += 1;
                    }
                    '/' if !in_class => {
                        i += 1;
                        break;
                    }
                    '\n' => break,
                    _ => i += 1,
                }
            }
            let text: String = chars[start..i.min(chars.len())].iter().collect();
            out.push_str(&text);
            prev = '/';
            continue;
        }

        match c {
            '{' => {
                if !out.is_empty() && !matches!(prev, ' ' | '\n' | '(' | '[' | '{') {
                    out.push(' ');
                }
                out.push('{');
                depth += 1;
                newline(&mut out, depth);
                prev = '{';
            }
            '}' => {
                depth -= 1;
                newline(&mut out, depth);
                out.push('}');
                // после '}' перевод строки, если дальше не ; , ) ] . else
                let next = chars[i + 1..].iter().find(|c| !c.is_whitespace()).copied();
                if !matches!(next, Some(';') | Some(',') | Some(')') | Some(']') | Some('.') | Some('}')) {
                    newline(&mut out, depth);
                }
                prev = '}';
            }
            ';' => {
                out.push(';');
                newline(&mut out, depth);
                prev = ';';
            }
            ',' => {
                out.push(',');
                out.push(' ');
                prev = ',';
            }
            '=' => {
                // '==' '===' '=>' '<=' '>=' '!=' — не трогаем, одиночный '=' — с пробелами
                let next = chars.get(i + 1).copied().unwrap_or('\0');
                let assignment = !matches!(next, '=' | '>')
                    && !matches!(prev, '=' | '!' | '<' | '>' | '+')
                    && !out.ends_with(' ');
                if assignment {
                    if !out.ends_with(' ') {
                        out.push(' ');
                    }
                    out.push('=');
                    out.push(' ');
                    prev = '=';
                } else {
                    out.push('=');
                    prev = '=';
                }
            }
            ' ' | '\t' | '\r' | '\n' => {
                if !out.is_empty() && !out.ends_with(' ') && !out.ends_with('\n') {
                    out.push(' ');
                    prev = ' ';
                }
            }
            _ => {
                out.push(c);
                prev = c;
            }
        }
        i += 1;
    }

    trim_lines(out)
}

/// '/' — начало регулярки, если предыдущий значимый символ не может стоять перед делением.
fn is_regex_position(prev: char) -> bool {
    matches!(
        prev,
        '\0' | '(' | ',' | '=' | ':' | '[' | '!' | '&' | '|' | '?' | '{' | '}' | ';' | '+' | '-'
            | '*' | '%' | '^' | '~' | '<' | '>' | '\n'
    )
}

fn trim_lines(s: String) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, line) in s.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line.trim_end());
    }
    out
}

// ---------------- CSS ----------------

fn pretty_css(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut depth: i32 = 0;
    let mut in_block = false;
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];

        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            let start = i;
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            let text: String = chars[start..i].iter().collect();
            newline(&mut out, depth);
            out.push_str(&text);
            i += 1;
            continue;
        }

        if c == '"' || c == '\'' {
            let quote = c;
            let start = i;
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' {
                    i += 2;
                    continue;
                }
                if chars[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
            let text: String = chars[start..i.min(chars.len())].iter().collect();
            out.push_str(&text);
            continue;
        }

        match c {
            '{' => {
                out.push_str(" {");
                depth += 1;
                in_block = true;
                newline(&mut out, depth);
            }
            '}' => {
                depth -= 1;
                in_block = false;
                newline(&mut out, depth);
                out.push('}');
                newline(&mut out, depth);
            }
            ';' => {
                out.push(';');
                newline(&mut out, depth);
            }
            ':' => {
                // В блоке объявлений это свойство (": "), в селекторе — псевдокласс (":").
                if in_block {
                    out.push(':');
                    out.push(' ');
                } else {
                    out.push(':');
                }
            }
            ',' => {
                out.push(',');
                out.push(' ');
            }
            ' ' | '\t' | '\r' | '\n' => {
                if !out.is_empty() && !out.ends_with(' ') && !out.ends_with('\n') && out.ends_with(|c: char| c.is_alphanumeric() || c == '%' || c == ')') {
                    out.push(' ');
                }
            }
            _ => out.push(c),
        }
        i += 1;
    }

    trim_lines(out)
}

// ---------------- HTML ----------------

const VOID_TAGS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

fn pretty_html(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len() + src.len() / 3);
    let mut depth: i32 = 0;
    let mut i = 0usize;

    while i < chars.len() {
        if chars[i] == '<' {
            // комментарий / doctype / тег — до '>' с учётом кавычек
            let start = i;
            if starts_with_at(&chars, i, "<!--") {
                i += 4;
                while i + 2 < chars.len() && !starts_with_at(&chars, i, "-->") {
                    i += 1;
                }
                i = (i + 3).min(chars.len());
            } else if starts_with_at(&chars, i, "<![CDATA[") {
                i += 9;
                while i + 2 < chars.len() && !starts_with_at(&chars, i, "]]>") {
                    i += 1;
                }
                i = (i + 3).min(chars.len());
            } else {
                i += 1;
                let mut quote: Option<char> = None;
                while i < chars.len() {
                    let ch = chars[i];
                    if let Some(q) = quote {
                        if ch == q {
                            quote = None;
                        }
                    } else if ch == '"' || ch == '\'' {
                        quote = Some(ch);
                    } else if ch == '>' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            let tag: String = chars[start..i.min(chars.len())].iter().collect();
            let trimmed = tag.trim();
            let is_close = trimmed.starts_with("</");
            let is_decl = trimmed.starts_with("<!") || trimmed.starts_with("<?");
            let name = tag_name(trimmed);
            let self_closing = trimmed.ends_with("/>") || VOID_TAGS.contains(&name.as_str());

            if is_close {
                depth -= 1;
            }
            newline(&mut out, depth);
            out.push_str(trimmed);

            // Короткий текст-ребёнок держим в одну строку: <p>hi</p>, <title>T</title>.
            if !is_close && !self_closing && !is_decl && name != "script" && name != "style" {
                let close = format!("</{name}");
                let mut j = i;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                let text_start = j;
                while j < chars.len() && chars[j] != '<' {
                    j += 1;
                }
                let text = chars[text_start..j]
                    .iter()
                    .collect::<String>()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                if starts_with_at_lower(&chars, j, &close)
                    && !text.is_empty()
                    && text.chars().count() <= 80
                {
                    out.push_str(&text);
                    let mut k = j;
                    while k < chars.len() && chars[k] != '>' {
                        k += 1;
                    }
                    let closing: String = chars[j..(k + 1).min(chars.len())].iter().collect();
                    out.push_str(closing.trim());
                    i = (k + 1).min(chars.len());
                    newline(&mut out, depth);
                    continue;
                }
            }

            if !is_close && !self_closing && !is_decl {
                depth += 1;
            }
            newline(&mut out, depth);

            // script/style: содержимое не трогаем
            if !is_close && (name == "script" || name == "style") {
                let close = format!("</{name}");
                let content_start = i;
                while i < chars.len() && !starts_with_at_lower(&chars, i, &close) {
                    i += 1;
                }
                let content: String = chars[content_start..i].iter().collect();
                let content = content.trim();
                if !content.is_empty() {
                    out.push_str(content);
                    newline(&mut out, depth);
                }
            }
            continue;
        }

        // текстовый узел
        let start = i;
        while i < chars.len() && chars[i] != '<' {
            i += 1;
        }
        let text: String = chars[start..i].iter().collect();
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if !text.is_empty() {
            newline(&mut out, depth);
            out.push_str(&text);
            newline(&mut out, depth);
        }
    }

    trim_lines(out)
}

fn starts_with_at_lower(chars: &[char], i: usize, pat: &str) -> bool {
    let mut j = i;
    for pc in pat.chars() {
        if j >= chars.len() || chars[j].to_ascii_lowercase() != pc.to_ascii_lowercase() {
            return false;
        }
        j += 1;
    }
    true
}

fn tag_name(tag: &str) -> String {
    let t = tag.trim_start_matches('<').trim_start_matches('/');
    t.split(|c: char| c.is_whitespace() || c == '>' || c == '/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_by_content_type_and_body() {
        assert_eq!(detect(Some("application/json"), "{}"), Some(Lang::Json));
        assert_eq!(detect(Some("text/javascript"), "var a=1"), Some(Lang::Js));
        assert_eq!(detect(Some("text/css"), "a{}"), Some(Lang::Css));
        assert_eq!(detect(Some("text/html"), ""), Some(Lang::Html));
        assert_eq!(detect(None, "{\"a\":1}"), Some(Lang::Json));
        assert_eq!(detect(None, "<!DOCTYPE html><p>x"), Some(Lang::Html));
        assert_eq!(detect(None, "function f(){return 1}"), Some(Lang::Js));
        assert_eq!(detect(None, "просто текст"), None);
    }

    #[test]
    fn json_is_indented() {
        let (lang, out) = pretty_print(Some("application/json"), "{\"a\":1,\"b\":[1,2]}").unwrap();
        assert_eq!(lang, Lang::Json);
        assert!(out.contains("\n  \"a\": 1"), "{out}");
    }

    #[test]
    fn js_keeps_strings_and_splits_statements() {
        let src = "function f(a){var s=\"a;b{c}\";if(a){return s}else{return null}}";
        let (lang, out) = pretty_print(Some("text/javascript"), src).unwrap_or((Lang::Js, String::new()));
        assert_eq!(lang, Lang::Js);
        assert!(out.contains("a;b{c}"), "строку не тронули: {out}");
        assert!(out.lines().count() > 3, "должно быть многострочно: {out}");
    }

    #[test]
    fn css_formats_rules() {
        let out = pretty_css("a{color:red;margin:0 1px}b{}.c{x:1}");
        assert!(out.contains("a {"), "{out}");
        assert!(out.contains("color: red;"), "{out}");
    }

    #[test]
    fn html_indents_nested_tags() {
        let out = pretty_html("<div><p>hi</p><br><span>x</span></div>");
        assert!(out.contains("<div>"), "{out}");
        assert!(out.contains("  <p>"), "вложенность: {out}");
        assert!(out.lines().count() >= 4, "{out}");
    }
}
