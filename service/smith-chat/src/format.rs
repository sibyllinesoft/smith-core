use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashSet;
use std::time::Duration;

/// Metadata used to render the root trace header message.
#[derive(Debug, Clone)]
pub struct TraceHeader {
    pub trace_id: String,
    pub service_name: String,
    pub root_span_name: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub prefix: Option<String>,
    pub is_root_span: bool,
}

/// Snapshot of a span used for Mattermost formatting.
#[derive(Debug, Clone)]
pub struct SpanPresentation {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub kind: String,
    pub status: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration: Duration,
    pub attributes: Option<Value>,
    pub events: Option<Value>,
}

/// Render the top-level trace message (creates/updates the Mattermost thread).
pub fn format_trace_header(header: &TraceHeader) -> String {
    let mut content = String::new();
    if let Some(prefix) = &header.prefix {
        if !prefix.is_empty() {
            content.push_str(prefix);
            if !prefix.ends_with(' ') {
                content.push(' ');
            }
        }
    }

    let root_indicator = if header.is_root_span {
        " (root span)"
    } else {
        ""
    };

    content.push_str(&format!(
        "**Trace `{}`**{}\n- Service: `{}`\n- Span: `{}`\n- Status: `{}`\n- Started: {}\n",
        header.trace_id,
        root_indicator,
        header.service_name,
        header.root_span_name,
        header.status,
        format_timestamp(header.started_at),
    ));
    content
}

/// Render a span update message for posting inside a Mattermost thread.
pub fn format_span_message(span: &SpanPresentation) -> String {
    let mut lines = Vec::new();
    lines.push(format!("#### `{}`", span.name));
    lines.push(format!("- **Trace:** `{}`", span.trace_id));
    lines.push(format!("- **Span ID:** `{}`", span.span_id));
    lines.push(format!(
        "- **Parent:** `{}`",
        span.parent_span_id
            .clone()
            .unwrap_or_else(|| "none".to_string())
    ));
    lines.push(format!("- **Kind:** `{}`", span.kind));
    lines.push(format!("- **Status:** `{}`", span.status));
    lines.push(format!(
        "- **Duration:** `{}`",
        human_duration(span.duration)
    ));
    lines.push(format!(
        "- **Start:** {}",
        format_timestamp(span.start_time)
    ));
    lines.push(format!("- **End:** {}", format_timestamp(span.end_time)));

    if let Some(attrs) = span.attributes.as_ref().filter(|v| !v.is_null()) {
        if let Ok(pretty) = serde_json::to_string_pretty(attrs) {
            if !pretty.is_empty() {
                lines.push(String::new());
                lines.push("**Attributes**".into());
                lines.push("```json".into());
                lines.push(pretty);
                lines.push("```".into());
            }
        }
    }

    if let Some(events) = span.events.as_ref().filter(|v| !v.is_null()) {
        if let Ok(pretty) = serde_json::to_string_pretty(events) {
            if !pretty.is_empty() {
                lines.push(String::new());
                lines.push("**Events**".into());
                lines.push("```json".into());
                lines.push(pretty);
                lines.push("```".into());
            }
        }
    }

    lines.join("\n")
}

fn format_timestamp(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn human_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis >= 1000 {
        format!("{:.2}s", millis as f64 / 1000.0)
    } else {
        format!("{}ms", millis)
    }
}

/// Render a compact summary grouped by span category (root, tool calls, other spans).
pub fn format_span_summary(spans: &[SpanPresentation]) -> String {
    let mut lines = vec!["#### Execution Summary".to_string()];

    if let Some(root) = spans.iter().find(|span| span.parent_span_id.is_none()) {
        let (icon, label) = status_badge(&root.status);
        let duration = human_duration(root.duration);
        lines.push(format!(
            "- Root: {} `{}` {} ({})",
            icon, root.name, label, duration
        ));

        if let Some(agent) = extract_attribute(&root.attributes, "agent.name") {
            lines.push(format!("  - Agent: `{}`", agent));
        }
    }

    let conversation_snippets = collect_conversation_snippets(spans);
    if !conversation_snippets.is_empty() {
        lines.push("- **Conversation**".into());
        for (label, text) in conversation_snippets {
            lines.push(format!("  - {}: \"{}\"", label, text));
        }
    }

    let mut tool_lines = Vec::new();
    let mut other_lines = Vec::new();

    for span in spans.iter().filter(|span| span.parent_span_id.is_some()) {
        let (icon, label) = status_badge(&span.status);
        let duration = human_duration(span.duration);

        if let Some(tool_name) = span.name.strip_prefix("tool.call:") {
            tool_lines.push(format!(
                "  - {} `{}` {} ({})",
                icon, tool_name, label, duration
            ));
        } else {
            other_lines.push(format!(
                "  - {} `{}` {} ({}) [kind: {}]",
                icon, span.name, label, duration, span.kind
            ));
        }
    }

    if !tool_lines.is_empty() {
        lines.push("- **Tool Calls**".into());
        lines.extend(tool_lines);
    }

    if !other_lines.is_empty() {
        lines.push("- **Other Spans**".into());
        lines.extend(other_lines);
    }

    if lines.len() == 1 {
        lines.push("_No additional spans recorded_".into());
    }

    lines.join("\n")
}

/// Render detailed information for spans that require attention (e.g. errors).
pub fn format_notable_spans(spans: &[SpanPresentation]) -> Option<String> {
    let mut blocks = Vec::new();
    for span in spans {
        if is_error_status(&span.status) {
            blocks.push(format_span_message(span));
        }
    }

    if blocks.is_empty() {
        return None;
    }

    let mut content = String::from("#### ❗ Notable Spans\n");
    content.push_str(&blocks.join("\n\n"));
    Some(content)
}

fn collect_conversation_snippets(spans: &[SpanPresentation]) -> Vec<(String, String)> {
    const MAX_SNIPPETS: usize = 8;
    const SNIPPET_LIMIT: usize = 160;

    let mut seen = HashSet::new();
    let mut snippets = Vec::new();

    for span in spans {
        let role_hint = span.name.to_ascii_lowercase();

        if let Some(Value::Object(attrs)) = &span.attributes {
            for (key, value) in attrs {
                if let Some(text) = value.as_str() {
                    if !looks_like_conversation_field(key, text) {
                        continue;
                    }

                    if let Some(snippet) = build_snippet(text, SNIPPET_LIMIT) {
                        let label = derive_role_label(key, &role_hint);
                        let dedupe_key = format!("{}:{}", label, snippet);
                        if seen.insert(dedupe_key) {
                            snippets.push((label, snippet));
                            if snippets.len() >= MAX_SNIPPETS {
                                return snippets;
                            }
                        }
                    }
                }
            }
        }
    }

    snippets
}

fn looks_like_conversation_field(key: &str, text: &str) -> bool {
    let cleaned = text.trim();
    if cleaned.is_empty() || cleaned.starts_with("sha256:") {
        return false;
    }

    if cleaned.starts_with('{') || cleaned.starts_with('[') {
        return false;
    }

    let key_lower = key.to_ascii_lowercase();
    if key_lower.contains("hash") || key_lower.contains("token") || key_lower.ends_with(".id") {
        return false;
    }

    const CANDIDATE_KEYS: [&str; 8] = [
        "message",
        "content",
        "prompt",
        "response",
        "summary",
        "transcript",
        "assistant",
        "user",
    ];

    CANDIDATE_KEYS
        .iter()
        .any(|needle| key_lower.contains(needle))
}

fn derive_role_label(key: &str, span_name: &str) -> String {
    let key_lower = key.to_ascii_lowercase();

    if key_lower.contains("user") || key_lower.contains("request") || key_lower.contains("input") {
        "User".to_string()
    } else if key_lower.contains("assistant")
        || key_lower.contains("response")
        || key_lower.contains("output")
        || key_lower.contains("reply")
    {
        "Assistant".to_string()
    } else if key_lower.contains("system") || key_lower.contains("instruction") {
        "System".to_string()
    } else if span_name.contains("tool.call") {
        "Tool".to_string()
    } else if span_name.contains("agent.run") {
        "Agent".to_string()
    } else {
        "Message".to_string()
    }
}

fn build_snippet(text: &str, limit: usize) -> Option<String> {
    let collapsed = collapse_whitespace(text);
    if collapsed.is_empty() {
        return None;
    }

    let total_chars = collapsed.chars().count();
    let mut snippet: String = collapsed.chars().take(limit).collect();
    snippet = snippet.replace('"', "'");

    if total_chars > limit {
        snippet.push_str("...");
    }

    Some(snippet)
}

fn collapse_whitespace(text: &str) -> String {
    let mut collapsed = String::new();
    for (idx, part) in text.split_whitespace().enumerate() {
        if idx > 0 {
            collapsed.push(' ');
        }
        collapsed.push_str(part);
    }
    collapsed.trim().to_string()
}

fn status_badge(status: &str) -> (&'static str, String) {
    let lower = status.to_ascii_lowercase();
    if let Some(message) = lower.strip_prefix("error: ") {
        return (":x:", format!("ERROR ({})", message));
    }
    if lower == "error" {
        return (":x:", "ERROR".to_string());
    }
    if lower == "ok" {
        return (":white_check_mark:", "OK".to_string());
    }
    if lower == "unset" {
        return (":grey_question:", "UNSET".to_string());
    }
    (":information_source:", status.to_string())
}

fn is_error_status(status: &str) -> bool {
    status.to_ascii_lowercase().starts_with("error")
}

fn extract_attribute(attrs: &Option<Value>, key: &str) -> Option<String> {
    match attrs {
        Some(Value::Object(map)) => map.get(key).map(value_to_string),
        _ => None,
    }
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}
