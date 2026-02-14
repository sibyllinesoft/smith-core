#![cfg(feature = "otel-exporter")]

use crate::bridge::ChatBridge;
use crate::format::{format_trace_header, SpanPresentation, TraceHeader};
use crate::message::{ChannelAddress, MessageContent};
use crate::OutgoingMessage;
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use opentelemetry::trace::{SpanId, SpanKind, Status, TraceError};
use opentelemetry::Array as OtelArray;
use opentelemetry::{KeyValue as OtelKeyValue, Value as OtelValue};
use opentelemetry_sdk::export::trace::{ExportResult, SpanData, SpanExporter};
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;

#[derive(Clone)]
struct ThreadInfo {
    root_post_id: String,
}

struct ExporterState {
    bridge: Arc<ChatBridge>,
    adapter_id: String,
    channel: ChannelAddress,
    thread_prefix: Option<String>,
    threads: Mutex<HashMap<String, ThreadInfo>>,
}

impl ExporterState {
    async fn ensure_thread(&self, trace_id: &str, span: &SpanData) -> Result<String, TraceError> {
        {
            let threads = self.threads.lock().await;
            if let Some(info) = threads.get(trace_id) {
                return Ok(info.root_post_id.clone());
            }
        }

        let header = trace_header_from_span(trace_id, span, self.thread_prefix.as_deref());
        let content = format_trace_header(&header);
        let message = OutgoingMessage::new(self.channel.clone(), MessageContent::markdown(content));
        let receipt = self
            .bridge
            .send(&self.adapter_id, message)
            .await
            .map_err(to_trace_error)?;

        let thread_id = receipt
            .channel
            .thread_id
            .clone()
            .unwrap_or_else(|| receipt.message_id.clone());

        let mut threads = self.threads.lock().await;
        threads.insert(
            trace_id.to_string(),
            ThreadInfo {
                root_post_id: thread_id.clone(),
            },
        );

        Ok(thread_id)
    }
}

#[derive(Clone)]
pub struct MattermostTasksExporter {
    state: Arc<ExporterState>,
}

impl MattermostTasksExporter {
    pub fn new(
        bridge: Arc<ChatBridge>,
        adapter_id: impl Into<String>,
        channel: ChannelAddress,
        thread_prefix: Option<String>,
    ) -> Self {
        Self {
            state: Arc::new(ExporterState {
                bridge,
                adapter_id: adapter_id.into(),
                channel,
                thread_prefix,
                threads: Mutex::new(HashMap::new()),
            }),
        }
    }

    async fn process_batch(&self, batch: Vec<SpanData>) -> Result<(), TraceError> {
        let mut grouped: HashMap<String, Vec<SpanData>> = HashMap::new();
        for span in batch {
            grouped
                .entry(span.span_context.trace_id().to_string())
                .or_default()
                .push(span);
        }

        for (trace_id, mut spans) in grouped {
            spans.sort_by_key(|span| span.start_time);
            if spans.is_empty() {
                continue;
            }

            let thread_id = self.state.ensure_thread(&trace_id, &spans[0]).await?;

            let presentations: Vec<SpanPresentation> = spans
                .iter()
                .map(|span| span_to_presentation(&trace_id, span))
                .collect();

            let summary = crate::format::format_span_summary(&presentations);
            let mut summary_message = OutgoingMessage::new(
                self.state.channel.clone(),
                MessageContent::markdown(summary),
            );
            summary_message.reply_in_thread = Some(thread_id.clone());
            self.state
                .bridge
                .send(&self.state.adapter_id, summary_message)
                .await
                .map_err(to_trace_error)?;

            if let Some(content) = crate::format::format_notable_spans(&presentations) {
                let mut detail = OutgoingMessage::new(
                    self.state.channel.clone(),
                    MessageContent::markdown(content),
                );
                detail.reply_in_thread = Some(thread_id.clone());
                self.state
                    .bridge
                    .send(&self.state.adapter_id, detail)
                    .await
                    .map_err(to_trace_error)?;
            }
        }

        Ok(())
    }
}

impl fmt::Debug for MattermostTasksExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MattermostTasksExporter")
            .field("adapter_id", &self.state.adapter_id)
            .field("channel_id", &self.state.channel.channel_id)
            .finish()
    }
}

impl SpanExporter for MattermostTasksExporter {
    fn export(&mut self, batch: Vec<SpanData>) -> BoxFuture<'static, ExportResult> {
        let exporter = self.clone();
        Box::pin(async move { exporter.process_batch(batch).await })
    }
}

fn to_trace_error<E>(err: E) -> TraceError
where
    E: std::error::Error + Send + Sync + 'static,
{
    TraceError::Other(Box::new(err))
}

fn format_status(status: &Status) -> String {
    match status {
        Status::Ok => "ok".to_string(),
        Status::Unset => "unset".to_string(),
        Status::Error { description } => {
            if description.is_empty() {
                "error".to_string()
            } else {
                format!("error: {}", description)
            }
        }
    }
}

fn format_span_kind(kind: &SpanKind) -> &'static str {
    match kind {
        SpanKind::Server => "server",
        SpanKind::Client => "client",
        SpanKind::Producer => "producer",
        SpanKind::Consumer => "consumer",
        SpanKind::Internal => "internal",
    }
}

fn attributes_to_json(attributes: &[OtelKeyValue]) -> JsonValue {
    if attributes.is_empty() {
        return JsonValue::Null;
    }

    let mut map = JsonMap::new();
    for attr in attributes {
        map.insert(
            attr.key.as_str().to_string(),
            otel_value_to_json(&attr.value),
        );
    }
    JsonValue::Object(map)
}

fn events_to_json(span: &SpanData) -> Option<JsonValue> {
    if span.events.events.is_empty() {
        return None;
    }

    let mut events = Vec::new();
    for event in &span.events.events {
        let mut obj = JsonMap::new();
        obj.insert("name".into(), JsonValue::String(event.name.to_string()));
        obj.insert(
            "timestamp".into(),
            JsonValue::String(format_system_time(event.timestamp)),
        );

        if !event.attributes.is_empty() {
            obj.insert("attributes".into(), attributes_to_json(&event.attributes));
        }

        events.push(JsonValue::Object(obj));
    }

    Some(JsonValue::Array(events))
}

fn otel_value_to_json(value: &OtelValue) -> JsonValue {
    match value {
        OtelValue::Bool(v) => JsonValue::Bool(*v),
        OtelValue::I64(v) => JsonValue::Number((*v).into()),
        OtelValue::F64(v) => serde_json::Number::from_f64(*v)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        OtelValue::String(v) => JsonValue::String(v.to_string()),
        OtelValue::Array(values) => match values {
            OtelArray::Bool(items) => {
                JsonValue::Array(items.iter().map(|v| JsonValue::Bool(*v)).collect())
            }
            OtelArray::I64(items) => JsonValue::Array(
                items
                    .iter()
                    .map(|v| JsonValue::Number((*v).into()))
                    .collect(),
            ),
            OtelArray::F64(items) => JsonValue::Array(
                items
                    .iter()
                    .map(|v| {
                        serde_json::Number::from_f64(*v)
                            .map(JsonValue::Number)
                            .unwrap_or(JsonValue::Null)
                    })
                    .collect(),
            ),
            OtelArray::String(items) => JsonValue::Array(
                items
                    .iter()
                    .map(|v| JsonValue::String(v.as_str().to_string()))
                    .collect(),
            ),
        },
    }
}

fn trace_header_from_span(trace_id: &str, span: &SpanData, prefix: Option<&str>) -> TraceHeader {
    let service_name = extract_service_name(span);
    TraceHeader {
        trace_id: trace_id.to_string(),
        service_name,
        root_span_name: span.name.to_string(),
        status: format_status(&span.status),
        started_at: system_time_to_datetime(span.start_time),
        prefix: prefix.map(|s| s.to_string()),
        is_root_span: span.parent_span_id == SpanId::INVALID,
    }
}

fn span_to_presentation(trace_id: &str, span: &SpanData) -> SpanPresentation {
    let start_time = system_time_to_datetime(span.start_time);
    let end_time = system_time_to_datetime(span.end_time);
    let duration = span
        .end_time
        .duration_since(span.start_time)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let attributes_json = attributes_to_json(&span.attributes);
    let events_json = events_to_json(span);

    SpanPresentation {
        trace_id: trace_id.to_string(),
        span_id: span.span_context.span_id().to_string(),
        parent_span_id: if span.parent_span_id == SpanId::INVALID {
            None
        } else {
            Some(span.parent_span_id.to_string())
        },
        name: span.name.to_string(),
        kind: format_span_kind(&span.span_kind).to_string(),
        status: format_status(&span.status),
        start_time,
        end_time,
        duration,
        attributes: if attributes_json.is_null() {
            None
        } else {
            Some(attributes_json)
        },
        events: events_json,
    }
}

fn extract_service_name(span: &SpanData) -> String {
    for attr in &span.attributes {
        if attr.key.as_str() == "service.name" {
            return match otel_value_to_json(&attr.value) {
                JsonValue::String(s) => s,
                other => other.to_string(),
            };
        }
    }

    let name = span.instrumentation_lib.name.as_ref();
    if name.is_empty() {
        "unknown-service".to_string()
    } else {
        name.to_string()
    }
}

fn system_time_to_datetime(time: SystemTime) -> DateTime<Utc> {
    time.into()
}

fn format_system_time(time: SystemTime) -> String {
    system_time_to_datetime(time).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
