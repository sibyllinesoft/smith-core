#[cfg(feature = "grpc")]
use serde::Serialize;

#[cfg(feature = "grpc")]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct UiBounds {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[cfg(feature = "grpc")]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct UiWindowRecord {
    pub window_id: String,
    pub destination: String,
    pub object_path: String,
    pub title: Option<String>,
    pub role: Option<String>,
    pub bounds: Option<UiBounds>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inspectable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
}
