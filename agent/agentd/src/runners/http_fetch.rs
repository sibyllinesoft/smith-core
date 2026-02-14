use anyhow::{Context, Result};
use async_trait::async_trait;
use regex::Regex;
use reqwest::{Client, Method, Url};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, warn};

use super::{ExecContext, ExecutionResult, OutputSink, Runner};
use smith_protocol::ExecutionStatus;

/// HTTP fetch runner for http.fetch capability
pub struct HttpFetchRunner {
    version: String,
    client: Client,
}

impl HttpFetchRunner {
    /// Create new http.fetch runner
    pub fn new() -> Self {
        // Create HTTP client with reasonable defaults
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent("Smith-Executor/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            version: "http-fetch-v1".to_string(),
            client,
        }
    }

    /// Validate URL against allowed patterns
    fn validate_url(&self, url: &str, allowed_patterns: &[String]) -> Result<()> {
        // Parse URL to ensure it's valid
        let parsed_url = Url::parse(url).with_context(|| format!("Invalid URL: {}", url))?;

        // Ensure HTTPS only
        if parsed_url.scheme() != "https" {
            return Err(anyhow::anyhow!(
                "Only HTTPS URLs are allowed, got: {}",
                parsed_url.scheme()
            ));
        }

        // Check against allowed URL patterns (regex)
        for pattern in allowed_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(url) {
                    debug!("URL {} matches allowed pattern {}", url, pattern);
                    return Ok(());
                }
            } else {
                warn!("Invalid regex pattern in URL allowlist: {}", pattern);
            }
        }

        Err(anyhow::anyhow!(
            "URL {} does not match any allowed pattern",
            url
        ))
    }

    /// Validate HTTP headers
    fn validate_headers(&self, headers: &HashMap<String, String>) -> Result<()> {
        // Allowed header names (whitelist)
        let allowed_headers = [
            "accept",
            "accept-encoding",
            "accept-language",
            "cache-control",
            "if-none-match",
            "user-agent",
        ];

        for (name, value) in headers {
            let name_lower = name.to_lowercase();

            if !allowed_headers.contains(&name_lower.as_str()) {
                return Err(anyhow::anyhow!("Header '{}' is not allowed", name));
            }

            // Validate header value length
            if value.len() > 1024 {
                return Err(anyhow::anyhow!(
                    "Header '{}' value too long (max 1024 chars)",
                    name
                ));
            }

            // Basic validation for suspicious header values
            if value.contains('\n') || value.contains('\r') {
                return Err(anyhow::anyhow!(
                    "Header '{}' contains invalid characters",
                    name
                ));
            }
        }

        Ok(())
    }

    /// Execute HTTP request with constraints
    async fn execute_request(
        &self,
        url: &str,
        method: Method,
        headers: HashMap<String, String>,
        timeout_ms: u64,
        max_bytes: u64,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        let start_time = std::time::Instant::now();

        out.write_log(
            "INFO",
            &format!("Starting HTTP {} request to {}", method, url),
        )?;

        // Create request builder
        let mut request_builder = self.client.request(method.clone(), url);

        // Set timeout
        if timeout_ms > 0 {
            request_builder = request_builder.timeout(Duration::from_millis(timeout_ms));
        }

        // Add headers
        for (name, value) in headers {
            request_builder = request_builder.header(&name, &value);
        }

        // Execute request
        let response = match request_builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = format!("Request failed: {}", e);
                out.write_log("ERROR", &error_msg)?;
                out.write_stderr(error_msg.as_bytes())?;

                return Ok(ExecutionResult {
                    status: ExecutionStatus::Error,
                    exit_code: Some(1),
                    artifacts: vec![],
                    duration_ms: start_time.elapsed().as_millis() as u64,
                    stdout_bytes: 0,
                    stderr_bytes: error_msg.len() as u64,
                });
            }
        };

        let status_code = response.status();
        let headers = response.headers().clone();

        out.write_log("INFO", &format!("Response status: {}", status_code))?;

        // Log response headers
        for (name, value) in headers.iter() {
            if let Ok(value_str) = value.to_str() {
                out.write_log("DEBUG", &format!("Response header {}: {}", name, value_str))?;
            }
        }

        // Check content length
        let content_length = response.content_length().unwrap_or(0);
        if content_length > max_bytes {
            let error_msg = format!(
                "Response too large: {} bytes (max: {} bytes)",
                content_length, max_bytes
            );
            out.write_log("ERROR", &error_msg)?;
            out.write_stderr(error_msg.as_bytes())?;

            return Ok(ExecutionResult {
                status: ExecutionStatus::Error,
                exit_code: Some(2),
                artifacts: vec![],
                duration_ms: start_time.elapsed().as_millis() as u64,
                stdout_bytes: 0,
                stderr_bytes: error_msg.len() as u64,
            });
        }

        // Read response body with size limit
        match response.bytes().await {
            Ok(body) => {
                if body.len() as u64 > max_bytes {
                    let error_msg = format!(
                        "Response body too large: {} bytes (max: {} bytes)",
                        body.len(),
                        max_bytes
                    );
                    out.write_log("ERROR", &error_msg)?;
                    out.write_stderr(error_msg.as_bytes())?;

                    return Ok(ExecutionResult {
                        status: ExecutionStatus::Error,
                        exit_code: Some(3),
                        artifacts: vec![],
                        duration_ms: start_time.elapsed().as_millis() as u64,
                        stdout_bytes: 0,
                        stderr_bytes: error_msg.len() as u64,
                    });
                }

                // Write response body to stdout
                out.write_stdout(&body)?;
                out.write_log(
                    "INFO",
                    &format!("Successfully fetched {} bytes", body.len()),
                )?;

                let stdout_bytes = body.len() as u64;

                Ok(ExecutionResult {
                    status: ExecutionStatus::Ok,
                    exit_code: Some(0),
                    artifacts: vec![],
                    duration_ms: start_time.elapsed().as_millis() as u64,
                    stdout_bytes,
                    stderr_bytes: 0,
                })
            }
            Err(e) => {
                let error_msg = format!("Failed to read response body: {}", e);
                out.write_log("ERROR", &error_msg)?;
                out.write_stderr(error_msg.as_bytes())?;

                Ok(ExecutionResult {
                    status: ExecutionStatus::Error,
                    exit_code: Some(4),
                    artifacts: vec![],
                    duration_ms: start_time.elapsed().as_millis() as u64,
                    stdout_bytes: 0,
                    stderr_bytes: error_msg.len() as u64,
                })
            }
        }
    }
}

#[async_trait]
impl Runner for HttpFetchRunner {
    fn digest(&self) -> String {
        self.version.clone()
    }

    fn validate_params(&self, params: &Value) -> Result<()> {
        // Validate method parameter (optional, defaults to GET)
        if let Some(method) = params.get("method") {
            let method_str = method
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("method must be a string"))?;

            match method_str {
                "GET" | "HEAD" => {} // Allowed methods
                _ => {
                    return Err(anyhow::anyhow!(
                        "method must be GET or HEAD, got: {}",
                        method_str
                    ));
                }
            }
        }

        // Validate headers parameter (optional)
        if let Some(headers) = params.get("headers") {
            if !headers.is_object() {
                return Err(anyhow::anyhow!("headers must be an object"));
            }

            let headers_map = headers.as_object().unwrap();
            if headers_map.len() > 10 {
                return Err(anyhow::anyhow!("too many headers (max: 10)"));
            }

            for (name, value) in headers_map {
                if !value.is_string() {
                    return Err(anyhow::anyhow!("header '{}' value must be a string", name));
                }
            }
        }

        // Validate timeout_ms parameter (optional)
        if let Some(timeout) = params.get("timeout_ms") {
            if !timeout.is_u64() {
                return Err(anyhow::anyhow!("timeout_ms must be a non-negative integer"));
            }

            let timeout_val = timeout.as_u64().unwrap();
            if timeout_val < 50 || timeout_val > 30_000 {
                return Err(anyhow::anyhow!("timeout_ms must be between 50 and 30000"));
            }
        }

        Ok(())
    }

    async fn execute(
        &self,
        ctx: &ExecContext,
        params: Value,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        out.write_log("INFO", "Starting http.fetch execution")?;

        // Extract resource URL from scope
        let url = ctx
            .scope
            .urls
            .first()
            .ok_or_else(|| anyhow::anyhow!("No URL provided in scope"))?;

        // Validate URL against allowed patterns
        if let Err(e) = self.validate_url(url, &ctx.scope.urls) {
            out.write_log("ERROR", &format!("URL validation failed: {}", e))?;
            return Ok(ExecutionResult {
                status: ExecutionStatus::Error,
                exit_code: Some(1),
                artifacts: vec![],
                duration_ms: 0,
                stdout_bytes: 0,
                stderr_bytes: 0,
            });
        }

        // Extract parameters
        let method_str = params
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET");

        let method = match method_str {
            "GET" => Method::GET,
            "HEAD" => Method::HEAD,
            _ => return Err(anyhow::anyhow!("Unsupported method: {}", method_str)),
        };

        let headers = if let Some(headers_obj) = params.get("headers") {
            let mut headers_map = HashMap::new();
            for (name, value) in headers_obj.as_object().unwrap() {
                headers_map.insert(name.clone(), value.as_str().unwrap().to_string());
            }
            headers_map
        } else {
            HashMap::new()
        };

        // Validate headers
        if let Err(e) = self.validate_headers(&headers) {
            out.write_log("ERROR", &format!("Header validation failed: {}", e))?;
            return Ok(ExecutionResult {
                status: ExecutionStatus::Error,
                exit_code: Some(1),
                artifacts: vec![],
                duration_ms: 0,
                stdout_bytes: 0,
                stderr_bytes: 0,
            });
        }

        let timeout_ms = params
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(5000); // Default 5 second timeout

        // Get max_bytes from limits (default to 1MB if not set)
        let max_bytes = ctx.limits.io_bytes.max(1_048_576); // At least 1MB

        // Execute the HTTP request
        self.execute_request(url, method, headers, timeout_ms, max_bytes, out)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Note: These imports are currently unused in the tests but may be needed later
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn test_http_fetch_runner() {
        let runner = HttpFetchRunner::new();
        assert_eq!(runner.digest(), "http-fetch-v1");
    }

    #[test]
    fn test_validate_params() {
        let runner = HttpFetchRunner::new();

        // Valid parameters with GET
        let valid_get = json!({
            "method": "GET",
            "headers": {
                "Accept": "application/json",
                "User-Agent": "Test-Agent"
            },
            "timeout_ms": 5000
        });
        assert!(runner.validate_params(&valid_get).is_ok());

        // Valid parameters with HEAD
        let valid_head = json!({
            "method": "HEAD",
            "timeout_ms": 1000
        });
        assert!(runner.validate_params(&valid_head).is_ok());

        // Invalid method
        let invalid_method = json!({"method": "POST"});
        assert!(runner.validate_params(&invalid_method).is_err());

        // Invalid timeout (too low)
        let invalid_timeout_low = json!({"timeout_ms": 10});
        assert!(runner.validate_params(&invalid_timeout_low).is_err());

        // Invalid timeout (too high)
        let invalid_timeout_high = json!({"timeout_ms": 60000});
        assert!(runner.validate_params(&invalid_timeout_high).is_err());

        // Too many headers
        let mut many_headers = json!({});
        let headers_obj = many_headers.as_object_mut().unwrap();
        for i in 0..15 {
            headers_obj.insert(format!("Header{}", i), json!("value"));
        }
        let too_many_headers = json!({"headers": headers_obj});
        assert!(runner.validate_params(&too_many_headers).is_err());
    }

    #[test]
    fn test_validate_url() {
        let runner = HttpFetchRunner::new();
        let allowed_patterns = vec![
            "^https://api\\.example\\.com/.*".to_string(),
            "^https://secure\\.test\\.org/.*".to_string(),
        ];

        // Valid HTTPS URL matching pattern
        assert!(runner
            .validate_url("https://api.example.com/data", &allowed_patterns)
            .is_ok());
        assert!(runner
            .validate_url("https://secure.test.org/info", &allowed_patterns)
            .is_ok());

        // Invalid: HTTP instead of HTTPS
        assert!(runner
            .validate_url("http://api.example.com/data", &allowed_patterns)
            .is_err());

        // Invalid: doesn't match patterns
        assert!(runner
            .validate_url("https://evil.com/malware", &allowed_patterns)
            .is_err());

        // Invalid: malformed URL
        assert!(runner.validate_url("not-a-url", &allowed_patterns).is_err());
    }

    #[test]
    fn test_validate_headers() {
        let runner = HttpFetchRunner::new();

        // Valid headers
        let mut valid_headers = HashMap::new();
        valid_headers.insert("Accept".to_string(), "application/json".to_string());
        valid_headers.insert("User-Agent".to_string(), "Test-Agent/1.0".to_string());
        assert!(runner.validate_headers(&valid_headers).is_ok());

        // Invalid header name
        let mut invalid_headers = HashMap::new();
        invalid_headers.insert("Authorization".to_string(), "Bearer token".to_string());
        assert!(runner.validate_headers(&invalid_headers).is_err());

        // Header value too long
        let mut long_value_headers = HashMap::new();
        long_value_headers.insert("Accept".to_string(), "x".repeat(2000));
        assert!(runner.validate_headers(&long_value_headers).is_err());

        // Header value with newline
        let mut newline_headers = HashMap::new();
        newline_headers.insert(
            "Accept".to_string(),
            "text/plain\nmalicious: header".to_string(),
        );
        assert!(runner.validate_headers(&newline_headers).is_err());
    }

    // Note: Integration tests with real HTTP requests would require a test server
    // For now, we focus on validation and unit test logic

    // ==================== Additional validate_url edge cases ====================

    #[test]
    fn test_validate_url_empty_patterns() {
        let runner = HttpFetchRunner::new();
        let empty_patterns: Vec<String> = vec![];

        // No patterns means no URL matches
        assert!(runner
            .validate_url("https://api.example.com/data", &empty_patterns)
            .is_err());
    }

    #[test]
    fn test_validate_url_invalid_regex_pattern() {
        let runner = HttpFetchRunner::new();
        // Invalid regex pattern should be skipped (with warning)
        let patterns = vec![
            "[invalid(regex".to_string(),                  // Invalid regex
            "^https://api\\.example\\.com/.*".to_string(), // Valid pattern
        ];

        // Should still match the valid pattern
        assert!(runner
            .validate_url("https://api.example.com/data", &patterns)
            .is_ok());
    }

    #[test]
    fn test_validate_url_with_port() {
        let runner = HttpFetchRunner::new();
        let patterns = vec!["^https://api\\.example\\.com.*".to_string()];

        // URL with port number
        assert!(runner
            .validate_url("https://api.example.com:8443/data", &patterns)
            .is_ok());
    }

    #[test]
    fn test_validate_url_with_query_params() {
        let runner = HttpFetchRunner::new();
        let patterns = vec!["^https://api\\.example\\.com.*".to_string()];

        // URL with query parameters
        assert!(runner
            .validate_url("https://api.example.com/data?key=value&foo=bar", &patterns)
            .is_ok());
    }

    #[test]
    fn test_validate_url_with_fragment() {
        let runner = HttpFetchRunner::new();
        let patterns = vec!["^https://api\\.example\\.com.*".to_string()];

        // URL with fragment
        assert!(runner
            .validate_url("https://api.example.com/page#section1", &patterns)
            .is_ok());
    }

    #[test]
    fn test_validate_url_data_scheme() {
        let runner = HttpFetchRunner::new();
        let patterns = vec![".*".to_string()];

        // Data URLs should be rejected (not HTTPS)
        assert!(runner
            .validate_url("data:text/html,<h1>Hello</h1>", &patterns)
            .is_err());
    }

    #[test]
    fn test_validate_url_file_scheme() {
        let runner = HttpFetchRunner::new();
        let patterns = vec![".*".to_string()];

        // File URLs should be rejected (not HTTPS)
        assert!(runner
            .validate_url("file:///etc/passwd", &patterns)
            .is_err());
    }

    #[test]
    fn test_validate_url_ftp_scheme() {
        let runner = HttpFetchRunner::new();
        let patterns = vec![".*".to_string()];

        // FTP URLs should be rejected (not HTTPS)
        assert!(runner
            .validate_url("ftp://files.example.com/file.txt", &patterns)
            .is_err());
    }

    // ==================== Additional validate_headers edge cases ====================

    #[test]
    fn test_validate_headers_empty() {
        let runner = HttpFetchRunner::new();
        let empty_headers: HashMap<String, String> = HashMap::new();

        // Empty headers should be valid
        assert!(runner.validate_headers(&empty_headers).is_ok());
    }

    #[test]
    fn test_validate_headers_carriage_return() {
        let runner = HttpFetchRunner::new();
        let mut headers = HashMap::new();
        headers.insert(
            "Accept".to_string(),
            "text/plain\rmalicious: header".to_string(),
        );

        // Carriage return should be rejected
        assert!(runner.validate_headers(&headers).is_err());
    }

    #[test]
    fn test_validate_headers_case_insensitivity() {
        let runner = HttpFetchRunner::new();

        // Uppercase header names should work (case-insensitive matching)
        let mut headers = HashMap::new();
        headers.insert("ACCEPT".to_string(), "application/json".to_string());
        assert!(runner.validate_headers(&headers).is_ok());

        // Mixed case should work
        let mut headers2 = HashMap::new();
        headers2.insert("User-Agent".to_string(), "Test".to_string());
        assert!(runner.validate_headers(&headers2).is_ok());

        // All lowercase should work
        let mut headers3 = HashMap::new();
        headers3.insert("cache-control".to_string(), "no-cache".to_string());
        assert!(runner.validate_headers(&headers3).is_ok());
    }

    #[test]
    fn test_validate_headers_value_exactly_1024() {
        let runner = HttpFetchRunner::new();

        // Value of exactly 1024 characters should be allowed
        let mut headers = HashMap::new();
        headers.insert("Accept".to_string(), "x".repeat(1024));
        assert!(runner.validate_headers(&headers).is_ok());
    }

    #[test]
    fn test_validate_headers_value_1025() {
        let runner = HttpFetchRunner::new();

        // Value of 1025 characters should be rejected
        let mut headers = HashMap::new();
        headers.insert("Accept".to_string(), "x".repeat(1025));
        assert!(runner.validate_headers(&headers).is_err());
    }

    #[test]
    fn test_validate_headers_forbidden_authorization() {
        let runner = HttpFetchRunner::new();

        // Common sensitive headers that should be forbidden
        let sensitive_headers = [
            "Authorization",
            "Cookie",
            "Set-Cookie",
            "X-Api-Key",
            "X-Auth-Token",
        ];

        for header_name in sensitive_headers {
            let mut headers = HashMap::new();
            headers.insert(header_name.to_string(), "sensitive-value".to_string());
            assert!(
                runner.validate_headers(&headers).is_err(),
                "Header '{}' should be forbidden",
                header_name
            );
        }
    }

    #[test]
    fn test_validate_headers_all_allowed() {
        let runner = HttpFetchRunner::new();

        // Test all allowed headers at once
        let mut headers = HashMap::new();
        headers.insert("Accept".to_string(), "application/json".to_string());
        headers.insert("Accept-Encoding".to_string(), "gzip".to_string());
        headers.insert("Accept-Language".to_string(), "en-US".to_string());
        headers.insert("Cache-Control".to_string(), "no-cache".to_string());
        headers.insert("If-None-Match".to_string(), "abc123".to_string());
        headers.insert("User-Agent".to_string(), "Test/1.0".to_string());

        assert!(runner.validate_headers(&headers).is_ok());
    }

    // ==================== Additional validate_params edge cases ====================

    #[test]
    fn test_validate_params_empty_object() {
        let runner = HttpFetchRunner::new();

        // Empty params should be valid (all defaults)
        let params = json!({});
        assert!(runner.validate_params(&params).is_ok());
    }

    #[test]
    fn test_validate_params_method_non_string() {
        let runner = HttpFetchRunner::new();

        // Method as number should fail
        let params = json!({"method": 123});
        assert!(runner.validate_params(&params).is_err());

        // Method as boolean should fail
        let params2 = json!({"method": true});
        assert!(runner.validate_params(&params2).is_err());
    }

    #[test]
    fn test_validate_params_headers_not_object() {
        let runner = HttpFetchRunner::new();

        // Headers as array should fail
        let params = json!({"headers": ["Accept: application/json"]});
        assert!(runner.validate_params(&params).is_err());

        // Headers as string should fail
        let params2 = json!({"headers": "Accept: application/json"});
        assert!(runner.validate_params(&params2).is_err());
    }

    #[test]
    fn test_validate_params_header_value_non_string() {
        let runner = HttpFetchRunner::new();

        // Header with numeric value should fail
        let params = json!({"headers": {"Accept": 123}});
        assert!(runner.validate_params(&params).is_err());

        // Header with boolean value should fail
        let params2 = json!({"headers": {"Accept": true}});
        assert!(runner.validate_params(&params2).is_err());

        // Header with null value should fail
        let params3 = json!({"headers": {"Accept": null}});
        assert!(runner.validate_params(&params3).is_err());
    }

    #[test]
    fn test_validate_params_timeout_boundary_low() {
        let runner = HttpFetchRunner::new();

        // timeout_ms at minimum boundary (50) should pass
        let params = json!({"timeout_ms": 50});
        assert!(runner.validate_params(&params).is_ok());

        // timeout_ms just below minimum (49) should fail
        let params2 = json!({"timeout_ms": 49});
        assert!(runner.validate_params(&params2).is_err());
    }

    #[test]
    fn test_validate_params_timeout_boundary_high() {
        let runner = HttpFetchRunner::new();

        // timeout_ms at maximum boundary (30000) should pass
        let params = json!({"timeout_ms": 30000});
        assert!(runner.validate_params(&params).is_ok());

        // timeout_ms just above maximum (30001) should fail
        let params2 = json!({"timeout_ms": 30001});
        assert!(runner.validate_params(&params2).is_err());
    }

    #[test]
    fn test_validate_params_timeout_non_integer() {
        let runner = HttpFetchRunner::new();

        // timeout_ms as string should fail
        let params = json!({"timeout_ms": "5000"});
        assert!(runner.validate_params(&params).is_err());

        // timeout_ms as float should fail (not u64)
        let params2 = json!({"timeout_ms": 5000.5});
        assert!(runner.validate_params(&params2).is_err());

        // timeout_ms as negative should fail
        let params3 = json!({"timeout_ms": -1000});
        assert!(runner.validate_params(&params3).is_err());
    }

    #[test]
    fn test_validate_params_exactly_10_headers() {
        let runner = HttpFetchRunner::new();

        // Exactly 10 headers should pass
        let mut headers_obj = serde_json::Map::new();
        for i in 0..10 {
            headers_obj.insert(format!("Header{}", i), json!("value"));
        }
        let params = json!({"headers": headers_obj});
        assert!(runner.validate_params(&params).is_ok());
    }

    #[test]
    fn test_validate_params_11_headers() {
        let runner = HttpFetchRunner::new();

        // 11 headers should fail
        let mut headers_obj = serde_json::Map::new();
        for i in 0..11 {
            headers_obj.insert(format!("Header{}", i), json!("value"));
        }
        let params = json!({"headers": headers_obj});
        assert!(runner.validate_params(&params).is_err());
    }

    #[test]
    fn test_validate_params_method_lowercase() {
        let runner = HttpFetchRunner::new();

        // Lowercase method names should fail (must be uppercase)
        let params = json!({"method": "get"});
        assert!(runner.validate_params(&params).is_err());

        let params2 = json!({"method": "head"});
        assert!(runner.validate_params(&params2).is_err());
    }

    #[test]
    fn test_validate_params_put_delete_methods() {
        let runner = HttpFetchRunner::new();

        // PUT and DELETE should be rejected
        let params = json!({"method": "PUT"});
        assert!(runner.validate_params(&params).is_err());

        let params2 = json!({"method": "DELETE"});
        assert!(runner.validate_params(&params2).is_err());

        let params3 = json!({"method": "PATCH"});
        assert!(runner.validate_params(&params3).is_err());
    }
}
