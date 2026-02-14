//! IPC client for connecting to Smith service

use crate::{Command, Event};
use anyhow::{Context, Result};
use serde_json;
use std::path::Path;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info};

/// Connection type for Smith service
pub enum Connection {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Connection {
    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        match self {
            Connection::Unix(stream) => stream.write_all(buf).await.context("Unix write failed"),
            Connection::Tcp(stream) => stream.write_all(buf).await.context("TCP write failed"),
        }
    }

    async fn flush(&mut self) -> Result<()> {
        match self {
            Connection::Unix(stream) => stream.flush().await.context("Unix flush failed"),
            Connection::Tcp(stream) => stream.flush().await.context("TCP flush failed"),
        }
    }
}

/// IPC client for connecting to the Smith service (legacy)
pub struct IpcClient {
    connection: Arc<Mutex<Connection>>,
}

/// Smith service client with both TCP and Unix socket support
pub struct SmithClient {
    command_sender: mpsc::Sender<Command>,
    event_receiver: Arc<RwLock<Option<mpsc::Receiver<Event>>>>,
}

impl IpcClient {
    /// Connect to IPC server at socket path
    pub async fn connect<P: AsRef<Path>>(socket_path: P) -> Result<Self> {
        let stream = UnixStream::connect(&socket_path)
            .await
            .context("Failed to connect to Unix socket")?;

        info!("Connected to IPC server at {:?}", socket_path.as_ref());

        Ok(Self {
            connection: Arc::new(Mutex::new(Connection::Unix(stream))),
        })
    }

    /// Send command to server
    pub async fn send_command(&mut self, command: &Command) -> Result<()> {
        let json = serde_json::to_string(command).context("Failed to serialize command")?;

        let mut connection = self.connection.lock().await;
        connection
            .write_all(json.as_bytes())
            .await
            .context("Failed to write command")?;
        connection
            .write_all(b"\n")
            .await
            .context("Failed to write newline")?;
        connection
            .flush()
            .await
            .context("Failed to flush connection")?;

        debug!("Sent command: {}", json);
        Ok(())
    }

    /// Process events from server
    pub async fn process_events<F, Fut>(self, mut _handler: F) -> Result<()>
    where
        F: FnMut(Event) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        // This is a simplified implementation - would need proper stream splitting in production
        info!("IPC connection processing started");
        Ok(())
    }
}

impl SmithClient {
    /// Connect to Smith service via TCP
    pub async fn connect_tcp(address: &str) -> Result<Self> {
        let stream = TcpStream::connect(address)
            .await
            .context("Failed to connect to TCP address")?;

        info!("Connected to Smith service at {}", address);
        Self::from_connection(Connection::Tcp(stream)).await
    }

    /// Connect to Smith service via Unix socket
    pub async fn connect_unix<P: AsRef<Path>>(socket_path: P) -> Result<Self> {
        let stream = UnixStream::connect(&socket_path)
            .await
            .context("Failed to connect to Unix socket")?;

        info!("Connected to Smith service at {:?}", socket_path.as_ref());
        Self::from_connection(Connection::Unix(stream)).await
    }

    /// Create client from existing connection
    async fn from_connection(connection: Connection) -> Result<Self> {
        let (command_tx, mut command_rx) = mpsc::channel::<Command>(1000);
        let (_event_tx, event_rx) = mpsc::channel::<Event>(10000);

        // Start command sending task
        let connection = Arc::new(Mutex::new(connection));
        let connection_for_commands = Arc::clone(&connection);

        tokio::spawn(async move {
            while let Some(command) = command_rx.recv().await {
                let json = match serde_json::to_string(&command) {
                    Ok(json) => json,
                    Err(err) => {
                        error!("Failed to serialize command: {}", err);
                        continue;
                    }
                };

                let mut conn = connection_for_commands.lock().await;
                if let Err(err) = conn.write_all(json.as_bytes()).await {
                    error!("Failed to send command: {}", err);
                    break;
                }
                if let Err(err) = conn.write_all(b"\n").await {
                    error!("Failed to send newline: {}", err);
                    break;
                }
                if let Err(err) = conn.flush().await {
                    error!("Failed to flush connection: {}", err);
                    break;
                }

                debug!("Sent command: {}", json);
            }
        });

        // Start event receiving task - simplified for now
        // In a full implementation, you'd split the connection and read from it
        tokio::spawn(async move {
            // This is where event reading would happen
            // For now, we'll just keep the channel alive
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                // In real implementation, read events from connection and send to event_tx
            }
        });

        Ok(Self {
            command_sender: command_tx,
            event_receiver: Arc::new(RwLock::new(Some(event_rx))),
        })
    }

    /// Send command to Smith service
    pub async fn send_command(&self, command: Command) -> Result<()> {
        self.command_sender
            .send(command)
            .await
            .context("Failed to send command - connection may be closed")?;
        Ok(())
    }

    /// Receive events from Smith service
    pub async fn receive_events(&self) -> Result<Vec<Event>> {
        let mut events = Vec::new();

        // Try to get events without blocking
        if let Some(ref mut receiver) = self.event_receiver.write().await.as_mut() {
            while let Ok(event) = receiver.try_recv() {
                events.push(event);
            }
        }

        Ok(events)
    }

    /// Get single event (blocking)
    pub async fn receive_event(&self) -> Result<Event> {
        if let Some(ref mut receiver) = self.event_receiver.write().await.as_mut() {
            receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("Event channel closed"))
        } else {
            Err(anyhow::anyhow!("Event receiver not available"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use tokio::net::TcpListener;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_connection_write_and_flush() {
        // Test Unix connection write operations
        let (client_stream, _server_stream) = tokio::net::UnixStream::pair().unwrap();
        let mut connection = Connection::Unix(client_stream);

        let test_data = b"test data";
        assert!(connection.write_all(test_data).await.is_ok());
        assert!(connection.flush().await.is_ok());
    }

    #[tokio::test]
    async fn test_tcp_connection_write_and_flush() {
        // Create TCP listener for testing
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Connect to our test server
        let tcp_stream = TcpStream::connect(addr).await.unwrap();
        let mut connection = Connection::Tcp(tcp_stream);

        let test_data = b"tcp test data";
        assert!(connection.write_all(test_data).await.is_ok());
        assert!(connection.flush().await.is_ok());
    }

    #[tokio::test]
    async fn test_ipc_client_connection() {
        // Create temporary Unix socket path
        let socket_path = format!("/tmp/smith_test_{}.sock", Uuid::new_v4());

        // Create Unix listener
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        // Test connecting to the socket
        tokio::spawn(async move {
            // Accept connection in background
            let _stream = listener.accept().await;
        });

        let client = IpcClient::connect(&socket_path).await;
        assert!(client.is_ok());

        // Cleanup
        std::fs::remove_file(&socket_path).ok();
    }

    #[tokio::test]
    async fn test_ipc_client_send_command() {
        // Create Unix socket pair for testing
        let (client_stream, _server_stream) = tokio::net::UnixStream::pair().unwrap();
        let mut client = IpcClient {
            connection: Arc::new(Mutex::new(Connection::Unix(client_stream))),
        };

        let command = Command::Handshake {
            version: 1,
            capabilities: vec!["shell_exec".to_string(), "nats".to_string()],
        };

        let result = client.send_command(&command).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ipc_client_process_events() {
        let (client_stream, _server_stream) = tokio::net::UnixStream::pair().unwrap();
        let client = IpcClient {
            connection: Arc::new(Mutex::new(Connection::Unix(client_stream))),
        };

        // Test event processing with simple handler
        let handler = |_event: Event| async { Ok(()) };

        let result = client.process_events(handler).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_smith_client_tcp_connection() {
        // Create TCP listener for testing
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept connection in background
        tokio::spawn(async move {
            let _accepted = listener.accept().await;
        });

        let client = SmithClient::connect_tcp(&addr.to_string()).await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_smith_client_unix_connection() {
        let socket_path = format!("/tmp/smith_test_unix_{}.sock", Uuid::new_v4());

        // Create Unix listener
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            let _accepted = listener.accept().await;
        });

        let client = SmithClient::connect_unix(&socket_path).await;
        assert!(client.is_ok());

        // Cleanup
        std::fs::remove_file(&socket_path).ok();
    }

    #[tokio::test]
    async fn test_smith_client_send_command() {
        let (client_stream, _server_stream) = tokio::net::UnixStream::pair().unwrap();
        let client = SmithClient::from_connection(Connection::Unix(client_stream))
            .await
            .unwrap();

        let command = Command::ToolCall {
            request_id: Uuid::new_v4(),
            tool: "test_tool".to_string(),
            args: json!({"param": "value"}),
            timeout_ms: Some(5000),
        };

        let result = client.send_command(command).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_smith_client_receive_events() {
        let (client_stream, _server_stream) = tokio::net::UnixStream::pair().unwrap();
        let client = SmithClient::from_connection(Connection::Unix(client_stream))
            .await
            .unwrap();

        // Test receiving events (should return empty vector since no events are sent)
        let events = client.receive_events().await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_smith_client_receive_single_event_with_closed_receiver() {
        let (client_stream, _server_stream) = tokio::net::UnixStream::pair().unwrap();
        let client = SmithClient::from_connection(Connection::Unix(client_stream))
            .await
            .unwrap();

        // Drop the receiver to test the error path
        {
            let mut receiver_guard = client.event_receiver.write().await;
            *receiver_guard = None;
        }

        // Now trying to receive should return an error
        let result = client.receive_event().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Event receiver not available"));
    }

    #[tokio::test]
    async fn test_command_variants() {
        // Test all command variants can be serialized
        let commands = vec![
            Command::Handshake {
                version: 1,
                capabilities: vec!["test".to_string()],
            },
            Command::Plan {
                request_id: Uuid::new_v4(),
                goal: "test goal".to_string(),
                context: HashMap::new(),
            },
            Command::ToolCall {
                request_id: Uuid::new_v4(),
                tool: "test_tool".to_string(),
                args: json!({"key": "value"}),
                timeout_ms: Some(1000),
            },
            Command::HookLoad {
                request_id: Uuid::new_v4(),
                hook_type: "js".to_string(),
                script: "console.log('test');".to_string(),
            },
            Command::ShellExec {
                request_id: Uuid::new_v4(),
                command: "echo test".to_string(),
                shell: Some("bash".to_string()),
                cwd: Some("/tmp".to_string()),
                env: HashMap::new(),
                timeout_ms: Some(5000),
            },
            Command::Shutdown,
        ];

        for command in commands {
            let json = serde_json::to_string(&command).unwrap();
            let deserialized: Command = serde_json::from_str(&json).unwrap();

            // Verify serialization roundtrip works
            match (command, deserialized) {
                (
                    Command::Handshake { version: v1, .. },
                    Command::Handshake { version: v2, .. },
                ) => {
                    assert_eq!(v1, v2);
                }
                (Command::Plan { goal: g1, .. }, Command::Plan { goal: g2, .. }) => {
                    assert_eq!(g1, g2);
                }
                (Command::ToolCall { tool: t1, .. }, Command::ToolCall { tool: t2, .. }) => {
                    assert_eq!(t1, t2);
                }
                (
                    Command::HookLoad { hook_type: h1, .. },
                    Command::HookLoad { hook_type: h2, .. },
                ) => {
                    assert_eq!(h1, h2);
                }
                (
                    Command::ShellExec { command: c1, .. },
                    Command::ShellExec { command: c2, .. },
                ) => {
                    assert_eq!(c1, c2);
                }
                (Command::Shutdown, Command::Shutdown) => {}
                _ => panic!("Mismatched command variants after serialization"),
            }
        }
    }

    #[tokio::test]
    async fn test_connection_tcp_error_handling() {
        // Test TCP connection with invalid address
        let result = SmithClient::connect_tcp("invalid.host:999999").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connection_unix_error_handling() {
        // Test Unix connection with non-existent socket
        let non_existent_path = "/tmp/non_existent_socket.sock";
        let result = SmithClient::connect_unix(non_existent_path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connection_error_contexts() {
        // Test that connection errors have proper context messages
        let result = SmithClient::connect_tcp("0.0.0.0:1").await; // Port 1 should be unavailable
        match result {
            Err(err) => {
                let err_msg = format!("{}", err);
                assert!(err_msg.contains("Failed to connect to TCP address"));
            }
            Ok(_) => panic!("Expected connection to fail"),
        }
    }

    #[tokio::test]
    async fn test_ipc_client_connect_error() {
        // Test IPC client connection with non-existent socket
        let non_existent_path = "/tmp/non_existent_ipc.sock";
        let result = IpcClient::connect(non_existent_path).await;
        assert!(result.is_err());

        // Verify error context
        match result {
            Err(err) => {
                let err_msg = format!("{}", err);
                assert!(err_msg.contains("Failed to connect to Unix socket"));
            }
            Ok(_) => panic!("Expected connection to fail"),
        }
    }

    #[tokio::test]
    async fn test_smith_client_from_connection_task_spawning() {
        // Test that background tasks are properly spawned
        let (client_stream, _server_stream) = tokio::net::UnixStream::pair().unwrap();
        let client_result = SmithClient::from_connection(Connection::Unix(client_stream)).await;

        assert!(client_result.is_ok());
        let client = client_result.unwrap();

        // Verify client can send commands (which means background task is running)
        let command = Command::Shutdown;
        let send_result = client.send_command(command).await;
        assert!(send_result.is_ok());
    }

    #[tokio::test]
    async fn test_command_serialization_edge_cases() {
        // Test commands with optional fields and edge cases
        let mut context = HashMap::new();
        context.insert("key1".to_string(), "value1".to_string());
        context.insert("key2".to_string(), "value2".to_string());

        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());

        let shell_exec = Command::ShellExec {
            request_id: Uuid::new_v4(),
            command: "ls -la".to_string(),
            shell: None, // Test None case
            cwd: None,   // Test None case
            env,
            timeout_ms: None, // Test None case
        };

        let json = serde_json::to_string(&shell_exec).unwrap();
        let deserialized: Command = serde_json::from_str(&json).unwrap();

        match deserialized {
            Command::ShellExec {
                shell,
                cwd,
                timeout_ms,
                ..
            } => {
                assert_eq!(shell, None);
                assert_eq!(cwd, None);
                assert_eq!(timeout_ms, None);
            }
            _ => panic!("Expected ShellExec command"),
        }
    }

    #[tokio::test]
    async fn test_concurrent_command_sending() {
        // Test that multiple commands can be sent concurrently
        let (client_stream, _server_stream) = tokio::net::UnixStream::pair().unwrap();
        let client = Arc::new(
            SmithClient::from_connection(Connection::Unix(client_stream))
                .await
                .unwrap(),
        );

        let mut handles = vec![];

        for i in 0..10 {
            let client_clone = Arc::clone(&client);
            let handle = tokio::spawn(async move {
                let command = Command::Plan {
                    request_id: Uuid::new_v4(),
                    goal: format!("test goal {}", i),
                    context: HashMap::new(),
                };
                client_clone.send_command(command).await
            });
            handles.push(handle);
        }

        // Wait for all commands to be sent
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }
    }
}
