//! Firecracker Guest Agent
//!
//! This is a minimal agent that runs inside a Firecracker microVM.
//! It listens on vsock port 5000 and executes commands sent by the host.
//!
//! Protocol:
//! - Request: JSON object with `command`, `args`, `cwd`, `env`
//! - Response: JSON object with `exit_code`, `stdout`, `stderr`
//!
//! Build as a static binary:
//! ```sh
//! cargo build --release --bin fc-guest-agent --target x86_64-unknown-linux-musl
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

/// Vsock port to listen on
const VSOCK_PORT: u32 = 5000;
/// Vsock CID for host
const VMADDR_CID_HOST: u32 = 2;
/// Vsock CID for any
const VMADDR_CID_ANY: u32 = u32::MAX;

/// Socket address family for vsock
const AF_VSOCK: i32 = 40;
/// Socket type for stream
const SOCK_STREAM: i32 = 1;

/// Vsock socket address structure
#[repr(C)]
struct SockaddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

/// Command request from host
#[derive(Debug, Deserialize)]
struct ExecRequest {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    stdin: Option<String>,
}

/// Command response to host
#[derive(Debug, Serialize)]
struct ExecResponse {
    exit_code: i32,
    #[serde(with = "base64_serde")]
    stdout: Vec<u8>,
    #[serde(with = "base64_serde")]
    stderr: Vec<u8>,
    error: Option<String>,
}

mod base64_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64_encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64_decode(&s).map_err(serde::de::Error::custom)
    }

    fn base64_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::with_capacity((data.len() + 2) / 3 * 4);

        for chunk in data.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
            let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

            result.push(ALPHABET[b0 >> 2] as char);
            result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

            if chunk.len() > 1 {
                result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
            } else {
                result.push('=');
            }

            if chunk.len() > 2 {
                result.push(ALPHABET[b2 & 0x3f] as char);
            } else {
                result.push('=');
            }
        }

        result
    }

    fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
        const DECODE: [i8; 128] = [
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62,
            -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
        ];

        let s = s.trim_end_matches('=');
        let mut result = Vec::with_capacity(s.len() * 3 / 4);

        let bytes: Vec<u8> = s.bytes().collect();
        for chunk in bytes.chunks(4) {
            if chunk.len() < 2 {
                break;
            }

            let b0 = DECODE.get(chunk[0] as usize).copied().unwrap_or(-1);
            let b1 = DECODE.get(chunk[1] as usize).copied().unwrap_or(-1);
            let b2 = chunk
                .get(2)
                .and_then(|&c| DECODE.get(c as usize).copied())
                .unwrap_or(0);
            let b3 = chunk
                .get(3)
                .and_then(|&c| DECODE.get(c as usize).copied())
                .unwrap_or(0);

            if b0 < 0 || b1 < 0 {
                return Err("Invalid base64".to_string());
            }

            result.push(((b0 << 2) | (b1 >> 4)) as u8);
            if chunk.len() > 2 && b2 >= 0 {
                result.push((((b1 & 0x0f) << 4) | (b2 >> 2)) as u8);
            }
            if chunk.len() > 3 && b3 >= 0 {
                result.push((((b2 & 0x03) << 6) | b3) as u8);
            }
        }

        Ok(result)
    }
}

/// Create a vsock listener socket
fn create_vsock_listener(port: u32) -> std::io::Result<i32> {
    unsafe {
        // Create socket
        let fd = libc::socket(AF_VSOCK, SOCK_STREAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Bind to address
        let addr = SockaddrVm {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: VMADDR_CID_ANY,
            svm_zero: [0; 4],
        };

        let result = libc::bind(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
        );
        if result < 0 {
            libc::close(fd);
            return Err(std::io::Error::last_os_error());
        }

        // Listen
        let result = libc::listen(fd, 16);
        if result < 0 {
            libc::close(fd);
            return Err(std::io::Error::last_os_error());
        }

        Ok(fd)
    }
}

/// Accept a connection on the vsock listener
fn vsock_accept(listener_fd: i32) -> std::io::Result<i32> {
    unsafe {
        let mut addr = SockaddrVm {
            svm_family: 0,
            svm_reserved1: 0,
            svm_port: 0,
            svm_cid: 0,
            svm_zero: [0; 4],
        };
        let mut addr_len = std::mem::size_of::<SockaddrVm>() as libc::socklen_t;

        let fd = libc::accept(
            listener_fd,
            &mut addr as *mut SockaddrVm as *mut libc::sockaddr,
            &mut addr_len,
        );

        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(fd)
        }
    }
}

/// Execute a command and return the result
fn execute_command(req: &ExecRequest) -> ExecResponse {
    let mut cmd = Command::new(&req.command);

    cmd.args(&req.args);

    if let Some(ref cwd) = req.cwd {
        cmd.current_dir(cwd);
    }

    for (key, value) in &req.env {
        cmd.env(key, value);
    }

    cmd.stdin(if req.stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    match cmd.spawn() {
        Ok(mut child) => {
            // Write stdin if provided
            if let Some(ref stdin_data) = req.stdin {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(stdin_data.as_bytes());
                }
            }

            // Wait for completion and collect output
            match child.wait_with_output() {
                Ok(output) => ExecResponse {
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: output.stdout,
                    stderr: output.stderr,
                    error: None,
                },
                Err(e) => ExecResponse {
                    exit_code: -1,
                    stdout: vec![],
                    stderr: vec![],
                    error: Some(format!("Failed to wait for process: {}", e)),
                },
            }
        }
        Err(e) => ExecResponse {
            exit_code: -1,
            stdout: vec![],
            stderr: vec![],
            error: Some(format!("Failed to spawn process: {}", e)),
        },
    }
}

/// Handle a single client connection
fn handle_client(fd: i32) {
    // Wrap the fd in a safe UnixStream for easier I/O
    // This is a bit of a hack since vsock isn't actually a Unix socket,
    // but the fd interface is compatible
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;

    // Read requests line by line (newline-delimited JSON)
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                // Parse request
                let response = match serde_json::from_str::<ExecRequest>(line) {
                    Ok(req) => execute_command(&req),
                    Err(e) => ExecResponse {
                        exit_code: -1,
                        stdout: vec![],
                        stderr: vec![],
                        error: Some(format!("Invalid request: {}", e)),
                    },
                };

                // Send response
                let response_json = serde_json::to_string(&response).unwrap_or_else(|_| {
                    r#"{"exit_code":-1,"stdout":"","stderr":"","error":"Serialization failed"}"#
                        .to_string()
                });

                if writeln!(writer, "{}", response_json).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// Mount essential filesystems for a minimal Linux environment
fn setup_filesystems() {
    use std::ffi::CString;

    // These are the essential pseudo-filesystems needed for a working Linux environment
    let mounts = [
        ("/proc", "proc", "proc"),
        ("/sys", "sysfs", "sysfs"),
        ("/dev", "devtmpfs", "devtmpfs"),
        ("/dev/pts", "devpts", "devpts"),
        ("/tmp", "tmpfs", "tmpfs"),
        ("/run", "tmpfs", "tmpfs"),
    ];

    for (target, fstype, source) in mounts {
        // Create mount point if it doesn't exist
        let _ = std::fs::create_dir_all(target);

        let target_c = CString::new(target).unwrap();
        let fstype_c = CString::new(fstype).unwrap();
        let source_c = CString::new(source).unwrap();

        unsafe {
            let result = libc::mount(
                source_c.as_ptr(),
                target_c.as_ptr(),
                fstype_c.as_ptr(),
                0,
                std::ptr::null(),
            );
            if result != 0 {
                eprintln!(
                    "Warning: Failed to mount {} on {}: {}",
                    source,
                    target,
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}

/// Set hostname
fn set_hostname(name: &str) {
    use std::ffi::CString;
    let name_c = CString::new(name).unwrap();
    unsafe {
        libc::sethostname(name_c.as_ptr(), name.len());
    }
}

fn main() {
    eprintln!("fc-guest-agent: Starting...");

    // If we're running as PID 1 (init), set up the environment
    if std::process::id() == 1 {
        eprintln!("fc-guest-agent: Running as init (PID 1), setting up filesystems...");
        setup_filesystems();
        set_hostname("agentd-vm");
    }

    // Create vsock listener
    let listener_fd = match create_vsock_listener(VSOCK_PORT) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("fc-guest-agent: Failed to create vsock listener: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("fc-guest-agent: Listening on vsock port {}", VSOCK_PORT);

    // Accept connections in a loop
    loop {
        match vsock_accept(listener_fd) {
            Ok(client_fd) => {
                eprintln!("fc-guest-agent: Accepted connection");
                // Handle in same thread (simple single-threaded design)
                // For higher performance, could spawn threads
                handle_client(client_fd);
                eprintln!("fc-guest-agent: Connection closed");
            }
            Err(e) => {
                eprintln!("fc-guest-agent: Accept error: {}", e);
            }
        }
    }
}
