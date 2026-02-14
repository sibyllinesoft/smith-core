use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};

/// Utility functions for the executor

/// Get current timestamp in milliseconds since Unix epoch
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Generate secure random bytes
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Hex encode bytes
pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Hex decode string
pub fn hex_decode(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str).map_err(|e| anyhow::anyhow!("Hex decode error: {}", e))
}

/// Calculate SHA256 hash
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Format bytes as human readable size
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: u64 = 1024;

    if bytes < THRESHOLD {
        return format!("{} B", bytes);
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD as f64;
        unit_index += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_index])
}

/// Format duration as human readable string
pub fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        format!("{:.1}m", ms as f64 / 60_000.0)
    } else {
        format!("{:.1}h", ms as f64 / 3_600_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_generation() {
        let ts1 = current_timestamp_ms();
        let ts2 = current_timestamp_ms();
        assert!(ts2 >= ts1, "Timestamps should be non-decreasing");
    }

    #[test]
    fn test_timestamp_is_reasonable() {
        let ts = current_timestamp_ms();
        // Should be after Jan 1, 2024 (1704067200000 ms)
        assert!(ts > 1704067200000, "Timestamp should be after 2024");
        // Should be before year 2100 (4102444800000 ms)
        assert!(ts < 4102444800000, "Timestamp should be before 2100");
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = generate_random_bytes(16);
        let bytes2 = generate_random_bytes(16);

        assert_eq!(bytes1.len(), 16);
        assert_eq!(bytes2.len(), 16);
        assert_ne!(bytes1, bytes2, "Random bytes should be different");
    }

    #[test]
    fn test_random_bytes_zero_length() {
        let bytes = generate_random_bytes(0);
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_random_bytes_large() {
        let bytes = generate_random_bytes(1024);
        assert_eq!(bytes.len(), 1024);
    }

    #[test]
    fn test_random_bytes_various_sizes() {
        for size in [1, 8, 32, 64, 128, 256] {
            let bytes = generate_random_bytes(size);
            assert_eq!(bytes.len(), size);
        }
    }

    #[test]
    fn test_hex_encoding() {
        let data = b"hello world";
        let encoded = hex_encode(data);
        let decoded = hex_decode(&encoded).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_encode_empty() {
        let encoded = hex_encode(&[]);
        assert!(encoded.is_empty());
    }

    #[test]
    fn test_hex_encode_single_byte() {
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0x0a]), "0a");
    }

    #[test]
    fn test_hex_encode_known_values() {
        assert_eq!(hex_encode(b"ABC"), "414243");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn test_hex_decode_empty() {
        let decoded = hex_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_hex_decode_known_values() {
        assert_eq!(hex_decode("414243").unwrap(), b"ABC");
        assert_eq!(
            hex_decode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn test_hex_decode_uppercase() {
        // Should handle uppercase hex
        assert_eq!(
            hex_decode("DEADBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn test_hex_decode_invalid_char() {
        let result = hex_decode("xyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_decode_odd_length() {
        let result = hex_decode("abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash1 = sha256_hash(data);
        let hash2 = sha256_hash(data);

        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert_eq!(hash1.len(), 32, "SHA256 should be 32 bytes");
    }

    #[test]
    fn test_sha256_hash_empty() {
        let hash = sha256_hash(&[]);
        // SHA256 of empty string is known
        let expected =
            hex_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_hash_known_value() {
        // SHA256 of "hello" is known
        let hash = sha256_hash(b"hello");
        let hex_hash = hex_encode(&hash);
        assert_eq!(
            hex_hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_hash_different_inputs() {
        let hash1 = sha256_hash(b"hello");
        let hash2 = sha256_hash(b"world");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
    }

    #[test]
    fn test_format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn test_format_bytes_edge_cases() {
        // Just under 1KB
        assert_eq!(format_bytes(1023), "1023 B");
        // Just over 1KB
        assert_eq!(format_bytes(1025), "1.0 KB");
    }

    #[test]
    fn test_format_bytes_terabytes() {
        let tb = 1024u64 * 1024 * 1024 * 1024;
        assert_eq!(format_bytes(tb), "1.0 TB");
    }

    #[test]
    fn test_format_bytes_large() {
        let large = 10u64 * 1024 * 1024 * 1024 * 1024; // 10 TB
        assert_eq!(format_bytes(large), "10.0 TB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration_ms(500), "500ms");
        assert_eq!(format_duration_ms(1500), "1.5s");
        assert_eq!(format_duration_ms(90000), "1.5m");
        assert_eq!(format_duration_ms(7200000), "2.0h");
    }

    #[test]
    fn test_format_duration_zero() {
        assert_eq!(format_duration_ms(0), "0ms");
    }

    #[test]
    fn test_format_duration_edge_cases() {
        // Just under 1 second
        assert_eq!(format_duration_ms(999), "999ms");
        // Exactly 1 second
        assert_eq!(format_duration_ms(1000), "1.0s");
        // Just under 1 minute
        assert_eq!(format_duration_ms(59999), "60.0s");
        // Exactly 1 minute
        assert_eq!(format_duration_ms(60000), "1.0m");
        // Just under 1 hour
        assert_eq!(format_duration_ms(3599999), "60.0m");
        // Exactly 1 hour
        assert_eq!(format_duration_ms(3600000), "1.0h");
    }

    #[test]
    fn test_format_duration_large() {
        // 24 hours
        assert_eq!(format_duration_ms(24 * 3600000), "24.0h");
    }

    #[test]
    fn test_hex_roundtrip_random() {
        let original = generate_random_bytes(64);
        let encoded = hex_encode(&original);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
