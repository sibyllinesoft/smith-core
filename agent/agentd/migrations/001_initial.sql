-- Initial database schema for Smith Executor
-- Creates tables for idempotency tracking and replay protection

-- Table for tracking intent execution runs
CREATE TABLE IF NOT EXISTS runs (
    intent_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    runner_digest TEXT NOT NULL,
    capability_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'ok', 'denied', 'error', 'expired')),
    result BLOB,                    -- Serialized IntentResult (NULL for running)
    started_ms INTEGER NOT NULL,    -- Unix timestamp in milliseconds
    ended_ms INTEGER,               -- Unix timestamp in milliseconds (NULL for running)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (intent_id, seq, runner_digest, capability_digest)
);

-- Table for replay protection (nonce tracking)
CREATE TABLE IF NOT EXISTS replays (
    nonce TEXT PRIMARY KEY,         -- 128-bit hex nonce string
    ts_ms INTEGER NOT NULL,         -- Unix timestamp when nonce was first seen
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_runs_started_ms ON runs (started_ms);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs (status);
CREATE INDEX IF NOT EXISTS idx_replays_ts_ms ON replays (ts_ms);