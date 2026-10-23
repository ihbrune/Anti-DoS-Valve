-- 1. Rename table blocked_client_events to client_events
ALTER TABLE IF EXISTS blocked_client_events RENAME TO client_events;

-- 2. Add status column to client_events (defaults to 'BLOCKED' for all historical rows)
ALTER TABLE client_events ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'BLOCKED';

-- 3. Create composite index on status and slot_time for fast filtering of blocked vs active events
CREATE INDEX IF NOT EXISTS idx_events_status_time ON client_events(status, slot_time);
