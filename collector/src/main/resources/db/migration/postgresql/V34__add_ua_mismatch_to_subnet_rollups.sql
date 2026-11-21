-- Version 34: Add ua_mismatch_requests to client_subnet_rollups
ALTER TABLE client_subnet_rollups ADD COLUMN ua_mismatch_requests BIGINT NOT NULL DEFAULT 0;
