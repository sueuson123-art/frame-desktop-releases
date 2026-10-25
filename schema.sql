CREATE TABLE IF NOT EXISTS licenses(id TEXT PRIMARY KEY,email TEXT NOT NULL,code_hash TEXT NOT NULL UNIQUE,expires_at INTEGER NOT NULL,seats INTEGER NOT NULL CHECK(seats BETWEEN 1 AND 10),status TEXT NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS activations(license_id TEXT NOT NULL REFERENCES licenses(id),device_id TEXT NOT NULL,refresh_hash TEXT NOT NULL UNIQUE,updated_at INTEGER NOT NULL,PRIMARY KEY(license_id,device_id));
CREATE INDEX IF NOT EXISTS activation_lookup ON activations(device_id,refresh_hash);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rate_limits(key TEXT PRIMARY KEY,bucket INTEGER NOT NULL,count INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS rate_limits_expiry ON rate_limits(bucket);
