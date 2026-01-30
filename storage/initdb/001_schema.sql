-- SOC Lab - ClickHouse schema

-- NOTE:
-- The official ClickHouse docker entrypoint creates CLICKHOUSE_DB/CLICKHOUSE_USER from env vars.
-- This init script should only create schema objects inside the DB (no CREATE USER / GRANT).

USE soc;

-- Required for ClickHouse 24.8 JSON type
SET allow_experimental_json_type = 1;
SET allow_experimental_object_type = 1;

CREATE TABLE IF NOT EXISTS raw_logs
(
  timestamp DateTime,
  project String,
  cluster LowCardinality(String),
  namespace LowCardinality(String),
  pod LowCardinality(String),
  service LowCardinality(String),
  severity LowCardinality(String),
  user String,
  method LowCardinality(String),
  ip String,
  resource String,
  payload JSON
)
ENGINE = MergeTree
PARTITION BY toDate(timestamp)
ORDER BY (timestamp, project, cluster, namespace, service)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS normalized_logs
(
  timestamp DateTime,
  project String,
  cluster LowCardinality(String),
  namespace LowCardinality(String),
  pod LowCardinality(String),
  service LowCardinality(String),
  severity LowCardinality(String),
  severity_num UInt8,
  identity String,
  method LowCardinality(String),
  ip String,
  resource String,
  request_id String,
  message String DEFAULT '',
  status_code Int32 DEFAULT 0,
  is_success UInt8 DEFAULT 0,
  error_signature String DEFAULT '',
  payload JSON
)
ENGINE = MergeTree
PARTITION BY toDate(timestamp)
ORDER BY (timestamp, project, cluster, namespace, service)
TTL timestamp + INTERVAL 45 DAY;

CREATE TABLE IF NOT EXISTS enriched_logs
(
  timestamp DateTime,
  project String,
  cluster LowCardinality(String),
  namespace LowCardinality(String),
  pod LowCardinality(String),
  service LowCardinality(String),
  severity LowCardinality(String),
  severity_num UInt8,
  identity String,
  method LowCardinality(String),
  ip String,
  resource String,
  request_id String,
  message String DEFAULT '',
  status_code Int32 DEFAULT 0,
  is_success UInt8 DEFAULT 0,
  error_signature String DEFAULT '',

  -- enrichment
  ip_is_public UInt8,
  geo_country LowCardinality(String),
  geo_region LowCardinality(String),
  geo_city LowCardinality(String),
  asn UInt32,
  as_org String,
  iam_roles Array(String),
  owner_team LowCardinality(String),
  threat_tags Array(String),
  baseline_error_rate Float64,

  payload JSON
)
ENGINE = MergeTree
PARTITION BY toDate(timestamp)
ORDER BY (timestamp, project, cluster, namespace, service)
TTL timestamp + INTERVAL 60 DAY;

CREATE TABLE IF NOT EXISTS features
(
  window_start DateTime,
  window_end DateTime,
  project String,
  cluster LowCardinality(String),
  namespace LowCardinality(String),
  service LowCardinality(String),

  total_logs UInt64,
  error_rate Float64,
  iam_change_count UInt64,
  failed_logins UInt64,
  privilege_escalations UInt64,
  new_service_accounts UInt64,
  api_abuse_rate Float64,
  ip_entropy Float64,
  pod_restart_rate Float64,
  container_escape_signals UInt64
)
ENGINE = MergeTree
PARTITION BY toDate(window_start)
ORDER BY (window_start, project, cluster, namespace, service)
TTL window_start + INTERVAL 180 DAY;

CREATE TABLE IF NOT EXISTS anomalies
(
  created_at DateTime DEFAULT now(),
  window DateTime,
  project String,
  cluster LowCardinality(String),
  namespace LowCardinality(String),
  service LowCardinality(String),
  score Float64,
  confidence Float64,
  model LowCardinality(String),
  risk_level LowCardinality(String),
  reason String,
  llm_summary String
)
ENGINE = MergeTree
PARTITION BY toDate(window)
ORDER BY (window, project, cluster, namespace, service, model)
TTL window + INTERVAL 365 DAY;

-- High-signal anomaly "signals" emitted by the anomaly detector.
-- Stored as structured JSON payloads for flexible querying / dashboarding.
CREATE TABLE IF NOT EXISTS anomaly_signals
(
  created_at DateTime DEFAULT now(),
  window_start DateTime,
  window_end DateTime,
  project String,
  cluster LowCardinality(String),
  namespace LowCardinality(String),
  service LowCardinality(String),
  signal_type LowCardinality(String),
  severity LowCardinality(String),
  pod LowCardinality(String),
  data JSON
)
ENGINE = MergeTree
PARTITION BY toDate(window_start)
ORDER BY (window_start, project, cluster, namespace, service, signal_type, pod)
TTL window_start + INTERVAL 365 DAY;

CREATE TABLE IF NOT EXISTS rule_matches
(
  created_at DateTime DEFAULT now(),
  window DateTime,
  project String,
  cluster LowCardinality(String),
  namespace LowCardinality(String),
  service LowCardinality(String),
  identity String,
  rule_id LowCardinality(String),
  rule_name String,
  severity LowCardinality(String),
  description String,
  evidence JSON
)
ENGINE = MergeTree
PARTITION BY toDate(window)
ORDER BY (window, project, cluster, namespace, service, identity, rule_id)
TTL window + INTERVAL 365 DAY;

CREATE TABLE IF NOT EXISTS alerts
(
  id UUID DEFAULT generateUUIDv4(),
  created_at DateTime DEFAULT now(),
  fingerprint String,
  channel LowCardinality(String),
  risk_level LowCardinality(String),
  title String,
  message String,
  payload JSON,
  sent UInt8 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toDate(created_at)
ORDER BY (created_at, fingerprint)
TTL created_at + INTERVAL 365 DAY;

-- Materialized view: 5-minute error rate per service from normalized logs.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_error_rate_5m
ENGINE = SummingMergeTree
PARTITION BY toDate(window_start)
ORDER BY (window_start, project, cluster, namespace, service)
AS
SELECT
  toStartOfFiveMinute(timestamp) AS window_start,
  toStartOfFiveMinute(timestamp) + INTERVAL 5 MINUTE AS window_end,
  project,
  cluster,
  namespace,
  service,
  count() AS total_logs,
  sum(severity_num >= 40) AS error_logs
FROM normalized_logs
GROUP BY window_start, window_end, project, cluster, namespace, service;

CREATE VIEW IF NOT EXISTS v_latest_anomalies AS
SELECT *
FROM anomalies
ORDER BY created_at DESC
LIMIT 500;

