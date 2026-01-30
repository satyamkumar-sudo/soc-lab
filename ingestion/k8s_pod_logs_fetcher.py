from __future__ import annotations

import datetime as dt
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any

import structlog
from kubernetes import client, config

from ingestion.k8s_inventory import _pod_service_name

log = structlog.get_logger(__name__)


_RFC3339_PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(.*)$")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_HTTP_STATUS_PATTERN = re.compile(r"\b(status[=:]?\s*|code[=:]?\s*|http[_\s]?status[=:]?\s*)(\d{3})\b", re.I)
_LOG_LEVEL_PATTERN = re.compile(r"\b(FATAL|ERROR|ERR|WARN|WARNING|INFO|DEBUG|TRACE)\b", re.I)


@dataclass(frozen=True)
class K8sPodLogFetchConfig:
    kubeconfig: str
    project: str
    cluster: str
    service_allowlist: tuple[str, ...]
    # Defaults tuned for "live" ingestion every 5 minutes (keep it light/fast).
    max_pods: int = 25
    max_lines_per_pod: int = 200
    qps: float = 2.0
    limit_bytes_per_pod: int = 65536

    @staticmethod
    def from_env() -> "K8sPodLogFetchConfig":
        allow = tuple(s.strip().lower() for s in os.environ.get("SOC_SERVICE_ALLOWLIST", "").split(",") if s.strip())
        project = os.environ.get("SOC_GCP_PROJECT", "").strip() or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        cluster = os.environ.get("GKE_CLUSTER_NAME", "").strip() or os.environ.get("AKS_CLUSTER_NAME", "").strip()
        return K8sPodLogFetchConfig(
            kubeconfig=os.environ.get("KUBECONFIG", "/kube/config"),
            project=project,
            cluster=cluster,
            service_allowlist=allow,
            max_pods=int(os.environ.get("SOC_K8S_MAX_PODS", "25")),
            max_lines_per_pod=int(os.environ.get("SOC_K8S_MAX_LINES_PER_POD", "200")),
            qps=float(os.environ.get("SOC_K8S_QPS", "2.0")),
            limit_bytes_per_pod=int(os.environ.get("SOC_K8S_LIMIT_BYTES_PER_POD", "65536")),
        )


class TokenBucket:
    def __init__(self, rate_per_s: float, burst: float | None = None) -> None:
        self.rate = max(rate_per_s, 0.1)
        self.capacity = burst or self.rate
        self.tokens = self.capacity
        self.updated_at = time.time()

    def take(self, tokens: float = 1.0) -> None:
        while True:
            now = time.time()
            elapsed = max(0.0, now - self.updated_at)
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.updated_at = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return
            time.sleep(max(0.01, (tokens - self.tokens) / self.rate))


class K8sPodLogFetcher:
    """
    Generic Kubernetes pod log fetcher (works for GKE once kubeconfig auth works).

    - Uses kubeconfig mounted at /kube/config
    - Reads pod logs with timestamps enabled
    - Emits each log line as a row into ClickHouse raw_logs
    """

    def __init__(self, cfg: K8sPodLogFetchConfig | None = None) -> None:
        self.cfg = cfg or K8sPodLogFetchConfig.from_env()
        self._bucket = TokenBucket(rate_per_s=self.cfg.qps, burst=max(2.0, self.cfg.qps))

    def _load_client(self) -> client.CoreV1Api:
        config.load_kube_config(config_file=self.cfg.kubeconfig)
        return client.CoreV1Api()

    def fetch(self, start: dt.datetime, end: dt.datetime) -> list[dict[str, Any]]:
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("start/end must be timezone-aware")
        since_seconds = max(1, int((end - start).total_seconds()))

        v1 = self._load_client()
        pods = v1.list_pod_for_all_namespaces(watch=False, timeout_seconds=30).items

        targets: list[client.V1Pod] = []
        for p in pods:
            svc = _pod_service_name(p)
            if self.cfg.service_allowlist and svc not in self.cfg.service_allowlist:
                continue
            targets.append(p)
            if len(targets) >= self.cfg.max_pods:
                break

        rows: list[dict[str, Any]] = []
        for p in targets:
            ns = p.metadata.namespace or ""
            pod_name = p.metadata.name or ""
            svc = _pod_service_name(p)

            container_name = ""
            if p.spec and p.spec.containers:
                container_name = p.spec.containers[0].name or ""

            self._bucket.take(1.0)
            try:
                text = v1.read_namespaced_pod_log(
                    name=pod_name,
                    namespace=ns,
                    container=container_name or None,
                    timestamps=True,
                    since_seconds=since_seconds,
                    tail_lines=self.cfg.max_lines_per_pod,
                    limit_bytes=self.cfg.limit_bytes_per_pod,
                    _preload_content=True,
                )
            except Exception as e:
                log.warning("k8s_pod_log_failed", namespace=ns, pod=pod_name, error=str(e))
                continue

            for line in (text or "").splitlines():
                line = line.strip()
                if not line:
                    continue

                ts = end
                msg = line
                m = _RFC3339_PREFIX.match(line)
                if m:
                    ts_s, msg = m.group(1), m.group(2)
                    try:
                        ts = dt.datetime.fromisoformat(ts_s.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
                    except Exception:
                        ts = end

                payload: dict[str, Any] = {
                    "k8s": {"namespace": ns, "pod": pod_name, "container": container_name},
                    "line": msg,
                }

                severity = "INFO"
                user = ""
                method = ""
                ip = ""
                status_code = 0

                # JSON logs: extract fields
                try:
                    obj = json.loads(msg)
                    if isinstance(obj, dict):
                        payload["jsonPayload"] = obj
                        for k in ("level", "severity", "log_level", "lvl"):
                            v = obj.get(k)
                            if isinstance(v, str) and v.strip():
                                severity = v.strip().upper()
                                break
                        for k in ("user", "username", "email", "identity", "sub"):
                            v = obj.get(k)
                            if isinstance(v, str) and v.strip():
                                user = v.strip()
                                break
                        for k in ("method", "endpoint", "path", "route", "action", "operation"):
                            v = obj.get(k)
                            if isinstance(v, str) and v.strip():
                                method = v.strip()
                                break
                        for k in ("ip", "client_ip", "remote_addr", "source_ip", "clientIp", "remoteAddr"):
                            v = obj.get(k)
                            if isinstance(v, str) and v.strip():
                                ip = v.strip()
                                break
                        for k in ("status", "status_code", "http_status", "statusCode", "code"):
                            v = obj.get(k)
                            if isinstance(v, int):
                                status_code = int(v)
                                break
                            if isinstance(v, str) and v.isdigit():
                                status_code = int(v)
                                break
                except Exception:
                    pass

                # Fallback: infer severity from text
                if not severity or severity == "INFO":
                    level_match = _LOG_LEVEL_PATTERN.search(msg)
                    if level_match:
                        sev = level_match.group(1).upper()
                        severity = "ERROR" if sev in {"ERR", "ERROR", "FATAL"} else ("WARNING" if sev in {"WARN", "WARNING"} else sev)

                # Fallback: infer IP/user/status_code from text
                if not ip:
                    ip_match = _IP_PATTERN.search(msg)
                    if ip_match:
                        ip = ip_match.group(0)
                if not user:
                    email_match = _EMAIL_PATTERN.search(msg)
                    if email_match:
                        user = email_match.group(0)
                if not status_code:
                    sm = _HTTP_STATUS_PATTERN.search(msg)
                    if sm:
                        try:
                            status_code = int(sm.group(2))
                        except Exception:
                            pass

                if status_code >= 500:
                    severity = "ERROR"
                elif status_code >= 400 and severity == "INFO":
                    severity = "WARNING"

                if not method:
                    method = "k8s.pod_log"

                rows.append(
                    {
                        "timestamp": ts,
                        "project": self.cfg.project,
                        "cluster": self.cfg.cluster,
                        "namespace": ns,
                        "pod": pod_name,
                        "service": svc,
                        "severity": severity,
                        "user": user,
                        "method": method,
                        "ip": ip,
                        "resource": f"pods/{ns}/{pod_name}",
                        "payload": payload,
                    }
                )

        log.info("k8s_pod_log_fetch_complete", rows=len(rows), pods=len(targets), cluster=self.cfg.cluster)
        return rows

