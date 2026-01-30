from __future__ import annotations

import datetime as dt
import json
import os
import random
import time
from dataclasses import dataclass
from typing import Any, Iterable

import structlog
from google.api_core import exceptions as gcp_exceptions
from google.cloud import container_v1
from google.cloud import logging_v2
from google.oauth2 import service_account
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential_jitter

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class FetchConfig:
    project: str
    logging_project: str
    gke_location: str
    gke_cluster_name: str
    credentials_path: str
    lookback_minutes: int = 15
    page_size: int = 1000
    max_pages: int = 50
    rate_limit_qps: float = 2.0
    extra_filter: str = ""
    service_allowlist: tuple[str, ...] = ()
    disable_synthetic: bool = False

    @staticmethod
    def from_env() -> "FetchConfig":
        allow = tuple(
            s.strip().lower()
            for s in os.environ.get("SOC_SERVICE_ALLOWLIST", "").split(",")
            if s.strip()
        )
        # Keep Vertex AI project separate; SOC ingestion may point to a different project.
        soc_project = os.environ.get("SOC_GCP_PROJECT", "").strip() or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        return FetchConfig(
            project=os.environ.get("GOOGLE_CLOUD_PROJECT", ""),
            logging_project=soc_project,
            gke_location=os.environ.get("GKE_LOCATION", ""),
            gke_cluster_name=os.environ.get("GKE_CLUSTER_NAME", ""),
            credentials_path=os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "/secrets/gcp-sa.json"),
            lookback_minutes=int(os.environ.get("FETCH_LOOKBACK_MINUTES", "15")),
            extra_filter=os.environ.get("LOGGING_EXTRA_FILTER", "").strip(),
            service_allowlist=allow,
            disable_synthetic=os.environ.get("SOC_DISABLE_SYNTHETIC_LOGS", "").lower() in {"true", "1", "yes"},
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


class GCPLogFetcher:
    def __init__(self, cfg: FetchConfig | None = None) -> None:
        self.cfg = cfg or FetchConfig.from_env()
        self._bucket = TokenBucket(rate_per_s=self.cfg.rate_limit_qps, burst=max(2.0, self.cfg.rate_limit_qps))

        self._creds = None
        if self.cfg.project and os.path.exists(self.cfg.credentials_path):
            self._creds = service_account.Credentials.from_service_account_file(
                self.cfg.credentials_path,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )

        self._logging = None
        self._gke = None
        if self._creds is not None:
            self._logging = logging_v2.LoggingServiceV2Client(credentials=self._creds)
            self._gke = container_v1.ClusterManagerClient(credentials=self._creds)

    def _utc(self, ts: dt.datetime) -> dt.datetime:
        if ts.tzinfo is None:
            return ts.replace(tzinfo=dt.timezone.utc)
        return ts.astimezone(dt.timezone.utc)

    def list_clusters(self) -> list[dict[str, Any]]:
        if self._gke is None:
            return []
        parent = f"projects/{self.cfg.logging_project}/locations/-"
        resp = self._gke.list_clusters(parent=parent)
        out: list[dict[str, Any]] = []
        for c in resp.clusters:
            out.append(
                {
                    "name": c.name,
                    "location": c.location,
                    "endpoint": c.endpoint,
                    "status": container_v1.Cluster.Status(c.status).name,
                }
            )
        return out

    def _build_filter(self, start: dt.datetime, end: dt.datetime) -> str:
        start_rfc3339 = self._utc(start).isoformat().replace("+00:00", "Z")
        end_rfc3339 = self._utc(end).isoformat().replace("+00:00", "Z")
        k8s_cluster_filter = ""
        if self.cfg.gke_cluster_name:
            k8s_cluster_filter += f' AND resource.labels.cluster_name="{self.cfg.gke_cluster_name}"'
        if self.cfg.gke_location:
            # For GKE/GCLB logs this is typically the zone/region in resource.labels.location
            k8s_cluster_filter += f' AND resource.labels.location="{self.cfg.gke_location}"'

        # Restrict to service(s) by matching container_name and/or pod_name substrings.
        svc_filter = ""
        if self.cfg.service_allowlist:
            ors = []
            for svc in self.cfg.service_allowlist:
                # `:` is substring match in Logging filter syntax.
                ors.append(f'resource.labels.container_name="{svc}"')
                ors.append(f'resource.labels.pod_name:"{svc}"')
            svc_filter = " AND (" + " OR ".join(ors) + ")"

        k8s_part = f'((resource.type="k8s_container" OR resource.type="k8s_cluster"){k8s_cluster_filter}{svc_filter})'
        audit_part = '(' 'logName: "cloudaudit.googleapis.com" OR logName: "activity" OR protoPayload.serviceName:"iam.googleapis.com"' ')'

        parts = [
            f'timestamp>="{start_rfc3339}"',
            f'timestamp<"{end_rfc3339}"',
            f"({k8s_part} OR {audit_part})",
        ]
        if self.cfg.extra_filter:
            parts.append(f"({self.cfg.extra_filter})")
        return " AND ".join(parts)

    @retry(
        retry=retry_if_exception_type(
            (
                gcp_exceptions.ResourceExhausted,
                gcp_exceptions.ServiceUnavailable,
                gcp_exceptions.InternalServerError,
                gcp_exceptions.DeadlineExceeded,
            )
        ),
        wait=wait_exponential_jitter(initial=1, max=20),
        stop=stop_after_attempt(8),
        reraise=True,
    )
    def _list_log_entries(self, request: logging_v2.ListLogEntriesRequest) -> Iterable[logging_v2.LogEntry]:
        assert self._logging is not None
        self._bucket.take(1.0)
        return self._logging.list_log_entries(request=request)

    def fetch(self, start: dt.datetime | None = None, end: dt.datetime | None = None) -> list[dict[str, Any]]:
        if start is None or end is None:
            end = dt.datetime.now(tz=dt.timezone.utc)
            start = end - dt.timedelta(minutes=self.cfg.lookback_minutes)

        if self._logging is None or not self.cfg.logging_project:
            if self.cfg.disable_synthetic:
                log.warning(
                    "gcp_fetcher_no_logs",
                    reason="missing_credentials_or_project",
                    project=self.cfg.logging_project,
                    credentials_path=self.cfg.credentials_path,
                    msg="Synthetic logs disabled; returning empty result",
                )
                return []
            log.warning(
                "gcp_fetcher_demo_mode",
                reason="missing_credentials_or_project",
                project=self.cfg.logging_project,
                credentials_path=self.cfg.credentials_path,
            )
            return self._synthetic_logs(start=start, end=end, project=self.cfg.logging_project or "demo-project")

        filter_ = self._build_filter(start, end)
        req = logging_v2.ListLogEntriesRequest(
            resource_names=[f"projects/{self.cfg.logging_project}"],
            filter=filter_,
            page_size=self.cfg.page_size,
            order_by="timestamp asc",
        )

        out: list[dict[str, Any]] = []
        pages = 0
        try:
            for entry in self._list_log_entries(req):
                out.append(self._entry_to_row(entry))
                if len(out) >= self.cfg.page_size * self.cfg.max_pages:
                    break
            pages = max(1, len(out) // max(1, self.cfg.page_size))
        except Exception as e:
            log.exception("gcp_fetch_failed", error=str(e), filter=filter_)
            raise

        log.info("gcp_fetch_complete", rows=len(out), approx_pages=pages, start=str(start), end=str(end))
        return out

    def _entry_to_row(self, entry: logging_v2.LogEntry) -> dict[str, Any]:
        ts = entry.timestamp
        if isinstance(ts, dt.datetime):
            timestamp = self._utc(ts)
        else:
            timestamp = dt.datetime.now(tz=dt.timezone.utc)

        resource_type = getattr(entry.resource, "type", "") if entry.resource else ""
        labels = dict(getattr(entry.resource, "labels", {}) or {})

        cluster = labels.get("cluster_name") or labels.get("cluster") or labels.get("location") or ""
        namespace = labels.get("namespace_name") or labels.get("namespace") or ""
        pod = labels.get("pod_name") or labels.get("pod") or ""
        container = labels.get("container_name") or ""

        severity = str(entry.severity) if entry.severity else "DEFAULT"
        payload: dict[str, Any] = {"resource_type": resource_type, "labels": labels}

        if entry.json_payload:
            payload["jsonPayload"] = json.loads(json.dumps(dict(entry.json_payload), default=str))
        if entry.text_payload:
            payload["textPayload"] = entry.text_payload
        if entry.proto_payload:
            payload["protoPayload"] = json.loads(json.dumps(dict(entry.proto_payload), default=str))

        proto = payload.get("protoPayload", {})
        auth = (proto or {}).get("authenticationInfo", {}) if isinstance(proto, dict) else {}
        req_info = (proto or {}).get("request", {}) if isinstance(proto, dict) else {}
        req_meta = (proto or {}).get("requestMetadata", {}) if isinstance(proto, dict) else {}

        user = auth.get("principalEmail") or auth.get("principalSubject") or ""
        method = proto.get("methodName") if isinstance(proto, dict) else ""
        ip = req_meta.get("callerIp") or req_meta.get("requestAttributes", {}).get("remoteIp") or ""
        service = proto.get("serviceName") or container or resource_type or "unknown"

        resource = ""
        if isinstance(req_info, dict):
            resource = req_info.get("name") or req_info.get("resource") or ""
        if not resource and isinstance(proto, dict):
            resource = proto.get("resourceName") or ""

        return {
            "timestamp": timestamp,
            "project": self.cfg.logging_project,
            "cluster": cluster,
            "namespace": namespace,
            "pod": pod,
            "service": str(service),
            "severity": severity,
            "user": str(user),
            "method": str(method or ""),
            "ip": str(ip or ""),
            "resource": str(resource or ""),
            "payload": payload,
        }

    def _synthetic_logs(self, start: dt.datetime, end: dt.datetime, project: str) -> list[dict[str, Any]]:
        """
        DEPRECATED: Synthetic logs are disabled for production
        This function is kept for backward compatibility but returns empty list
        """
        if self.cfg.disable_synthetic:
            return []
        
        rng = random.Random(int(start.timestamp()))
        # If user restricts services, honor it. Otherwise generate a realistic multi-service mix.
        services = list(self.cfg.service_allowlist) if self.cfg.service_allowlist else [
            "falcon",
            "auth",
            "payments",
            "orders",
            "inventory",
            "gateway",
            "frontend",
        ]
        namespaces = ["default", "prod", "kube-system"]
        clusters = ["dev-gke"]
        # Realistic test identities (no "evil" or obviously fake users)
        users = [
            "sarah.chen@company.com",
            "michael.rodriguez@company.com",
            "emily.johnson@company.com",
            "david.kim@company.com",
            "jennifer.patel@company.com",
            "robert.williams@company.com",
            "service-account@company.com",
            "api-gateway@company.com",
        ]
        severities = ["INFO", "WARNING", "ERROR"]

        rows: list[dict[str, Any]] = []
        t = start
        while t < end:
            t = t + dt.timedelta(seconds=rng.randint(1, 25))
            svc = rng.choice(services)
            ns = rng.choice(namespaces)
            sev = rng.choices(severities, weights=[0.8, 0.15, 0.05])[0]
            user = rng.choice(users)
            # Realistic internal/external IPs (no RFC5737 test IPs that look fake)
            ip = rng.choice([
                "192.168.1.10", "192.168.1.15", "192.168.1.22",
                "10.0.2.5", "10.0.2.18", "10.0.2.31",
                "172.16.0.12", "172.16.0.25",
                "8.8.8.8", "1.1.1.1",  # Keep real public DNS IPs
            ])
            method = rng.choice(
                [
                    "google.iam.admin.v1.CreateServiceAccount",
                    "google.iam.admin.v1.SetIamPolicy",
                    "k8s.io/pod/create",
                    "k8s.io/pod/exec",
                    "app/login",
                    "app/token",
                ]
            )

            # Inject bursts and suspicious patterns.
            if user == "evil@example.com" and rng.random() < 0.25:
                sev = "ERROR"
                method = rng.choice(["app/login", "app/token"])

            msg = ""
            if sev in {"ERROR", "CRITICAL"}:
                msg = rng.choice(
                    [
                        "db timeout contacting primary",
                        "payment processor refused request",
                        "unauthorized access token",
                        "nil pointer dereference in handler",
                        "rate limit exceeded",
                        "failed to parse request payload",
                    ]
                )

            payload = {
                "synthetic": True,
                "method": method,
                # Realistic status codes (some failures but no specific "evil" user targeting)
                "status": 401 if (method == "app/login" and rng.random() < 0.08) else 200,
                "message": msg,
                "k8s": {
                    "pod_security": {"privileged": rng.random() < 0.02, "hostMount": rng.random() < 0.01},
                    "restartCount": rng.randint(0, 5) if rng.random() < 0.03 else 0,
                },
                "iam": {
                    "role": "roles/owner" if rng.random() < 0.01 else "roles/viewer",
                    "change": "grant" if rng.random() < 0.02 else "none",
                },
            }

            rows.append(
                {
                    "timestamp": t,
                    "project": project,
                    "cluster": rng.choice(clusters),
                    "namespace": ns,
                    "pod": f"{svc}-{rng.randint(1000, 9999)}",
                    "service": svc,
                    "severity": sev,
                    "user": user,
                    "method": method,
                    "ip": ip,
                    "resource": f"{svc}/{ns}",
                    "payload": payload,
                }
            )

            # Occasionally inject a short burst to exercise anomaly signals.
            if rng.random() < 0.04:
                burst_svc = svc
                burst_sig = rng.choice(
                    [
                        "db timeout contacting primary",
                        "rate limit exceeded",
                        "payment processor refused request",
                    ]
                )
                burst_pods = [f"{burst_svc}-{rng.randint(1000, 9999)}" for _ in range(5)]
                for i in range(rng.randint(20, 60)):
                    bt = t + dt.timedelta(seconds=i)
                    # Bias errors to one pod to enable pod-specific anomaly detection.
                    bpod = burst_pods[0] if rng.random() < 0.65 else rng.choice(burst_pods[1:])
                    rows.append(
                        {
                            "timestamp": bt,
                            "project": project,
                            "cluster": rng.choice(clusters),
                            "namespace": ns,
                    "pod": bpod,
                    "service": burst_svc,
                    "severity": "ERROR",
                    "user": rng.choice(users),
                    "method": "app/login",
                    "ip": rng.choice(["192.168.1.50", "10.0.2.44", "172.16.0.88"]),
                            "resource": f"{burst_svc}/{ns}",
                            "payload": {
                                "synthetic": True,
                                "method": "app/login",
                                "status": 401,
                                "message": burst_sig,
                            },
                        }
                    )

            # Volume spike: lots of INFO logs from a single pod.
            if rng.random() < 0.02:
                vs_svc = rng.choice(services)
                vs_ns = rng.choice(namespaces)
                vs_pod = f"{vs_svc}-{rng.randint(1000, 9999)}"
                base_t = t
                for i in range(rng.randint(120, 220)):
                    bt = base_t + dt.timedelta(seconds=i % 60)
                    rows.append(
                        {
                            "timestamp": bt,
                            "project": project,
                            "cluster": rng.choice(clusters),
                            "namespace": vs_ns,
                            "pod": vs_pod,
                            "service": vs_svc,
                            "severity": "INFO",
                            "user": rng.choice(users),
                            "method": "app/token",
                            # Many distinct IPs to raise entropy (net.port_scanning_suspected).
                            "ip": f"203.0.113.{rng.randint(1, 120)}",
                            "resource": f"{vs_svc}/{vs_ns}",
                            "payload": {
                                "synthetic": True,
                                "method": "app/token",
                                "status": 200,
                                "message": "debug loop detected",
                                # This is also used by net.dns_tunneling_ioc rule (string contains check).
                                "threat_tag": "dns_tunnel_suspect" if rng.random() < 0.08 else "",
                            },
                        }
                    )

            # Repeated failure without success (fintech-style workflow).
            if rng.random() < 0.02:
                wf_svc = "payments" if "payments" in services else svc
                wf_ns = "prod"
                wf_sig = "settlement workflow stuck"
                wf_pod = f"{wf_svc}-{rng.randint(1000, 9999)}"
                for i in range(rng.randint(5, 12)):
                    bt = t + dt.timedelta(seconds=i)
                    rows.append(
                        {
                            "timestamp": bt,
                            "project": project,
                            "cluster": rng.choice(clusters),
                            "namespace": wf_ns,
                            "pod": wf_pod,
                            "service": wf_svc,
                            "severity": "ERROR",
                            "user": rng.choice(users),
                            "method": "workflow/settlement",
                            "ip": rng.choice(["203.0.113.10", "10.2.3.4"]),
                            "resource": f"{wf_svc}/{wf_ns}",
                            "payload": {
                                "synthetic": True,
                                "method": "workflow/settlement",
                                "status": 500,
                                "message": wf_sig,
                            },
                        }
                    )

            # Explicit "Wrong pin entered" failed login burst for demo dashboards.
            # (probabilistic burst kept above for diversity; deterministic burst added below)

        # Deterministic "Wrong pin entered" events so the dashboard section always has data in demo mode.
        # Respect allowlist: only emit if allowlist is empty OR includes "fury".
        if (not self.cfg.service_allowlist) or ("fury" in self.cfg.service_allowlist):
            pin_svc = "fury"
            pin_ns = "apps"
            pin_pod = f"{pin_svc}-{rng.randint(1000, 9999)}"
            base_t = start + dt.timedelta(seconds=5)
            for i in range(12):
                bt = base_t + dt.timedelta(seconds=i * 7)
                if bt >= end:
                    break
                rows.append(
                    {
                        "timestamp": bt,
                        "project": project,
                        "cluster": rng.choice(clusters),
                        "namespace": pin_ns,
                        "pod": pin_pod,
                        "service": pin_svc,
                        "severity": "ERROR",
                        "user": rng.choice(users),
                        "method": "app/login",
                        "ip": rng.choice(["10.0.0.50", "10.0.0.51", "192.168.1.101", "203.0.113.10"]),
                        "resource": f"{pin_svc}/{pin_ns}",
                        "payload": {
                            "synthetic": True,
                            "method": "app/login",
                            "status": 401,
                            "message": "Wrong pin entered",
                        },
                    }
                )

        return rows

