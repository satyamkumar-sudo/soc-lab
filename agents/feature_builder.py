from __future__ import annotations

import datetime as dt
import math
from typing import Any

import structlog

from agents.base_agent import BaseAgent, TimeWindow

log = structlog.get_logger(__name__)


def _entropy(counts: list[int]) -> float:
    total = sum(counts)
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in counts:
        if c <= 0:
            continue
        p = c / total
        ent -= p * math.log(p, 2)
    return float(ent)


def _get(d: Any, path: list[str], default: Any = None) -> Any:
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default


class FeatureBuilderAgent(BaseAgent):
    name = "feature_builder"

    def run(self, window: TimeWindow, **kwargs: Any) -> dict[str, Any]:
        sql = """
        SELECT timestamp, project, cluster, namespace, service, severity_num, identity, method, ip, payload
        FROM enriched_logs
        WHERE timestamp >= %(start)s AND timestamp < %(end)s
        """
        logs = self.ch.fetch_dicts(sql, {"start": window.start, "end": window.end})
        if not logs:
            return {"features": 0}

        groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
        for r in logs:
            key = (r["project"], r["cluster"], r["namespace"], r["service"])
            groups.setdefault(key, []).append(r)

        feature_rows: list[dict[str, Any]] = []
        for (project, cluster, namespace, service), rows in groups.items():
            # Exclude inventory snapshots from volume/error denominators,
            # but keep them for restart/security signals.
            non_inventory = [
                r
                for r in rows
                if str(r.get("method") or "") != "k8s.inventory" and not _get(r.get("payload") or {}, ["k8s", "inventory"], False)
            ]
            total = len(non_inventory)
            error_logs = sum(1 for r in non_inventory if int(r.get("severity_num") or 0) >= 40)
            error_rate = (error_logs / total) if total else 0.0

            iam_change = 0
            failed_logins = 0
            priv_esc = 0
            new_sas = 0
            api_abuse = 0
            escape = 0
            restarts = 0
            restart_samples = 0

            ip_counts: dict[str, int] = {}
            identity_counts: dict[str, int] = {}

            for r in rows:
                method = str(r.get("method") or "")
                ip = str(r.get("ip") or "")
                identity = str(r.get("identity") or "")
                payload = r.get("payload") or {}

                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                if identity:
                    identity_counts[identity] = identity_counts.get(identity, 0) + 1

                # IAM signals
                if "iam." in method or method.startswith("google.iam") or "iam.googleapis.com" in service:
                    iam_change += 1
                if method.endswith("CreateServiceAccount") or "CreateServiceAccount" in method:
                    new_sas += 1

                role = _get(payload, ["jsonPayload", "iam", "role"]) or _get(payload, ["protoPayload", "serviceData", "policyDelta", "bindingDeltas", "role"])
                if isinstance(role, str) and role in {"roles/owner", "roles/editor"}:
                    priv_esc += 1

                # Application auth signals
                status = _get(payload, ["jsonPayload", "status"])
                if method == "app/login" and int(status or 0) in {401, 403}:
                    failed_logins += 1

                # Abuse rate proxy: very high per-identity request volume in the same window
                # (computed later); also treat token endpoint bursts as abuse.
                if method in {"app/token", "app/login"}:
                    api_abuse += 1

                # K8s signals
                privileged = bool(_get(payload, ["k8s", "pod_security", "privileged"], False))
                host_mount = bool(_get(payload, ["k8s", "pod_security", "hostMount"], False))
                if privileged or host_mount:
                    escape += 1

                rc = _get(payload, ["k8s", "restartCount"])
                if isinstance(rc, int):
                    restarts += rc
                    restart_samples += 1

            ip_ent = _entropy(list(ip_counts.values()))
            pod_restart_rate = (restarts / restart_samples) if restart_samples else 0.0

            # Identity burstiness (rough): max share in window.
            max_identity_share = 0.0
            if identity_counts and total:
                max_identity_share = max(identity_counts.values()) / total

            api_abuse_rate = float(api_abuse / total) if total else 0.0
            if max_identity_share >= 0.7 and total >= 50:
                api_abuse_rate = min(1.0, api_abuse_rate + 0.25)

            feature_rows.append(
                {
                    "window_start": window.start,
                    "window_end": window.end,
                    "project": project,
                    "cluster": cluster,
                    "namespace": namespace,
                    "service": service,
                    "total_logs": total,
                    "error_rate": float(error_rate),
                    "iam_change_count": int(iam_change),
                    "failed_logins": int(failed_logins),
                    "privilege_escalations": int(priv_esc),
                    "new_service_accounts": int(new_sas),
                    "api_abuse_rate": float(api_abuse_rate),
                    "ip_entropy": float(ip_ent),
                    "pod_restart_rate": float(pod_restart_rate),
                    "container_escape_signals": int(escape),
                }
            )

        inserted = self.ch.insert_rows(
            "features",
            columns=[
                "window_start",
                "window_end",
                "project",
                "cluster",
                "namespace",
                "service",
                "total_logs",
                "error_rate",
                "iam_change_count",
                "failed_logins",
                "privilege_escalations",
                "new_service_accounts",
                "api_abuse_rate",
                "ip_entropy",
                "pod_restart_rate",
                "container_escape_signals",
            ],
            rows=[[r[c] for c in [
                "window_start",
                "window_end",
                "project",
                "cluster",
                "namespace",
                "service",
                "total_logs",
                "error_rate",
                "iam_change_count",
                "failed_logins",
                "privilege_escalations",
                "new_service_accounts",
                "api_abuse_rate",
                "ip_entropy",
                "pod_restart_rate",
                "container_escape_signals",
            ]] for r in feature_rows],
        )
        log.info("feature_build_complete", inserted=len(feature_rows), start=str(window.start), end=str(window.end))
        return {"features": len(feature_rows)}

