from __future__ import annotations

import csv
import datetime as dt
import ipaddress
import json
import os
from dataclasses import dataclass
from typing import Any

import structlog
import yaml

from agents.base_agent import BaseAgent, TimeWindow

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class IpEnrichment:
    ip_is_public: int
    country: str
    region: str
    city: str
    asn: int
    as_org: str


class EnrichmentAgent(BaseAgent):
    name = "enricher"

    def __init__(self, ch, data_dir: str | None = None) -> None:
        super().__init__(ch)
        self.data_dir = data_dir or os.environ.get("SOC_DATA_DIR", "/app/data")
        self._ip_ranges = self._load_ip_geo_asn(os.path.join(self.data_dir, "ip_geo_asn.csv"))
        self._ownership = self._load_ownership(os.path.join(self.data_dir, "ownership.yaml"))
        self._ti = self._load_threat_intel(os.path.join(self.data_dir, "threat_intel_iocs.csv"))

    def _load_ip_geo_asn(self, path: str) -> list[tuple[ipaddress._BaseNetwork, dict[str, Any]]]:
        out: list[tuple[ipaddress._BaseNetwork, dict[str, Any]]] = []
        if not os.path.exists(path):
            log.warning("ip_geo_asn_missing", path=path)
            return out
        with open(path, "r", newline="") as f:
            r = csv.DictReader(f)
            for row in r:
                try:
                    net = ipaddress.ip_network(row["cidr"])
                    out.append(
                        (
                            net,
                            {
                                "country": row.get("country", "UNKNOWN"),
                                "region": row.get("region", "UNKNOWN"),
                                "city": row.get("city", "UNKNOWN"),
                                "asn": int(row.get("asn") or 0),
                                "as_org": row.get("as_org", ""),
                            },
                        )
                    )
                except Exception:
                    continue
        return out

    def _load_ownership(self, path: str) -> dict[str, Any]:
        if not os.path.exists(path):
            return {"services": {"default": {"team": "unknown"}}}
        with open(path, "r") as f:
            return yaml.safe_load(f) or {"services": {"default": {"team": "unknown"}}}

    def _load_threat_intel(self, path: str) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = {"ip": [], "user": [], "service": []}
        if not os.path.exists(path):
            return out
        with open(path, "r", newline="") as f:
            r = csv.DictReader(f)
            for row in r:
                t = (row.get("indicator_type") or "").strip().lower()
                if t in out:
                    out[t].append(row)
        return out

    def _ip_enrich(self, ip: str) -> IpEnrichment:
        ip_is_public = 0
        try:
            ip_obj = ipaddress.ip_address(ip)
            ip_is_public = int(not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved))
        except Exception:
            return IpEnrichment(0, "UNKNOWN", "UNKNOWN", "UNKNOWN", 0, "")

        best: dict[str, Any] | None = None
        if ip_is_public and self._ip_ranges:
            try:
                ip_obj = ipaddress.ip_address(ip)
                for net, meta in self._ip_ranges:
                    if ip_obj in net:
                        best = meta
                        break
            except Exception:
                best = None

        if not best:
            best = {"country": "UNKNOWN", "region": "UNKNOWN", "city": "UNKNOWN", "asn": 0, "as_org": ""}
        return IpEnrichment(ip_is_public, best["country"], best["region"], best["city"], int(best["asn"]), str(best["as_org"]))

    def _owner_team(self, service: str) -> str:
        svc = (service or "").strip().lower()
        services = (self._ownership or {}).get("services", {}) if isinstance(self._ownership, dict) else {}
        if svc in services:
            return str((services[svc] or {}).get("team") or "unknown")
        return str((services.get("default") or {}).get("team") or "unknown")

    def _threat_tags(self, ip: str, identity: str, service: str) -> list[str]:
        tags: list[str] = []
        for row in self._ti.get("ip", []):
            if row.get("indicator") == ip:
                tags.append(str(row.get("tag") or "ioc_ip"))
        for row in self._ti.get("user", []):
            if row.get("indicator") == identity:
                tags.append(str(row.get("tag") or "ioc_user"))
        for row in self._ti.get("service", []):
            if (row.get("indicator") or "").strip().lower() == (service or "").strip().lower():
                tags.append(str(row.get("tag") or "ioc_service"))
        return sorted(set(tags))

    def _extract_iam_roles(self, payload: Any) -> list[str]:
        if not isinstance(payload, dict):
            return []

        roles: set[str] = set()
        jp = payload.get("jsonPayload")
        if isinstance(jp, dict):
            iam = jp.get("iam")
            if isinstance(iam, dict) and iam.get("role"):
                roles.add(str(iam["role"]))

        proto = payload.get("protoPayload")
        if isinstance(proto, dict):
            # common audit format: protoPayload.authorizationInfo[].permission / resourceAttributes
            authz = proto.get("authorizationInfo")
            if isinstance(authz, list):
                for a in authz:
                    if isinstance(a, dict):
                        perm = a.get("permission")
                        if perm:
                            roles.add(f"perm:{perm}")
            # Some IAM activity includes serviceData.policyDelta.bindingDeltas
            sd = proto.get("serviceData") or {}
            if isinstance(sd, dict):
                pd = sd.get("policyDelta") or {}
                if isinstance(pd, dict):
                    bds = pd.get("bindingDeltas")
                    if isinstance(bds, list):
                        for bd in bds:
                            if isinstance(bd, dict) and bd.get("role"):
                                roles.add(str(bd["role"]))

        return sorted(roles)

    def _baseline_error_rate(self, window: TimeWindow) -> dict[tuple[str, str, str, str], float]:
        sql = """
        SELECT project, cluster, namespace, service,
               if(count() = 0, 0, sum(severity_num >= 40) / count()) AS err_rate
        FROM normalized_logs
        WHERE timestamp >= %(start)s AND timestamp < %(end)s
        GROUP BY project, cluster, namespace, service
        """
        rows = self.ch.fetch_dicts(
            sql,
            {"start": window.start - dt.timedelta(hours=1), "end": window.start},
        )
        out: dict[tuple[str, str, str, str], float] = {}
        for r in rows:
            key = (r["project"], r["cluster"], r["namespace"], r["service"])
            out[key] = float(r["err_rate"])
        return out

    def run(self, window: TimeWindow, **kwargs: Any) -> dict[str, Any]:
        sql = """
        SELECT timestamp, project, cluster, namespace, pod, service, severity, severity_num, identity, method, ip, resource, request_id,
               message, status_code, is_success, error_signature, payload
        FROM normalized_logs
        WHERE timestamp >= %(start)s AND timestamp < %(end)s
        ORDER BY timestamp ASC
        """
        norm = self.ch.fetch_dicts(sql, {"start": window.start, "end": window.end})
        if not norm:
            return {"enriched": 0}

        baselines = self._baseline_error_rate(window)

        out_rows: list[dict[str, Any]] = []
        for r in norm:
            payload = r.get("payload") or {}
            ip = str(r.get("ip") or "")
            identity = str(r.get("identity") or "")
            service = str(r.get("service") or "")

            ipm = self._ip_enrich(ip)
            roles = self._extract_iam_roles(payload)
            tags = self._threat_tags(ip, identity, service)
            owner_team = self._owner_team(service)

            key = (r["project"], r["cluster"], r["namespace"], service)
            baseline_err = float(baselines.get(key, 0.0))

            # Copy SOC enrichment into payload so rule engine log_match can reference it
            # without having to query additional columns.
            if isinstance(payload, dict):
                payload.setdefault("soc", {})
                if isinstance(payload["soc"], dict):
                    payload["soc"]["threat_tags"] = tags
                    payload["soc"]["owner_team"] = owner_team
                    payload["soc"]["baseline_error_rate"] = baseline_err

            out_rows.append(
                {
                    "timestamp": r["timestamp"],
                    "project": r["project"],
                    "cluster": r["cluster"],
                    "namespace": r["namespace"],
                    "pod": r.get("pod") or "",
                    "service": service,
                    "severity": r.get("severity") or "DEFAULT",
                    "severity_num": int(r.get("severity_num") or 0),
                    "identity": identity,
                    "method": r.get("method") or "",
                    "ip": ip,
                    "resource": r.get("resource") or "",
                    "request_id": r.get("request_id") or "",
                    "message": str(r.get("message") or ""),
                    "status_code": int(r.get("status_code") or 0),
                    "is_success": int(r.get("is_success") or 0),
                    "error_signature": str(r.get("error_signature") or ""),
                    "ip_is_public": ipm.ip_is_public,
                    "geo_country": ipm.country,
                    "geo_region": ipm.region,
                    "geo_city": ipm.city,
                    "asn": ipm.asn,
                    "as_org": ipm.as_org,
                    "iam_roles": roles,
                    "owner_team": owner_team,
                    "threat_tags": tags,
                    "baseline_error_rate": baseline_err,
                    "payload": json.loads(json.dumps(payload, default=str)),
                }
            )

        inserted = self.ch.insert_json_payload_rows("enriched_logs", out_rows)
        log.info("enrich_complete", inserted=inserted, start=str(window.start), end=str(window.end))
        return {"enriched": inserted}

