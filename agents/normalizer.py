from __future__ import annotations

import datetime as dt
import ipaddress
import re
from typing import Any

import structlog

from agents.base_agent import BaseAgent, TimeWindow

log = structlog.get_logger(__name__)


_POD_SUFFIX_RE = re.compile(r"(-[a-f0-9]{8,10})?(-[a-z0-9]{5})?$")
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_HEX_RE = re.compile(r"\b0x[0-9a-f]+\b", re.I)
_LONG_HEX_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NUM_RE = re.compile(r"\b\d+\b")


def _svc_name(name: str) -> str:
    name = (name or "unknown").strip().lower()
    name = re.sub(r"[^a-z0-9\-\.\/]+", "-", name)
    return name[:128]


def _pod_name(pod: str) -> str:
    pod = (pod or "").strip().lower()
    pod = _POD_SUFFIX_RE.sub("", pod)
    return pod[:128] if pod else ""


def _ip_norm(ip: str) -> str:
    ip = (ip or "").strip()
    try:
        return str(ipaddress.ip_address(ip))
    except Exception:
        return ""


_SEV_MAP = {
    "DEFAULT": 0,
    "DEBUG": 10,
    "INFO": 20,
    "NOTICE": 25,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
    "ALERT": 60,
    "EMERGENCY": 70,
}


def _sev_num(sev: str) -> int:
    sev = (sev or "DEFAULT").upper()
    return int(_SEV_MAP.get(sev, 0))


def _extract_identity(payload: dict[str, Any], user_field: str) -> str:
    if user_field:
        return user_field
    proto = payload.get("protoPayload") if isinstance(payload, dict) else None
    if isinstance(proto, dict):
        auth = proto.get("authenticationInfo") or {}
        if isinstance(auth, dict):
            return str(auth.get("principalEmail") or auth.get("principalSubject") or "")
    jp = payload.get("jsonPayload") if isinstance(payload, dict) else None
    if isinstance(jp, dict):
        return str(jp.get("user") or jp.get("principal") or "")
    return ""


def _extract_request_id(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return ""
    jp = payload.get("jsonPayload")
    if isinstance(jp, dict) and jp.get("request_id"):
        return str(jp["request_id"])
    proto = payload.get("protoPayload")
    if isinstance(proto, dict):
        rid = (proto.get("requestMetadata") or {}).get("requestAttributes", {}).get("id")
        if rid:
            return str(rid)
    return ""


def _extract_message(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    # Some sources (synthetic / custom shippers) put fields at the top level.
    for k in ("message", "msg", "error", "exception", "detail"):
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    jp = payload.get("jsonPayload")
    if isinstance(jp, dict):
        for k in ("message", "msg", "error", "exception", "detail"):
            v = jp.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    tp = payload.get("textPayload")
    if isinstance(tp, str) and tp.strip():
        return tp.strip()
    proto = payload.get("protoPayload")
    if isinstance(proto, dict):
        status = proto.get("status")
        if isinstance(status, dict):
            msg = status.get("message")
            if isinstance(msg, str) and msg.strip():
                return msg.strip()
    return ""


def _extract_status_code(payload: Any) -> int:
    if not isinstance(payload, dict):
        return 0
    # Top-level (synthetic / custom) status code
    for k in ("status", "status_code", "http_status"):
        v = payload.get(k)
        if isinstance(v, int):
            return int(v)
        if isinstance(v, str) and v.isdigit():
            return int(v)
    jp = payload.get("jsonPayload")
    if isinstance(jp, dict):
        for k in ("status", "status_code", "http_status"):
            v = jp.get(k)
            if isinstance(v, int):
                return int(v)
            if isinstance(v, str) and v.isdigit():
                return int(v)
        http = jp.get("http")
        if isinstance(http, dict):
            v = http.get("status")
            if isinstance(v, int):
                return int(v)
            if isinstance(v, str) and v.isdigit():
                return int(v)
    proto = payload.get("protoPayload")
    if isinstance(proto, dict):
        status = proto.get("status")
        if isinstance(status, dict):
            code = status.get("code")
            if isinstance(code, int):
                return int(code)
            if isinstance(code, str) and code.isdigit():
                return int(code)
    return 0


def _error_signature(message: str) -> str:
    msg = (message or "").strip().lower()
    if not msg:
        return ""
    msg = _UUID_RE.sub("<uuid>", msg)
    msg = _HEX_RE.sub("<hex>", msg)
    msg = _LONG_HEX_RE.sub("<hex>", msg)
    msg = _IP_RE.sub("<ip>", msg)
    msg = _NUM_RE.sub("<num>", msg)
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg[:512]


class NormalizerAgent(BaseAgent):
    name = "normalizer"

    def run(self, window: TimeWindow, **kwargs: Any) -> dict[str, Any]:
        sql = """
        SELECT timestamp, project, cluster, namespace, pod, service, severity, user, method, ip, resource, payload
        FROM raw_logs
        WHERE timestamp >= %(start)s AND timestamp < %(end)s
        ORDER BY timestamp ASC
        """
        raw = self.ch.fetch_dicts(sql, {"start": window.start, "end": window.end})
        if not raw:
            return {"normalized": 0}

        out_rows: list[dict[str, Any]] = []
        for r in raw:
            ts = r["timestamp"]
            if isinstance(ts, dt.datetime):
                ts = ts.astimezone(dt.timezone.utc)
            else:
                ts = window.start

            payload = r.get("payload") or {}
            svc = _svc_name(str(r.get("service") or "unknown"))
            pod = _pod_name(str(r.get("pod") or ""))
            ip = _ip_norm(str(r.get("ip") or ""))
            sev = str(r.get("severity") or "DEFAULT").upper()
            sev_num = _sev_num(sev)

            msg = _extract_message(payload)
            status_code = int(_extract_status_code(payload) or 0)
            is_failure = bool(sev_num >= 40 or status_code >= 400)
            is_success = int((not is_failure) and (status_code == 0 or status_code < 400))
            sig = _error_signature(msg) if is_failure else ""

            out_rows.append(
                {
                    "timestamp": ts,
                    "project": str(r.get("project") or ""),
                    "cluster": str(r.get("cluster") or ""),
                    "namespace": str(r.get("namespace") or ""),
                    "pod": pod,
                    "service": svc,
                    "severity": sev,
                    "severity_num": sev_num,
                    "identity": _extract_identity(payload, str(r.get("user") or "")),
                    "method": str(r.get("method") or ""),
                    "ip": ip,
                    "resource": str(r.get("resource") or ""),
                    "request_id": _extract_request_id(payload),
                    "message": msg[:2000] if msg else "",
                    "status_code": status_code,
                    "is_success": is_success,
                    "error_signature": sig,
                    "payload": payload,
                }
            )

        inserted = self.ch.insert_json_payload_rows("normalized_logs", out_rows)
        log.info("normalize_complete", inserted=inserted, start=str(window.start), end=str(window.end))
        return {"normalized": inserted}

