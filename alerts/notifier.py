from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any

import requests
import structlog

from storage.clickhouse_client import ClickHouseClient
from storage.secrets import get_secret

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class AlertConfig:
    slack_webhook_url: str
    webhook_url: str
    throttle_seconds: int
    dedup_ttl_seconds: int

    @staticmethod
    def from_env() -> "AlertConfig":
        return AlertConfig(
            slack_webhook_url=get_secret(env_var="ALERT_SLACK_WEBHOOK_URL", secret_id="soc-slack-webhook").strip(),
            webhook_url=get_secret(env_var="ALERT_WEBHOOK_URL", secret_id="soc-generic-webhook").strip(),
            throttle_seconds=int(os.environ.get("ALERT_THROTTLE_SECONDS", "60")),
            dedup_ttl_seconds=int(os.environ.get("ALERT_DEDUP_TTL_SECONDS", "900")),
        )


def _fingerprint(obj: Any) -> str:
    s = json.dumps(obj, sort_keys=True, default=str)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:32]


class AlertNotifier:
    def __init__(self, ch: ClickHouseClient, cfg: AlertConfig | None = None) -> None:
        self.ch = ch
        self.cfg = cfg or AlertConfig.from_env()

    def _recently_sent(self, fingerprint: str) -> bool:
        rows = self.ch.fetch_dicts(
            """
            SELECT count() AS c
            FROM alerts
            WHERE fingerprint = %(fp)s AND created_at >= now() - INTERVAL %(ttl)s SECOND
            """,
            {"fp": fingerprint, "ttl": self.cfg.dedup_ttl_seconds},
        )
        return bool(rows and int(rows[0]["c"]) > 0)

    def _throttle_ok(self, channel: str) -> bool:
        rows = self.ch.fetch_dicts(
            """
            SELECT max(created_at) AS last
            FROM alerts
            WHERE channel = %(ch)s AND sent = 1
            """,
            {"ch": channel},
        )
        if not rows or rows[0]["last"] is None:
            return True
        last = rows[0]["last"]
        # clickhouse-driver returns datetime for DateTime
        try:
            delta = time.time() - last.timestamp()
        except Exception:
            return True
        return delta >= self.cfg.throttle_seconds

    def _post(self, url: str, body: dict[str, Any]) -> None:
        resp = requests.post(url, json=body, timeout=10)
        if resp.status_code >= 300:
            raise RuntimeError(f"alert_post_failed status={resp.status_code} body={resp.text[:2000]}")

    def send_window_alerts(self, window_start, window_end) -> dict[str, Any]:
        anomalies = self.ch.fetch_dicts(
            """
            SELECT window, project, cluster, namespace, service, risk_level, score, confidence, reason, llm_summary
            FROM anomalies
            WHERE window = %(w)s
            ORDER BY score DESC
            LIMIT 25
            """,
            {"w": window_start},
        )
        rules = self.ch.fetch_dicts(
            """
            SELECT window, project, cluster, namespace, service, identity, rule_id, severity, description
            FROM rule_matches
            WHERE window = %(w)s
            ORDER BY created_at DESC
            LIMIT 50
            """,
            {"w": window_start},
        )

        if not anomalies and not rules:
            return {"sent": 0}

        # Build message (LLM-enhanced where available).
        top = anomalies[:5]
        msg_lines = [
            f"SOC Lab alert window={window_start}..{window_end}",
            f"anomalies={len(anomalies)} rule_matches={len(rules)}",
            "",
            "Top anomalies:",
        ]
        for a in top:
            msg_lines.append(
                f"- [{a['risk_level']}] {a['project']}/{a['cluster']}/{a['namespace']}/{a['service']} "
                f"score={a['score']:.3f} conf={a['confidence']:.2f} reason={a['reason'][:180]}"
            )
            if a.get("llm_summary"):
                msg_lines.append(f"  LLM: {str(a['llm_summary'])[:500]}")

        if rules:
            msg_lines.append("")
            msg_lines.append("Recent rule matches:")
            for r in rules[:10]:
                msg_lines.append(
                    f"- [{r['severity']}] {r['rule_id']} {r['project']}/{r['cluster']}/{r['namespace']}/{r['service']} "
                    f"id={r.get('identity') or '*'} {r['description']}"
                )

        payload = {
            "window_start": str(window_start),
            "window_end": str(window_end),
            "anomalies": anomalies,
            "rule_matches": rules,
        }
        fp = _fingerprint(
            {
                "window_start": str(window_start),
                "top_anomaly": top[0] if top else None,
                "top_rule": rules[0] if rules else None,
            }
        )

        if self._recently_sent(fp):
            log.info("alert_deduped", fingerprint=fp)
            return {"sent": 0, "deduped": True}

        sent = 0
        title = f"SOC Lab alert [{(top[0]['risk_level'] if top else (rules[0]['severity'] if rules else 'info'))}]"
        message = "\n".join(msg_lines)

        if self.cfg.slack_webhook_url and self._throttle_ok("slack"):
            self._post(self.cfg.slack_webhook_url, {"text": message})
            sent += 1
            channel = "slack"
        elif self.cfg.webhook_url and self._throttle_ok("webhook"):
            self._post(self.cfg.webhook_url, {"title": title, "message": message, "payload": payload})
            sent += 1
            channel = "webhook"
        else:
            channel = "none"

        self.ch.insert_json_payload_rows(
            "alerts",
            [
                {
                    "fingerprint": fp,
                    "channel": channel,
                    "risk_level": (top[0]["risk_level"] if top else (rules[0]["severity"] if rules else "info")),
                    "title": title,
                    "message": message,
                    "payload": payload,
                    "sent": 1 if sent else 0,
                }
            ],
            payload_field="payload",
        )

        log.info("alert_sent", sent=sent, channel=channel, fingerprint=fp)
        return {"sent": sent, "channel": channel, "fingerprint": fp}

