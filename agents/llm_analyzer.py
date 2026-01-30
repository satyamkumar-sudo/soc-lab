from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from typing import Any, Literal

import structlog
import vertexai
from google import genai
from google.genai.types import HttpOptions

from agents.base_agent import BaseAgent, TimeWindow

log = structlog.get_logger(__name__)

# Required configuration variables (mirrors user requirements).
google_genai_use_vertexai = True
google_cloud_project = os.environ.get("GOOGLE_CLOUD_PROJECT", "wealthy-dev-app-8081")
google_cloud_location = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")


@dataclass(frozen=True)
class LlmConfig:
    project: str
    location: str
    use_vertexai: bool
    model: str
    cache_path: str

    @staticmethod
    def from_env() -> "LlmConfig":
        return LlmConfig(
            project=google_cloud_project,
            location=google_cloud_location,
            use_vertexai=str(os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "True")).lower() == "true",
            model=os.environ.get("SOC_GEMINI_MODEL", "gemini-1.5-pro"),
            cache_path=os.environ.get("SOC_LLM_CACHE", "/app/data/llm_cache.sqlite"),
        )


class SqliteCache:
    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_cache (
              k TEXT PRIMARY KEY,
              model TEXT NOT NULL,
              created_at TEXT NOT NULL,
              response TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, k: str) -> str | None:
        cur = self._conn.execute("SELECT response FROM llm_cache WHERE k=?", (k,))
        row = cur.fetchone()
        return row[0] if row else None

    def put(self, k: str, model: str, response: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO llm_cache(k, model, created_at, response) VALUES(?,?,?,?)",
            (k, model, dt.datetime.now(tz=dt.timezone.utc).isoformat(), response),
        )
        self._conn.commit()


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class LLMAnalyzerAgent(BaseAgent):
    name = "llm_analyzer"

    def __init__(self, ch, cfg: LlmConfig | None = None) -> None:
        super().__init__(ch)
        self.cfg = cfg or LlmConfig.from_env()
        self.cache = SqliteCache(self.cfg.cache_path)

        # Vertex AI initialization (official SDK).
        os.environ.setdefault("GOOGLE_CLOUD_PROJECT", self.cfg.project)
        os.environ.setdefault("GOOGLE_CLOUD_LOCATION", self.cfg.location)
        os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "True" if self.cfg.use_vertexai else "False")
        vertexai.init(project=self.cfg.project, location=self.cfg.location)

        # Google Gen AI SDK (Vertex backend when env/flag enabled).
        # NOTE: The official routing switch is GOOGLE_GENAI_USE_VERTEXAI=True
        self.client = genai.Client(
            http_options=HttpOptions(api_version="v1"),
        )

    def _generate(self, prompt: str) -> str:
        k = _sha256(self.cfg.model + "\n" + prompt)
        cached = self.cache.get(k)
        if cached is not None:
            return cached

        resp = self.client.models.generate_content(
            model=self.cfg.model,
            contents=prompt,
        )
        text = getattr(resp, "text", None) or str(resp)
        self.cache.put(k, self.cfg.model, text)
        return text

    def _build_prompt(
        self,
        kind: Literal["anomaly_explain", "incident_summary", "root_cause", "alert_enrich"],
        context: dict[str, Any],
    ) -> str:
        return (
            "You are a SOC analyst assistant. Use ONLY the provided context.\n"
            "Return STRICT JSON with keys: severity, summary, explanation, root_cause, mitigation, iocs, confidence.\n"
            f"Task: {kind}\n"
            "Context JSON:\n"
            f"{json.dumps(context, ensure_ascii=False, default=str)}\n"
        )

    def run(self, window: TimeWindow, **kwargs: Any) -> dict[str, Any]:
        # Find anomalies for this window that don't yet have LLM summaries.
        anomalies = self.ch.fetch_dicts(
            """
            SELECT window, project, cluster, namespace, service, score, confidence, model, risk_level, reason, llm_summary
            FROM anomalies
            WHERE window = %(w)s AND (llm_summary = '' OR llm_summary IS NULL)
            ORDER BY score DESC
            LIMIT 50
            """,
            {"w": window.start},
        )
        if not anomalies:
            return {"llm_enriched": 0}

        # Fetch rule matches and a sample of enriched logs for correlation.
        rules = self.ch.fetch_dicts(
            """
            SELECT window, project, cluster, namespace, service, identity, rule_id, severity, description, evidence
            FROM rule_matches
            WHERE window = %(w)s
            """,
            {"w": window.start},
        )
        logs = self.ch.fetch_dicts(
            """
            SELECT timestamp, project, cluster, namespace, service, identity, ip, method, threat_tags, iam_roles, payload
            FROM enriched_logs
            WHERE timestamp >= %(start)s AND timestamp < %(end)s
            ORDER BY timestamp DESC
            LIMIT 200
            """,
            {"start": window.start, "end": window.end},
        )

        enriched = 0
        for a in anomalies:
            svc = a["service"]
            rel_rules = [r for r in rules if r.get("service") == svc]
            rel_logs = [l for l in logs if l.get("service") == svc]

            context = {
                "window_start": str(window.start),
                "window_end": str(window.end),
                "anomaly": a,
                "related_rules": rel_rules[:20],
                "log_samples": [
                    {
                        "timestamp": str(l.get("timestamp")),
                        "identity": l.get("identity"),
                        "ip": l.get("ip"),
                        "method": l.get("method"),
                        "threat_tags": l.get("threat_tags"),
                        "iam_roles": l.get("iam_roles"),
                    }
                    for l in rel_logs[:30]
                ],
            }

            prompt = self._build_prompt("incident_summary", context)
            text = self._generate(prompt)

            # Best-effort extract JSON; fall back to raw.
            summary = text.strip()
            try:
                # Gemini often wraps JSON in code fences; strip if present.
                cleaned = summary
                if "```" in cleaned:
                    cleaned = cleaned.split("```")[1]
                obj = json.loads(cleaned)
                summary = json.dumps(obj, ensure_ascii=False)
            except Exception:
                pass

            # Persist summary (ClickHouse supports asynchronous updates).
            self.ch.execute(
                """
                ALTER TABLE anomalies
                UPDATE llm_summary = %(s)s
                WHERE window = %(w)s AND project = %(p)s AND cluster = %(c)s AND namespace = %(n)s AND service = %(svc)s AND model = %(m)s
                """,
                {
                    "s": summary,
                    "w": a["window"],
                    "p": a["project"],
                    "c": a["cluster"],
                    "n": a["namespace"],
                    "svc": a["service"],
                    "m": a["model"],
                },
            )
            enriched += 1

        log.info("llm_enrich_complete", enriched=enriched, window=str(window.start), model=self.cfg.model)
        return {"llm_enriched": enriched}

