from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Callable

import structlog
import yaml

from agents.base_agent import BaseAgent, TimeWindow

log = structlog.get_logger(__name__)


def _get_path(obj: Any, path: list[Any]) -> Any:
    cur = obj
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _op_func(op: str) -> Callable[[Any, Any], bool]:
    op = op.strip()
    if op == ">":
        return lambda a, b: float(a) > float(b)
    if op == ">=":
        return lambda a, b: float(a) >= float(b)
    if op == "<":
        return lambda a, b: float(a) < float(b)
    if op == "<=":
        return lambda a, b: float(a) <= float(b)
    if op in {"==", "="}:
        return lambda a, b: a == b
    if op == "!=":
        return lambda a, b: a != b
    raise ValueError(f"Unsupported op: {op}")


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    severity: str
    description: str
    type: str
    data: dict[str, Any]


class RuleEngineAgent(BaseAgent):
    name = "rule_engine"

    def __init__(self, ch, rules_path: str | None = None) -> None:
        super().__init__(ch)
        self.rules_path = rules_path or os.environ.get("SOC_RULES_PATH", "/app/agents/rules.yaml")
        self.rules = self._load_rules(self.rules_path)

    def _load_rules(self, path: str) -> list[Rule]:
        with open(path, "r") as f:
            doc = yaml.safe_load(f) or {}
        rules = []
        for r in doc.get("rules", []):
            rules.append(
                Rule(
                    id=str(r["id"]),
                    name=str(r.get("name") or r["id"]),
                    category=str(r.get("category") or "general"),
                    severity=str(r.get("severity") or "medium"),
                    description=str(r.get("description") or ""),
                    type=str(r.get("type") or ""),
                    data=dict(r),
                )
            )
        return rules

    def _eval_feature_rule(self, rule: Rule, feature_row: dict[str, Any]) -> bool:
        if "expr" in rule.data:
            expr = rule.data["expr"] or {}
            if "all_of" in expr:
                return all(self._eval_feature_cond(c, feature_row) for c in (expr["all_of"] or []))
            if "any_of" in expr:
                return any(self._eval_feature_cond(c, feature_row) for c in (expr["any_of"] or []))
            return False
        field = rule.data.get("field")
        op = rule.data.get("op")
        value = rule.data.get("value")
        if not field or not op:
            return False
        return _op_func(str(op))(feature_row.get(str(field), 0), value)

    def _eval_feature_cond(self, cond: dict[str, Any], feature_row: dict[str, Any]) -> bool:
        field = cond.get("field")
        op = cond.get("op")
        value = cond.get("value")
        if not field or not op:
            return False
        return _op_func(str(op))(feature_row.get(str(field), 0), value)

    def _eval_log_rule(self, rule: Rule, log_row: dict[str, Any]) -> bool:
        payload = log_row.get("payload") or {}
        payload_str = ""
        try:
            payload_str = json.dumps(payload, default=str)
        except Exception:
            payload_str = str(payload)

        match = rule.data.get("match") or {}
        clauses = match.get("any_of") or []
        for clause in clauses:
            if "contains" in clause:
                if str(clause["contains"]) in payload_str:
                    return True
            path = clause.get("payload_path")
            if path:
                val = _get_path(payload, list(path))
                op = clause.get("op", "==")
                target = clause.get("value")
                try:
                    if _op_func(str(op))(val, target):
                        return True
                except Exception:
                    continue
        return False

    def run(self, window: TimeWindow, **kwargs: Any) -> dict[str, Any]:
        features = self.ch.fetch_dicts(
            """
            SELECT window_start, window_end, project, cluster, namespace, service,
                   total_logs, error_rate, iam_change_count, failed_logins, privilege_escalations,
                   new_service_accounts, api_abuse_rate, ip_entropy, pod_restart_rate, container_escape_signals
            FROM features
            WHERE window_start = %(start)s AND window_end = %(end)s
            """,
            {"start": window.start, "end": window.end},
        )

        logs = self.ch.fetch_dicts(
            """
            SELECT timestamp, project, cluster, namespace, service, identity, ip, payload
            FROM enriched_logs
            WHERE timestamp >= %(start)s AND timestamp < %(end)s
            """,
            {"start": window.start, "end": window.end},
        )

        matches: list[dict[str, Any]] = []

        for rule in self.rules:
            if rule.type == "feature_threshold":
                for fr in features:
                    if self._eval_feature_rule(rule, fr):
                        matches.append(
                            {
                                "window": window.start,
                                "project": fr["project"],
                                "cluster": fr["cluster"],
                                "namespace": fr["namespace"],
                                "service": fr["service"],
                                "identity": "*",
                                "rule_id": rule.id,
                                "rule_name": rule.name,
                                "severity": rule.severity,
                                "description": rule.description,
                                "evidence": {
                                    "type": "feature",
                                    "features": {k: fr.get(k) for k in fr.keys() if k not in {"window_start", "window_end"}},
                                },
                            }
                        )
            elif rule.type == "log_match":
                for lr in logs:
                    if self._eval_log_rule(rule, lr):
                        matches.append(
                            {
                                "window": window.start,
                                "project": lr["project"],
                                "cluster": lr["cluster"],
                                "namespace": lr["namespace"],
                                "service": lr["service"],
                                "identity": lr.get("identity") or "",
                                "rule_id": rule.id,
                                "rule_name": rule.name,
                                "severity": rule.severity,
                                "description": rule.description,
                                "evidence": {
                                    "type": "log",
                                    "ip": lr.get("ip") or "",
                                    "timestamp": str(lr.get("timestamp") or ""),
                                },
                            }
                        )

        if not matches:
            return {"rule_matches": 0}

        inserted = self.ch.insert_json_payload_rows("rule_matches", matches, payload_field="evidence")
        log.info("rule_engine_complete", inserted=inserted, window=str(window.start))
        return {"rule_matches": inserted}

