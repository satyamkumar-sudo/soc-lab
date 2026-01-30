from __future__ import annotations

import json
import os
import datetime as dt
from dataclasses import dataclass
from typing import Any

import numpy as np
import structlog
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor

from agents.base_agent import BaseAgent, TimeWindow

log = structlog.get_logger(__name__)


FEATURE_COLUMNS = [
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
]


@dataclass(frozen=True)
class ModelConfig:
    iforest: dict[str, Any]
    autoencoder: dict[str, Any]

    @staticmethod
    def load(path: str) -> "ModelConfig":
        if not os.path.exists(path):
            return ModelConfig(
                iforest={"n_estimators": 200, "contamination": "auto", "random_state": 42},
                autoencoder={"hidden_layer_sizes": [16, 8, 16], "max_iter": 500, "random_state": 42},
            )
        with open(path, "r") as f:
            data = json.load(f)
        return ModelConfig(
            iforest=dict(data.get("iforest") or {}),
            autoencoder=dict(data.get("autoencoder") or {}),
        )


def _norm01(x: np.ndarray) -> np.ndarray:
    if x.size == 0:
        return x
    mn = float(np.nanmin(x))
    mx = float(np.nanmax(x))
    if mx - mn < 1e-9:
        return np.zeros_like(x)
    return (x - mn) / (mx - mn)


class AnomalyDetectionAgent(BaseAgent):
    name = "anomaly_detector"

    def __init__(self, ch, model_config_path: str | None = None) -> None:
        super().__init__(ch)
        self.model_config_path = model_config_path or os.environ.get("SOC_MODEL_PATH", "/app/ml/model.pkl")
        self.cfg = ModelConfig.load(self.model_config_path)

    def _fetch_training_set(self, window: TimeWindow, lookback_hours: int = 24) -> list[dict[str, Any]]:
        sql = f"""
        SELECT window_start, window_end, project, cluster, namespace, service, {", ".join(FEATURE_COLUMNS)}
        FROM features
        WHERE window_start >= %(start)s AND window_start < %(end)s
        ORDER BY window_start ASC
        """
        return self.ch.fetch_dicts(
            sql,
            {"start": window.start - dt.timedelta(hours=lookback_hours), "end": window.start},
        )

    def _fetch_scoring_set(self, window: TimeWindow) -> list[dict[str, Any]]:
        sql = f"""
        SELECT window_start, window_end, project, cluster, namespace, service, {", ".join(FEATURE_COLUMNS)}
        FROM features
        WHERE window_start = %(start)s AND window_end = %(end)s
        """
        return self.ch.fetch_dicts(sql, {"start": window.start, "end": window.end})

    def _insert_signals(self, rows: list[dict[str, Any]]) -> int:
        if not rows:
            return 0
        return self.ch.insert_json_payload_rows("anomaly_signals", rows, payload_field="data")

    def _service_baselines(self, window: TimeWindow, project: str, cluster: str, namespace: str, service: str) -> dict[str, float]:
        # Baselines from features over the last 60 minutes (12x 5m windows).
        sql = """
        SELECT
          avg(toFloat64(total_logs)) AS log_volume_baseline_avg,
          avg(toFloat64(total_logs) * toFloat64(error_rate)) AS error_count_baseline_avg
        FROM features
        WHERE window_start >= %(start)s AND window_start < %(end)s
          AND project=%(project)s AND cluster=%(cluster)s AND namespace=%(namespace)s AND service=%(service)s
        """
        rows = self.ch.fetch_dicts(
            sql,
            {
                "start": window.start - dt.timedelta(minutes=60),
                "end": window.start,
                "project": project,
                "cluster": cluster,
                "namespace": namespace,
                "service": service,
            },
        )
        if not rows:
            return {"log_volume_baseline_avg": 0.0, "error_count_baseline_avg": 0.0}
        r = rows[0]
        return {
            "log_volume_baseline_avg": float(r.get("log_volume_baseline_avg") or 0.0),
            "error_count_baseline_avg": float(r.get("error_count_baseline_avg") or 0.0),
        }

    def _fetch_enriched_window(self, window: TimeWindow) -> list[dict[str, Any]]:
        sql = """
        SELECT
          timestamp, project, cluster, namespace, service, pod,
          severity, severity_num, method, status_code, is_success, error_signature, message
        FROM enriched_logs
        WHERE timestamp >= %(start)s AND timestamp < %(end)s
        """
        rows = self.ch.fetch_dicts(sql, {"start": window.start, "end": window.end})

        def parse_dt(v: Any) -> dt.datetime | None:
            if isinstance(v, dt.datetime):
                return v.astimezone(dt.timezone.utc)
            if isinstance(v, str) and v:
                # ClickHouse JSONEachRow returns DateTime as "YYYY-MM-DD HH:MM:SS"
                try:
                    vv = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
                    if vv.tzinfo is None:
                        vv = vv.replace(tzinfo=dt.timezone.utc)
                    return vv.astimezone(dt.timezone.utc)
                except Exception:
                    return None
            return None

        for r in rows:
            ts = parse_dt(r.get("timestamp"))
            if ts is not None:
                r["timestamp"] = ts
        return rows

    def _historical_signature_counts(
        self,
        window: TimeWindow,
        *,
        project: str,
        cluster: str,
        namespace: str,
        service: str,
        signatures: list[str],
        lookback_days: int = 7,
    ) -> dict[str, int]:
        if not signatures:
            return {}
        # Bound the IN list to avoid pathological cases.
        sigs = signatures[:500]
        in_list = ", ".join("'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'" for s in sigs)
        sql = f"""
        SELECT error_signature, count() AS cnt
        FROM enriched_logs
        WHERE timestamp >= %(start)s AND timestamp < %(end)s
          AND project=%(project)s AND cluster=%(cluster)s AND namespace=%(namespace)s AND service=%(service)s
          AND error_signature IN ({in_list})
        GROUP BY error_signature
        """
        rows = self.ch.fetch_dicts(
            sql,
            {
                "start": window.start - dt.timedelta(days=lookback_days),
                "end": window.start,
                "project": project,
                "cluster": cluster,
                "namespace": namespace,
                "service": service,
            },
        )
        return {str(r["error_signature"]): int(r["cnt"]) for r in rows if r.get("error_signature")}

    def _compute_signals(self, window: TimeWindow) -> int:
        logs = self._fetch_enriched_window(window)
        if not logs:
            return 0

        # Group by service scope.
        by_svc: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
        for r in logs:
            key = (str(r.get("project") or ""), str(r.get("cluster") or ""), str(r.get("namespace") or ""), str(r.get("service") or ""))
            by_svc.setdefault(key, []).append(r)

        signal_rows: list[dict[str, Any]] = []

        for (project, cluster, namespace, service), rows in by_svc.items():
            baselines = self._service_baselines(window, project, cluster, namespace, service)
            log_volume_baseline_avg = float(baselines["log_volume_baseline_avg"])
            error_count_baseline_avg = float(baselines["error_count_baseline_avg"])

            non_inventory = [r for r in rows if str(r.get("method") or "") != "k8s.inventory"]
            failures = [r for r in non_inventory if int(r.get("severity_num") or 0) >= 40 or int(r.get("status_code") or 0) >= 400]

            # --- 1) New / never-seen error signatures ---
            sig_occ: dict[str, dict[str, Any]] = {}
            for r in failures:
                sig = str(r.get("error_signature") or "").strip()
                if not sig:
                    continue
                cur = sig_occ.setdefault(sig, {"count": 0, "first_ts": r["timestamp"], "pod": str(r.get("pod") or "")})
                cur["count"] += 1
                if r["timestamp"] < cur["first_ts"]:
                    cur["first_ts"] = r["timestamp"]
                    cur["pod"] = str(r.get("pod") or "")

            hist = self._historical_signature_counts(
                window,
                project=project,
                cluster=cluster,
                namespace=namespace,
                service=service,
                signatures=list(sig_occ.keys()),
            )

            for sig, meta in sig_occ.items():
                hist_cnt = int(hist.get(sig, 0))
                if hist_cnt != 0:
                    continue
                data = {
                    "signal_type": "new_error_signature",
                    "service_name": service,
                    "cluster": cluster,
                    "namespace": namespace,
                    "pod_name": str(meta.get("pod") or ""),
                    "severity": "ERROR",
                    "error_signature": sig,
                    "first_seen_timestamp": (meta["first_ts"].astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z") if isinstance(meta["first_ts"], dt.datetime) else ""),
                    "historical_occurrence_count": 0,
                    "current_window_occurrence_count": int(meta["count"]),
                }
                signal_rows.append(
                    {
                        "window_start": window.start,
                        "window_end": window.end,
                        "project": project,
                        "cluster": cluster,
                        "namespace": namespace,
                        "service": service,
                        "signal_type": "new_error_signature",
                        "severity": "ERROR",
                        "pod": str(meta.get("pod") or ""),
                        "data": data,
                    }
                )

            # --- 2) Error burst detection (5m window) ---
            error_count_current = len(failures)
            spike_ratio = float(error_count_current / max(1.0, error_count_baseline_avg))
            if error_count_current >= 10 and spike_ratio >= 3.0:
                data = {
                    "signal_type": "error_burst",
                    "service_name": service,
                    "cluster": cluster,
                    "namespace": namespace,
                    "time_window_seconds": 300,
                    "error_count_current_window": int(error_count_current),
                    "error_count_baseline_avg": float(error_count_baseline_avg),
                    "error_spike_ratio": float(spike_ratio),
                }
                signal_rows.append(
                    {
                        "window_start": window.start,
                        "window_end": window.end,
                        "project": project,
                        "cluster": cluster,
                        "namespace": namespace,
                        "service": service,
                        "signal_type": "error_burst",
                        "severity": "ERROR",
                        "pod": "",
                        "data": data,
                    }
                )

            # --- 3) Service behavior deviation (severity mix + volume) ---
            sev_cur: dict[str, int] = {"DEBUG": 0, "INFO": 0, "WARNING": 0, "ERROR": 0}
            for r in non_inventory:
                sev = str(r.get("severity") or "INFO").upper()
                if sev not in sev_cur:
                    continue
                sev_cur[sev] += 1
            # Baseline distribution from last 60 minutes of enriched logs.
            sql = """
            SELECT severity, count() AS c
            FROM enriched_logs
            WHERE timestamp >= %(start)s AND timestamp < %(end)s
              AND project=%(project)s AND cluster=%(cluster)s AND namespace=%(namespace)s AND service=%(service)s
              AND method != 'k8s.inventory'
            GROUP BY severity
            """
            base_rows = self.ch.fetch_dicts(
                sql,
                {
                    "start": window.start - dt.timedelta(minutes=60),
                    "end": window.start,
                    "project": project,
                    "cluster": cluster,
                    "namespace": namespace,
                    "service": service,
                },
            )
            sev_base: dict[str, int] = {"DEBUG": 0, "INFO": 0, "WARNING": 0, "ERROR": 0}
            for br in base_rows:
                s = str(br.get("severity") or "").upper()
                if s in sev_base:
                    sev_base[s] = int(br.get("c") or 0)

            log_volume_current = len(non_inventory)
            # Trigger on big volume shifts or a big error-share shift.
            cur_total = max(1, sum(sev_cur.values()))
            base_total = max(1, sum(sev_base.values()))
            cur_err_share = sev_cur["ERROR"] / cur_total
            base_err_share = sev_base["ERROR"] / base_total
            volume_spike = (log_volume_current >= 50 and log_volume_current >= (log_volume_baseline_avg * 2.0))
            err_share_shift = abs(cur_err_share - base_err_share) >= 0.20 and log_volume_current >= 20
            if volume_spike or err_share_shift:
                data = {
                    "signal_type": "service_behavior_deviation",
                    "service_name": service,
                    "severity_distribution_current": sev_cur,
                    "severity_distribution_baseline": sev_base,
                    "log_volume_current": int(log_volume_current),
                    "log_volume_baseline_avg": float(log_volume_baseline_avg),
                }
                signal_rows.append(
                    {
                        "window_start": window.start,
                        "window_end": window.end,
                        "project": project,
                        "cluster": cluster,
                        "namespace": namespace,
                        "service": service,
                        "signal_type": "service_behavior_deviation",
                        "severity": "WARNING",
                        "pod": "",
                        "data": data,
                    }
                )

            # --- 4) Repeated failures without success (workflow=method) ---
            failures_by_workflow: dict[tuple[str, str], int] = {}
            for r in failures:
                wf = str(r.get("method") or "")
                sig = str(r.get("error_signature") or "")
                if not wf or not sig:
                    continue
                failures_by_workflow[(wf, sig)] = failures_by_workflow.get((wf, sig), 0) + 1

            if failures_by_workflow:
                wf_names = sorted({wf for (wf, _sig) in failures_by_workflow.keys()})[:200]
                in_wf = ", ".join("'" + w.replace("\\", "\\\\").replace("'", "\\'") + "'" for w in wf_names)
                sql = f"""
                SELECT method, max(timestamp) AS last_success_ts
                FROM enriched_logs
                WHERE timestamp >= %(start)s AND timestamp < %(end)s
                  AND project=%(project)s AND cluster=%(cluster)s AND namespace=%(namespace)s AND service=%(service)s
                  AND is_success = 1
                  AND method IN ({in_wf})
                GROUP BY method
                """
                succ_rows = self.ch.fetch_dicts(
                    sql,
                    {
                        "start": window.start - dt.timedelta(hours=24),
                        "end": window.end,
                        "project": project,
                        "cluster": cluster,
                        "namespace": namespace,
                        "service": service,
                    },
                )
                last_success: dict[str, dt.datetime] = {}
                for sr in succ_rows:
                    m = str(sr.get("method") or "")
                    ts = sr.get("last_success_ts")
                    if isinstance(ts, dt.datetime):
                        last_success[m] = ts

                for (wf, sig), cnt in failures_by_workflow.items():
                    if cnt < 3:
                        continue
                    lst = last_success.get(wf)
                    if isinstance(lst, dt.datetime):
                        delta_s = int((window.end - lst.replace(tzinfo=dt.timezone.utc)).total_seconds()) if isinstance(window.end, dt.datetime) else 0
                    else:
                        # No known success in the last 24h window: treat as highly suspicious.
                        delta_s = int(dt.timedelta(hours=24).total_seconds())
                        lst = None
                    if delta_s >= 1800:
                        data = {
                            "signal_type": "repeated_failure_no_success",
                            "service_name": service,
                            "workflow_name": wf,
                            "failure_signature": sig,
                            "failure_count": int(cnt),
                            "last_success_timestamp": (lst.isoformat().replace("+00:00", "Z") if isinstance(lst, dt.datetime) else ""),
                            "time_since_last_success_seconds": int(delta_s),
                        }
                        signal_rows.append(
                            {
                                "window_start": window.start,
                                "window_end": window.end,
                                "project": project,
                                "cluster": cluster,
                                "namespace": namespace,
                                "service": service,
                                "signal_type": "repeated_failure_no_success",
                                "severity": "CRITICAL",
                                "pod": "",
                                "data": data,
                            }
                        )

            # --- 5) Cross-pod error correlation ---
            pods_total = len({str(r.get("pod") or "") for r in non_inventory if str(r.get("pod") or "")})
            if pods_total <= 0:
                pods_total = 1
            affected_by_sig: dict[str, set[str]] = {}
            for r in failures:
                sig = str(r.get("error_signature") or "")
                pod = str(r.get("pod") or "")
                if sig and pod:
                    affected_by_sig.setdefault(sig, set()).add(pod)
            for sig, pods in affected_by_sig.items():
                affected = len(pods)
                ratio = float(affected / max(1, pods_total))
                if affected >= 3 and ratio >= 0.5:
                    data = {
                        "signal_type": "cross_pod_error_correlation",
                        "service_name": service,
                        "error_signature": sig,
                        "affected_pod_count": int(affected),
                        "total_pod_count": int(pods_total),
                        "correlation_ratio": float(ratio),
                    }
                    signal_rows.append(
                        {
                            "window_start": window.start,
                            "window_end": window.end,
                            "project": project,
                            "cluster": cluster,
                            "namespace": namespace,
                            "service": service,
                            "signal_type": "cross_pod_error_correlation",
                            "severity": "ERROR",
                            "pod": "",
                            "data": data,
                        }
                    )

            # --- 6) Sudden log volume spike (per pod) ---
            pod_counts: dict[str, int] = {}
            for r in non_inventory:
                pod = str(r.get("pod") or "")
                if not pod:
                    continue
                pod_counts[pod] = pod_counts.get(pod, 0) + 1
            if pod_counts:
                pod_names = sorted(pod_counts.keys())[:200]
                in_pods = ", ".join("'" + p.replace("\\", "\\\\").replace("'", "\\'") + "'" for p in pod_names)
                sql = f"""
                SELECT pod, count() AS c
                FROM enriched_logs
                WHERE timestamp >= %(start)s AND timestamp < %(end)s
                  AND project=%(project)s AND cluster=%(cluster)s AND namespace=%(namespace)s AND service=%(service)s
                  AND method != 'k8s.inventory'
                  AND pod IN ({in_pods})
                GROUP BY pod
                """
                hist_rows = self.ch.fetch_dicts(
                    sql,
                    {
                        "start": window.start - dt.timedelta(minutes=60),
                        "end": window.start,
                        "project": project,
                        "cluster": cluster,
                        "namespace": namespace,
                        "service": service,
                    },
                )
                hist_counts = {str(r["pod"]): int(r["c"]) for r in hist_rows if r.get("pod")}
                for pod, cur_c in pod_counts.items():
                    base_avg = float(hist_counts.get(pod, 0)) / 12.0
                    mult = float(cur_c / max(1.0, base_avg))
                    if cur_c >= 50 and mult >= 3.0:
                        data = {
                            "signal_type": "log_volume_spike",
                            "service_name": service,
                            "pod_name": pod,
                            "log_count_current_window": int(cur_c),
                            "log_count_baseline_avg": float(base_avg),
                            "spike_multiplier": float(mult),
                        }
                        signal_rows.append(
                            {
                                "window_start": window.start,
                                "window_end": window.end,
                                "project": project,
                                "cluster": cluster,
                                "namespace": namespace,
                                "service": service,
                                "signal_type": "log_volume_spike",
                                "severity": "WARNING",
                                "pod": pod,
                                "data": data,
                            }
                        )

            # --- 7) Pod-specific anomaly (error heavy pod vs peers) ---
            pod_errors: dict[str, int] = {}
            for r in failures:
                pod = str(r.get("pod") or "")
                if not pod:
                    continue
                pod_errors[pod] = pod_errors.get(pod, 0) + 1
            if pod_errors:
                total_err = sum(pod_errors.values())
                pods = list(pod_errors.keys())
                for pod, ecount in pod_errors.items():
                    peers = max(1, len(pods) - 1)
                    peer_avg = float((total_err - ecount) / peers) if peers > 0 else float(total_err)
                    dev = float(ecount / max(1.0, peer_avg))
                    if ecount >= 5 and dev >= 3.0:
                        data = {
                            "signal_type": "pod_specific_anomaly",
                            "service_name": service,
                            "pod_name": pod,
                            "error_count_pod": int(ecount),
                            "error_count_peer_avg": float(peer_avg),
                            "deviation_ratio": float(dev),
                        }
                        signal_rows.append(
                            {
                                "window_start": window.start,
                                "window_end": window.end,
                                "project": project,
                                "cluster": cluster,
                                "namespace": namespace,
                                "service": service,
                                "signal_type": "pod_specific_anomaly",
                                "severity": "ERROR",
                                "pod": pod,
                                "data": data,
                            }
                        )

        inserted = self._insert_signals(signal_rows)
        if inserted:
            log.info("anomaly_signals_written", inserted=inserted, window=str(window.start))
        return inserted

    def run(self, window: TimeWindow, **kwargs: Any) -> dict[str, Any]:
        # Pull scoring rows (per service) and a recent training set.
        scoring = self._fetch_scoring_set(window)
        if not scoring:
            return {"anomalies": 0}

        training = self._fetch_training_set(window)
        if len(training) < 30:
            # Use scoring rows themselves if no history yet; still produces output for demo/dev.
            training = scoring

        X_train = np.array([[float(r.get(c) or 0.0) for c in FEATURE_COLUMNS] for r in training], dtype=float)
        X_score = np.array([[float(r.get(c) or 0.0) for c in FEATURE_COLUMNS] for r in scoring], dtype=float)

        # IsolationForest: higher = more anomalous (invert decision_function).
        iforest = IsolationForest(**self.cfg.iforest)
        iforest.fit(X_train)
        iso_raw = -iforest.decision_function(X_score)
        iso = _norm01(iso_raw)

        # Autoencoder-ish: train MLP to reconstruct input; reconstruction error indicates anomaly.
        ae = MLPRegressor(**self.cfg.autoencoder)
        ae.fit(X_train, X_train)
        recon = ae.predict(X_score)
        ae_raw = np.mean((X_score - recon) ** 2, axis=1)
        ae_s = _norm01(ae_raw)

        # Z-score baseline using training distribution.
        mu = np.mean(X_train, axis=0)
        sigma = np.std(X_train, axis=0)
        sigma = np.where(sigma < 1e-9, 1.0, sigma)
        z = np.abs((X_score - mu) / sigma)
        z_raw = np.mean(z, axis=1)
        z_s = _norm01(z_raw)

        # Ensemble score and confidence (agreement across models).
        score = (iso + ae_s + z_s) / 3.0
        disagree = np.std(np.stack([iso, ae_s, z_s], axis=1), axis=1)
        confidence = np.clip(1.0 - disagree * 2.0, 0.0, 1.0)

        def risk_level(s: float) -> str:
            if s >= 0.85:
                return "critical"
            if s >= 0.70:
                return "high"
            if s >= 0.50:
                return "medium"
            return "low"

        anomaly_rows: list[dict[str, Any]] = []
        for idx, r in enumerate(scoring):
            s = float(score[idx])
            conf = float(confidence[idx])
            # Feature attribution via z-scores.
            zrow = z[idx]
            top = np.argsort(zrow)[::-1][:3]
            parts = [f"{FEATURE_COLUMNS[i]} z={zrow[i]:.2f} val={X_score[idx, i]:.3f}" for i in top]
            reason = "Top deviations: " + "; ".join(parts)

            anomaly_rows.append(
                {
                    "window": window.start,
                    "project": r["project"],
                    "cluster": r["cluster"],
                    "namespace": r["namespace"],
                    "service": r["service"],
                    "score": s,
                    "confidence": conf,
                    "model": "ensemble(iforest+autoencoder+zscore)",
                    "risk_level": risk_level(s),
                    "reason": reason,
                    "llm_summary": "",
                }
            )

        inserted = self.ch.insert_rows(
            "anomalies",
            columns=[
                "window",
                "project",
                "cluster",
                "namespace",
                "service",
                "score",
                "confidence",
                "model",
                "risk_level",
                "reason",
                "llm_summary",
            ],
            rows=[[row[c] for c in [
                "window",
                "project",
                "cluster",
                "namespace",
                "service",
                "score",
                "confidence",
                "model",
                "risk_level",
                "reason",
                "llm_summary",
            ]] for row in anomaly_rows],
        )

        log.info("anomaly_detect_complete", inserted=len(anomaly_rows), window=str(window.start))
        signals = self._compute_signals(window)
        return {"anomalies": len(anomaly_rows), "signals": signals}

