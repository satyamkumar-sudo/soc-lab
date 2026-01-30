from __future__ import annotations

import json
import os
from datetime import timedelta

import pendulum
import requests
from airflow import DAG
from airflow.operators.python import PythonOperator


SOC_GATEWAY_HOST = os.environ.get("SOC_GATEWAY_HOST", "gateway")
SOC_GATEWAY_PORT = int(os.environ.get("SOC_GATEWAY_PORT", "8443"))
SOC_GATEWAY_SERVER_NAME = os.environ.get("SOC_GATEWAY_SERVER_NAME", "localhost")

CA_CERT = os.environ.get("SOC_MTLS_CA", "/certs/ca.crt")
CLIENT_CERT = os.environ.get("SOC_MTLS_CLIENT_CERT", "/certs/client.crt")
CLIENT_KEY = os.environ.get("SOC_MTLS_CLIENT_KEY", "/certs/client.key")


def _call_internal(endpoint: str, payload: dict) -> dict:
    url = f"https://{SOC_GATEWAY_HOST}:{SOC_GATEWAY_PORT}{endpoint}"
    resp = requests.post(
        url,
        json=payload,
        timeout=300,
        verify=CA_CERT,
        cert=(CLIENT_CERT, CLIENT_KEY),
        headers={"Host": SOC_GATEWAY_SERVER_NAME},
    )
    if resp.status_code >= 300:
        raise RuntimeError(f"API {endpoint} failed status={resp.status_code} body={resp.text[:2000]}")
    return resp.json()


def _task(endpoint: str, **context):
    start = context["data_interval_start"].in_timezone("UTC").to_iso8601_string()
    end = context["data_interval_end"].in_timezone("UTC").to_iso8601_string()
    payload = {"start": start, "end": end}
    out = _call_internal(endpoint, payload)
    print(json.dumps(out, indent=2))
    return out


default_args = {
    "owner": "soc-lab",
    "depends_on_past": False,
    "retries": 3,
    "retry_delay": timedelta(minutes=3),
    "sla": timedelta(minutes=12),
}


with DAG(
    dag_id="gcp_log_pipeline",
    default_args=default_args,
    schedule="*/5 * * * *",
    start_date=pendulum.datetime(2026, 1, 1, tz="UTC"),
    catchup=False,
    is_paused_upon_creation=False,
    # Allow a new run to start even if a prior run is stuck retrying LLM.
    max_active_runs=2,
    tags=["soc", "gcp", "clickhouse"],
) as dag:
    fetch_gcp_logs = PythonOperator(
        task_id="fetch_gcp_logs",
        python_callable=_task,
        op_kwargs={"endpoint": "/internal/fetch_store_raw"},
    )

    fetch_k8s_inventory = PythonOperator(
        task_id="fetch_k8s_inventory",
        python_callable=_task,
        op_kwargs={"endpoint": "/internal/fetch_k8s_inventory"},
    )

    normalize = PythonOperator(
        task_id="normalize",
        python_callable=_task,
        op_kwargs={"endpoint": "/internal/normalize"},
    )

    enrich = PythonOperator(
        task_id="enrich",
        python_callable=_task,
        op_kwargs={"endpoint": "/internal/enrich"},
    )

    build_features = PythonOperator(
        task_id="build_features",
        python_callable=_task,
        op_kwargs={"endpoint": "/internal/build_features"},
    )

    detect_anomalies = PythonOperator(
        task_id="detect_anomalies",
        python_callable=_task,
        op_kwargs={"endpoint": "/internal/detect_anomalies"},
    )

    apply_rules = PythonOperator(
        task_id="apply_rules",
        python_callable=_task,
        op_kwargs={"endpoint": "/internal/apply_rules"},
    )

    llm_enrich = PythonOperator(
        task_id="llm_enrich",
        python_callable=_task,
        op_kwargs={"endpoint": "/internal/llm_enrich"},
        retries=0,
    )

    alert = PythonOperator(
        task_id="alert",
        python_callable=_task,
        op_kwargs={"endpoint": "/internal/alert"},
    )

    # Keep the core pipeline running even if LLM enrichment fails (e.g., Vertex auth not configured).
    core = fetch_gcp_logs >> fetch_k8s_inventory >> normalize >> enrich >> build_features >> detect_anomalies >> apply_rules
    core >> alert
    core >> llm_enrich

