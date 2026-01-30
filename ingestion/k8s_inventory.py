from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from typing import Any

import structlog
from kubernetes import client, config

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class K8sConfig:
    project: str
    soc_project: str
    cluster_name: str
    location: str
    kubeconfig: str
    service_allowlist: tuple[str, ...]

    @staticmethod
    def from_env() -> "K8sConfig":
        allow = tuple(
            s.strip().lower()
            for s in os.environ.get("SOC_SERVICE_ALLOWLIST", "").split(",")
            if s.strip()
        )
        provider = (os.environ.get("SOC_INGEST_PROVIDER", "gcp") or "gcp").strip().lower()
        if provider == "azure":
            soc_project = os.environ.get("SOC_AZURE_PROJECT", "").strip() or os.environ.get("SOC_GCP_PROJECT", "").strip() or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
            cluster_name = os.environ.get("AKS_CLUSTER_NAME", "").strip() or os.environ.get("GKE_CLUSTER_NAME", "").strip()
            location = os.environ.get("AKS_RESOURCE_GROUP", "").strip() or os.environ.get("GKE_LOCATION", "").strip()
        else:
            soc_project = os.environ.get("SOC_GCP_PROJECT", "").strip() or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
            cluster_name = os.environ.get("GKE_CLUSTER_NAME", "").strip()
            location = os.environ.get("GKE_LOCATION", "").strip()
        return K8sConfig(
            project=os.environ.get("GOOGLE_CLOUD_PROJECT", ""),
            soc_project=soc_project,
            cluster_name=cluster_name,
            location=location,
            kubeconfig=os.environ.get("KUBECONFIG", "/kube/config"),
            service_allowlist=allow,
        )


def _pod_service_name(pod: client.V1Pod) -> str:
    labels = pod.metadata.labels or {}
    for k in ("app.kubernetes.io/name", "app", "k8s-app"):
        if labels.get(k):
            return str(labels[k]).strip().lower()
    return (pod.metadata.name or "unknown").split("-")[0].strip().lower()


def _pod_security_flags(pod: client.V1Pod) -> dict[str, Any]:
    spec = pod.spec
    flags = {
        "privileged": False,
        "hostPID": bool(getattr(spec, "host_pid", False)),
        "hostNetwork": bool(getattr(spec, "host_network", False)),
        "hostIPC": bool(getattr(spec, "host_ipc", False)),
        "hostMount": False,
        "runAsRoot": False,
    }

    # hostPath mounts
    vols = spec.volumes or []
    for v in vols:
        if getattr(v, "host_path", None) is not None:
            flags["hostMount"] = True
            break

    # privileged containers / runAsUser==0 signals
    for c in (spec.containers or []):
        sc = c.security_context
        if sc and sc.privileged:
            flags["privileged"] = True
        if sc and sc.run_as_user == 0:
            flags["runAsRoot"] = True
    return flags


class K8sInventoryFetcher:
    def __init__(self, cfg: K8sConfig | None = None) -> None:
        self.cfg = cfg or K8sConfig.from_env()

    def _load_client(self) -> client.CoreV1Api:
        # Uses kubeconfig produced by:
        # gcloud container clusters get-credentials wealthy-dev --zone asia-south1-a --project wealthy-dev-app-8081
        config.load_kube_config(config_file=self.cfg.kubeconfig)
        return client.CoreV1Api()

    def fetch_pod_inventory(self, at: dt.datetime | None = None) -> list[dict[str, Any]]:
        at = at or dt.datetime.now(tz=dt.timezone.utc)
        v1 = self._load_client()

        rows: list[dict[str, Any]] = []
        pods = v1.list_pod_for_all_namespaces(watch=False, timeout_seconds=30)
        for p in pods.items:
            ns = p.metadata.namespace or ""
            pod_name = p.metadata.name or ""
            svc = _pod_service_name(p)
            if self.cfg.service_allowlist and svc not in self.cfg.service_allowlist:
                continue
            cluster = self.cfg.cluster_name or ""

            restart_count = 0
            if p.status and p.status.container_statuses:
                restart_count = sum(int(cs.restart_count or 0) for cs in p.status.container_statuses)

            flags = _pod_security_flags(p)
            payload = {
                "k8s": {
                    "inventory": True,
                    "restartCount": restart_count,
                    "phase": str(p.status.phase if p.status else ""),
                    "node": str(p.spec.node_name if p.spec else ""),
                    "pod_security": flags,
                    "labels": p.metadata.labels or {},
                }
            }

            rows.append(
                {
                    "timestamp": at,
                    "project": self.cfg.soc_project or "",
                    "cluster": cluster,
                    "namespace": ns,
                    "pod": pod_name,
                    "service": svc,
                    "severity": "INFO",
                    "user": "",
                    "method": "k8s.inventory",
                    "ip": "",
                    "resource": f"pods/{ns}/{pod_name}",
                    "payload": payload,
                }
            )

        log.info("k8s_inventory_fetched", pods=len(rows), cluster=self.cfg.cluster_name, location=self.cfg.location)
        return rows

