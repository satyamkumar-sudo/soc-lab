from __future__ import annotations

import os
from dataclasses import dataclass

import structlog
from google.cloud import secretmanager

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class SecretConfig:
    use_secret_manager: bool
    project: str

    @staticmethod
    def from_env() -> "SecretConfig":
        return SecretConfig(
            use_secret_manager=str(os.environ.get("GCP_USE_SECRET_MANAGER", "False")).lower() == "true",
            project=os.environ.get("GOOGLE_CLOUD_PROJECT", ""),
        )


def _secret_resource(project: str, secret_id: str, version: str = "latest") -> str:
    if secret_id.startswith("projects/"):
        # allow full resource name
        return secret_id
    return f"projects/{project}/secrets/{secret_id}/versions/{version}"


def get_secret(
    *,
    env_var: str,
    secret_id: str,
    required: bool = False,
    cfg: SecretConfig | None = None,
) -> str:
    """
    Secret retrieval with least-privilege path:
    - Prefer env var (works in local dev / Docker Compose).
    - Optionally fetch from GCP Secret Manager when GCP_USE_SECRET_MANAGER=True.
    """
    v = os.environ.get(env_var, "")
    if v:
        return v

    cfg = cfg or SecretConfig.from_env()
    if not cfg.use_secret_manager:
        if required:
            raise RuntimeError(f"Missing required secret env var {env_var} (and Secret Manager disabled)")
        return ""

    if not cfg.project:
        raise RuntimeError("GOOGLE_CLOUD_PROJECT must be set when using Secret Manager")

    client = secretmanager.SecretManagerServiceClient()
    name = _secret_resource(cfg.project, secret_id)
    resp = client.access_secret_version(request={"name": name})
    val = resp.payload.data.decode("utf-8")
    if not val and required:
        raise RuntimeError(f"Secret Manager returned empty secret for {name}")
    log.info("secretmanager_access", secret_id=secret_id)
    return val

