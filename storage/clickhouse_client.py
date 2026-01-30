from __future__ import annotations

import json
import datetime as dt
import os
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

import requests
import structlog
from clickhouse_driver import Client

from storage.secrets import get_secret

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ClickHouseConfig:
    host: str
    port: int
    http_port: int
    database: str
    user: str
    password: str
    secure: bool = False
    connect_timeout: int = 10
    send_receive_timeout: int = 30

    @staticmethod
    def from_env() -> "ClickHouseConfig":
        return ClickHouseConfig(
            host=os.environ.get("CLICKHOUSE_HOST", "clickhouse"),
            port=int(os.environ.get("CLICKHOUSE_PORT", "9000")),
            http_port=int(os.environ.get("CLICKHOUSE_HTTP_PORT", "8123")),
            database=os.environ.get("CLICKHOUSE_DB", "soc"),
            user=os.environ.get("CLICKHOUSE_USER", "soc"),
            password=get_secret(env_var="CLICKHOUSE_PASSWORD", secret_id="soc-clickhouse-password"),
        )


class ClickHouseClient:
    def __init__(self, cfg: ClickHouseConfig | None = None) -> None:
        self.cfg = cfg or ClickHouseConfig.from_env()
        self._client = Client(
            host=self.cfg.host,
            port=self.cfg.port,
            database=self.cfg.database,
            user=self.cfg.user,
            password=self.cfg.password,
            secure=self.cfg.secure,
            connect_timeout=self.cfg.connect_timeout,
            send_receive_timeout=self.cfg.send_receive_timeout,
            settings={"use_numpy": False},
        )

    def ping(self) -> bool:
        try:
            self._client.execute("SELECT 1")
            return True
        except Exception:
            log.exception("clickhouse_ping_failed")
            return False

    def execute(self, sql: str, params: Mapping[str, Any] | None = None) -> list[Any]:
        return self._client.execute(sql, params or {})

    def insert_rows(
        self,
        table: str,
        columns: Sequence[str],
        rows: Iterable[Sequence[Any]],
        *,
        settings: Mapping[str, Any] | None = None,
    ) -> None:
        cols = ", ".join(columns)
        sql = f"INSERT INTO {table} ({cols}) VALUES"
        self._client.execute(sql, list(rows), settings=settings or {})

    def _http_insert_json_each_row(self, table: str, rows: list[dict[str, Any]]) -> None:
        """
        Use ClickHouse HTTP interface to insert JSONEachRow.
        This avoids `clickhouse-driver` limitations with the ClickHouse `JSON` data type.
        """
        base = f"http://{self.cfg.host}:{self.cfg.http_port}"
        query = f"INSERT INTO {self.cfg.database}.{table} FORMAT JSONEachRow"
        url = f"{base}/?query={requests.utils.quote(query, safe='')}"

        def normalize(v: Any) -> Any:
            if isinstance(v, dt.datetime):
                vv = v
                if vv.tzinfo is not None:
                    vv = vv.astimezone(dt.timezone.utc).replace(tzinfo=None)
                # ClickHouse JSONEachRow for DateTime expects "YYYY-MM-DD HH:MM:SS"
                return vv.strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(v, dt.date) and not isinstance(v, dt.datetime):
                return v.isoformat()
            if isinstance(v, dict):
                return {k: normalize(x) for k, x in v.items()}
            if isinstance(v, list):
                return [normalize(x) for x in v]
            return v

        norm_rows = [normalize(r) for r in rows]
        body = "\n".join(json.dumps(r, ensure_ascii=False, default=str) for r in norm_rows) + "\n"
        resp = requests.post(
            url,
            data=body.encode("utf-8"),
            auth=(self.cfg.user, self.cfg.password) if self.cfg.user else None,
            headers={"Content-Type": "application/x-ndjson"},
            timeout=30,
        )
        if resp.status_code >= 300:
            raise RuntimeError(f"clickhouse_http_insert_failed status={resp.status_code} body={resp.text[:2000]}")

    def insert_json_payload_rows(
        self,
        table: str,
        rows: Iterable[Mapping[str, Any]],
        *,
        payload_field: str = "payload",
    ) -> int:
        """
        Inserts rows where `payload_field` is a dict/list and must be stored as JSON.
        Returns inserted count.
        """
        prepared: list[dict[str, Any]] = []
        for r in rows:
            rr = dict(r)
            payload = rr.get(payload_field, {})
            if not isinstance(payload, (dict, list)):
                payload = {"_raw": str(payload)}
            rr[payload_field] = json.loads(json.dumps(payload, default=str))
            prepared.append(rr)

        if not prepared:
            return 0

        # Use HTTP JSONEachRow to support ClickHouse `JSON` columns.
        self._http_insert_json_each_row(table, prepared)
        return len(prepared)

    def fetch_dicts(self, sql: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        # Use HTTP JSONEachRow so ClickHouse `JSON` types decode correctly.
        params = params or {}

        def lit(v: Any) -> str:
            if v is None:
                return "NULL"
            if isinstance(v, bool):
                return "1" if v else "0"
            if isinstance(v, (int, float)):
                return str(v)
            if isinstance(v, dt.datetime):
                vv = v
                if vv.tzinfo is not None:
                    vv = vv.astimezone(dt.timezone.utc).replace(tzinfo=None)
                return "'" + vv.strftime("%Y-%m-%d %H:%M:%S") + "'"
            if isinstance(v, dt.date) and not isinstance(v, dt.datetime):
                return "'" + v.isoformat() + "'"
            s = str(v).replace("\\", "\\\\").replace("'", "\\'")
            return f"'{s}'"

        rendered = sql
        for k, v in params.items():
            rendered = rendered.replace(f"%({k})s", lit(v))

        # Ensure a single statement and append output format.
        q = rendered.strip().rstrip(";")
        q = f"{q} FORMAT JSONEachRow"

        base = f"http://{self.cfg.host}:{self.cfg.http_port}"
        url = f"{base}/?database={requests.utils.quote(self.cfg.database)}&query={requests.utils.quote(q, safe='')}"

        resp = requests.post(
            url,
            data=b"",
            auth=(self.cfg.user, self.cfg.password) if self.cfg.user else None,
            timeout=30,
        )
        if resp.status_code >= 300:
            raise RuntimeError(f"clickhouse_http_select_failed status={resp.status_code} body={resp.text[:2000]}")

        out: list[dict[str, Any]] = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
        return out

    def wait_until_ready(self, timeout_s: int = 60) -> None:
        start = time.time()
        while time.time() - start < timeout_s:
            if self.ping():
                return
            time.sleep(2)
        raise TimeoutError("ClickHouse not ready")

