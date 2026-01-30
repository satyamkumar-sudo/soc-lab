# API Response Format

## Endpoint: `/ui/mock-data`

Returns SOC analytics data in a format compatible with the React frontend.

### Request

```bash
GET /ui/mock-data?hours=24&log_limit=500&anomaly_limit=50
```

**Query Parameters:**
- `hours` (int): Time window in hours (default: 24)
- `log_limit` (int): Maximum logs to return (default: 500)
- `anomaly_limit` (int): Maximum anomalies to return (default: 50)

### Response Format

```typescript
interface ApiResponse {
  logs: Log[];
  anomalies: Anomaly[];
  iamChanges: IamChange[];
  networkFlow: NetworkFlow;
  topAttackers: Attacker[];
  threatDistribution: ThreatDistribution[];
  // ... other metrics
}

interface Log {
  id: string;                    // Unique log identifier
  type: LogType;                 // "login_failure" | "login_success" | "network_scan" | "iam_change" | "network_event"
  sourceIp: string;              // Source IP address
  timestamp: string;             // ISO 8601 format: "2026-01-30T12:00:00Z"
  user?: string;                 // Username or identity (optional)
  geo?: string;                  // Country code (optional)
  hostname?: string;             // Pod or hostname (optional)
  targetIp?: string;             // Target IP for lateral movement (optional)
  action?: string;               // IAM action type (optional)
  vpn?: boolean;                 // VPN connection flag (optional)
  device?: string;               // Device or service name (optional)
  _metadata?: {                  // Additional metadata for debugging
    severity: string;
    service: string;
    namespace: string;
    status_code: number;
  };
}

type LogType = 
  | "login_failure"    // Failed authentication attempts
  | "login_success"    // Successful logins
  | "network_scan"     // Port scans, network probes
  | "iam_change"       // IAM/permission changes
  | "network_event";   // General network activity
```

### Example Response

```json
{
  "logs": [
    {
      "id": "123-1706616000",
      "type": "login_failure",
      "sourceIp": "203.0.113.45",
      "user": "admin",
      "geo": "RU",
      "timestamp": "2026-01-30T09:15:00Z",
      "_metadata": {
        "severity": "error",
        "service": "auth-service",
        "namespace": "prod",
        "status_code": 401
      }
    },
    {
      "id": "124-1706616060",
      "type": "network_scan",
      "sourceIp": "192.168.1.34",
      "hostname": "EMP-LAP-034",
      "device": "workstation",
      "timestamp": "2026-01-30T10:05:00Z",
      "_metadata": {
        "severity": "warning",
        "service": "network-monitor",
        "namespace": "security"
      }
    },
    {
      "id": "125-1706616120",
      "type": "iam_change",
      "sourceIp": "10.1.1.9",
      "user": "cloud-admin",
      "action": "policy_attached",
      "timestamp": "2026-01-30T12:02:00Z",
      "_metadata": {
        "severity": "info",
        "service": "iam-service",
        "namespace": "admin"
      }
    }
  ],
  "anomalies": [...],
  "networkFlow": {
    "sankeyData": {
      "nodes": [...],
      "links": [...]
    }
  }
}
```

### Log Type Detection Logic

The API automatically infers `type` based on log characteristics:

1. **login_failure**: 
   - Message contains: "failed", "wrong", "denied", "unauthorized", "invalid"
   - AND contains: "login", "auth", "password", "signin"

2. **login_success**:
   - Message contains: "login", "auth", "authenticated"
   - OR status code 200-299 with auth-related content

3. **iam_change**:
   - Method/message contains: "iam", "policy", "role", "permission", "grant"

4. **network_scan**:
   - Message contains: "scan", "probe", "discovery", "enumeration", "port"

5. **network_event** (default):
   - All other logs

### IAM Action Types

For `type: "iam_change"`, the `action` field can be:
- `policy_attached` - IAM policy was attached
- `role_escalated` - Role elevation detected
- `resource_created` - New resource created
- `resource_deleted` - Resource deleted
- `permission_changed` - General permission change

### Integration Example

```javascript
// React Component
import { useEffect, useState } from 'react';

function Dashboard() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch('https://localhost:8443/ui/mock-data?hours=24')
      .then(res => res.json())
      .then(setData);
  }, []);

  if (!data) return <div>Loading...</div>;

  return (
    <div>
      <h2>Logs ({data.logs.length})</h2>
      {data.logs.map(log => (
        <div key={log.id} className={`log-${log.type}`}>
          <span>{log.timestamp}</span>
          <span>{log.type}</span>
          <span>{log.sourceIp}</span>
          {log.user && <span>{log.user}</span>}
        </div>
      ))}
    </div>
  );
}
```

### Filtering

All logs respect the query parameters:
- Time window: Only logs within specified hours
- Service filter: `&service=auth-service`
- Namespace filter: `&namespace=prod`

### Performance

- Response time: < 500ms for 500 logs
- Data freshness: Real-time (30s Grafana refresh)
- Caching: LLM responses cached, raw data not cached

---

## Sankey Diagram API

### Option 1: Inside `/ui/mock-data`

The full dashboard response includes Sankey data under `networkFlow.sankeyData`:

```json
{
  "networkFlow": {
    "totalEvents": 1234,
    "networkFlows": 5,
    "activeNodes": 12,
    "sankeyData": {
      "nodes": [
        { "id": 0, "name": "192.168.1.1", "layer": "source" },
        { "id": 1, "name": "api-gateway", "layer": "device" },
        { "id": 2, "name": "access-logs", "layer": "telemetry" }
      ],
      "links": [
        { "source": 0, "target": 1, "value": 150 },
        { "source": 1, "target": 2, "value": 150 }
      ]
    }
  }
}
```

- **Nodes**: `{ id, name, layer }` — `layer` is `"source"` (IP), `"device"` (service/gateway), or `"telemetry"` (log type).
- **Links**: `{ source, target, value }` — `source`/`target` are node `id`s; `value` is flow count.

### Option 2: Dedicated endpoint `/ui/network-flow`

Pre-aggregated Sankey data only (for D3/Recharts Sankey):

```bash
GET /ui/network-flow?hours=24&top_ips=20&service=fury&namespace=apps
```

**Query parameters:**

| Param      | Type | Default | Description                    |
|-----------|------|---------|--------------------------------|
| `hours`   | int  | 24      | Time window in hours           |
| `top_ips` | int  | 20      | Top N source IPs to include    |
| `service` | str  | —       | Filter by service (e.g. fury)  |
| `namespace` | str | —     | Filter by namespace            |

**Response:**

```json
{
  "nodes": [
    { "id": 0, "name": "10.0.0.5", "category": "source" },
    { "id": 1, "name": "istio-gateway", "category": "device" },
    { "id": 2, "name": "security-logs", "category": "telemetry" }
  ],
  "links": [
    { "source": 0, "target": 1, "value": 42 },
    { "source": 1, "target": 2, "value": 42 }
  ],
  "metadata": {
    "total_events": 5000,
    "network_flows": 15,
    "active_nodes": 12,
    "top_ips": 20
  }
}
```

- **Nodes**: `{ id, name, category }` — `category` is `"source"`, `"device"`, or `"telemetry"`.
- **Links**: `{ source, target, value }` — same as above.

Use `networkFlow.sankeyData` from `/ui/mock-data` when you need one payload with logs + Sankey. Use `/ui/network-flow` when you only need Sankey (e.g. D3SankeyDiagram) or want to filter by `service`/`namespace`/`top_ips`.

---

## Frontend: How to Get Alerts

The frontend can get alerts in two ways: **REST** (historical/list) and **WebSocket** (real-time stream).

### Base URLs

- **Direct API (dev):** `http://localhost:8088` → REST: `http://localhost:8088/api/alerts`, WS: `ws://localhost:8088/ws/alerts`
- **Via gateway (HTTPS/mTLS):** `https://localhost:8443` → REST: `https://localhost:8443/api/alerts`, WS: `wss://localhost:8443/ws/alerts`

### 1. REST – List and filter alerts

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/alerts` | GET | List alerts with pagination and filters |
| `/api/alerts/{id}` | GET | Get a single alert by ID |
| `/api/alerts/stats` | GET | Counts by risk level, channel, timeline |

**Examples:**

```bash
# Last 50 alerts (default)
GET /api/alerts

# Filter by risk level
GET /api/alerts?risk_level=critical&limit=100

# Time range (ISO-8601)
GET /api/alerts?from_date=2026-01-29T00:00:00Z&to_date=2026-01-30T00:00:00Z

# Pagination
GET /api/alerts?limit=20&offset=40

# One alert
GET /api/alerts/550e8400-e29b-41d4-a716-446655440000

# Stats (last 24h by default)
GET /api/alerts/stats
```

**List response shape:**

```json
{
  "total": 42,
  "limit": 50,
  "offset": 0,
  "count": 50,
  "alerts": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "created_at": "2026-01-30T10:00:00",
      "fingerprint": "abc123",
      "channel": "slack",
      "risk_level": "critical",
      "title": "High error rate detected",
      "message": "Service X exceeded threshold",
      "payload": { "service": "X", "error_rate": 0.15 },
      "sent": 1
    }
  ]
}
```

### 2. WebSocket – Real-time alert stream

Connect once; the server pushes new alerts as they are generated.

```javascript
const base = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const host = 'localhost:8443'; // or 8088 for direct API
const ws = new WebSocket(`${base}//${host}/ws/alerts`);

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'alert') {
    console.log('New alert:', data.data);
    // data.data: { id, created_at, risk_level, title, message, payload, ... }
  }
  if (data.type === 'connected') {
    console.log(data.message);
  }
};

// Optional: keep-alive
setInterval(() => { if (ws.readyState === 1) ws.send('ping'); }, 30000);
```

**Message types from server:**

- `connected` – right after connection (includes `message`, `timestamp`)
- `alert` – new alert (`data` = full alert object)
- `pong` – response to client `ping`

**Full alerts API doc:** [ALERTS_API.md](ALERTS_API.md)

---

**For complete API documentation, see:** [SOC_API_ENDPOINTS.md](SOC_API_ENDPOINTS.md)
