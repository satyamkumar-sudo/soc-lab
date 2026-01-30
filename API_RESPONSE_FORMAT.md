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

**For complete API documentation, see:** [SOC_API_ENDPOINTS.md](SOC_API_ENDPOINTS.md)
