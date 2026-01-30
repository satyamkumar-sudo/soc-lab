# Frontend API Mapping Documentation

## API Endpoint
```
GET https://192.168.50.236:8443/ui/mock-data?hours=24
```

## Complete Response Structure

```typescript
interface APIResponse {
  // Time context
  timeRange: {
    start: string;        // ISO-8601 timestamp
    end: string;          // ISO-8601 timestamp
    hours: number;        // Time window in hours
  };
  
  // Summary statistics
  stats: {
    totalEvents: number;
    criticalThreats: number;
    failedLogins: number;
    iamChanges: number;
    attackSources: number;
    eventsPerHour: number;
  };
  
  // === FRONTEND COMPONENT DATA ===
  
  // For TimelineChart & D3SankeyDiagram
  logs: Array<{
    id: string;
    timestamp: string;     // ISO-8601
    type: string;          // "login_failure" | "login_success" | "iam_change" | "network_event"
    sourceIp: string;      // e.g., "192.168.1.100"
    user: string;
    method: string;
    service: string;
    namespace: string;
    severity: string;      // "critical" | "error" | "warning" | "info"
    country: string;
    message: string;
  }>;
  
  // For TopAttackersChart & ThreatPieChart
  anomalies: Array<{
    id: string;
    timestamp: string;
    severity: string;      // "critical" | "high" | "medium" | "low"
    type: string;          // "ml_anomaly", "brute_force", etc.
    description: string;
    user: string;
    sourceIp: string;
    confidence: number;
    service: string;
    namespace: string;
  }>;
  
  // For D3SankeyDiagram (alternative format)
  networkFlow: {
    totalEvents: number;
    networkFlows: number;
    activeNodes: number;
    sankeyData: {
      nodes: Array<{
        id: number;
        name: string;
        layer: string;     // "source" | "device" | "telemetry"
      }>;
      links: Array<{
        source: number;    // Node ID
        target: number;    // Node ID
        value: number;     // Flow count
      }>;
    };
  };
  
  // IAM activity timeline
  iamChanges: Array<{
    timestamp: string;
    changedBy: string;
    action: string;
    resource: string;
    service: string;
  }>;
  
  // Additional dashboard data
  securityEventsTimeline: Array<{
    timestamp: string;
    critical_events: number;
    warnings: number;
    failed_logins: number;
    iam_changes: number;
  }>;
  
  threatDistribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  
  topAttackSources: Array<{
    sourceIp: string;
    country: string;
    attacks: number;
    servicesTargeted: number;
    severity: string;
    status: string;
  }>;
  
  securityPosture: {
    overallScore: number;
    status: string;
    categories: {
      authentication: number;
      accessControl: number;
      threatDetection: number;
      networkSecurity: number;
      compliance: number;
      incidentResponse: number;
    };
  };
  
  networkTraffic: {
    inbound: number;
    outbound: number;
    blocked: number;
    timeline: Array<any>;
  };
  
  attackPatternHeatmap: {
    data: number[][];      // 7x24 matrix
    days: string[];
    maxValue: number;
  };
  
  systemStatus: string;
  lastUpdated: string;
}
```

---

## Component Mapping

### 1. TopAttackersChart
**File:** `TopAttackersChart.jsx`

**Required Data:**
```javascript
const { anomalies, logs } = apiResponse;

// Uses:
// - anomalies[].sourceIp
// - anomalies[].severity ("critical", "medium", "low")
// - logs[] where type === "login_failure"
```

**API Fields Used:**
- ✅ `anomalies` array
- ✅ `logs` array (filtered by `type === "login_failure"`)

**Example:**
```javascript
fetch('https://192.168.50.236:8443/ui/mock-data?hours=24')
  .then(res => res.json())
  .then(data => {
    return <TopAttackersChart 
      anomalies={data.anomalies} 
      logs={data.logs} 
    />;
  });
```

---

### 2. ThreatPieChart
**File:** `ThreatPieChart.jsx`

**Required Data:**
```javascript
const { anomalies } = apiResponse;

// Uses:
// - anomalies[].severity ("critical", "medium", "low")
```

**API Fields Used:**
- ✅ `anomalies` array

**Example:**
```javascript
<ThreatPieChart anomalies={data.anomalies} />
```

**Data Processing:**
- Counts anomalies by severity level
- Displays pie chart with 3 segments (critical, medium, low)
- Shows stats below chart

---

### 3. TimelineChart
**File:** `TimelineChart.jsx`

**Required Data:**
```javascript
const { logs } = apiResponse;

// Uses:
// - logs[].timestamp
// - logs[].type ("login_failure", "iam_change", "anomaly")
```

**API Fields Used:**
- ✅ `logs` array

**Example:**
```javascript
<TimelineChart logs={data.logs} />
```

**Data Processing:**
- Groups logs into hourly buckets (last 24 hours)
- Counts by type:
  - `failed_logins`: where `type === "login_failure"`
  - `iam_changes`: where `type === "iam_change"`
  - `anomalies`: where `type === "anomaly"`

---

### 4. D3SankeyDiagram
**File:** `D3SankeyDiagram.jsx`

**Required Data:**
```javascript
const { logs } = apiResponse;

// Uses:
// - logs[].sourceIp
// - logs[].type
```

**API Fields Used:**
- ✅ `logs` array
- ✅ `networkFlow.sankeyData` (alternative, pre-calculated)

**Example:**
```javascript
<D3SankeyDiagram logs={data.logs} />
```

**Data Processing:**
- Takes top 10 IPs by frequency
- Creates 3-layer flow:
  1. **Source Layer**: IP addresses
  2. **Device Layer**: device types (admin-console, firewall, workstation, server, router)
  3. **Telemetry Layer**: log types (security-logs, access-logs, audit-logs, network-logs)

**Mapping Logic:**
```javascript
// Device Type Mapping
if (log.type === 'iam_change') → 'admin-console'
if (log.type === 'login_failure') → 'firewall'
if (sourceIp.startsWith('192.168')) → 'workstation'
if (sourceIp.startsWith('10.')) → 'server'
else → 'router'

// Telemetry Type Mapping
if (log.type === 'login_failure') → 'security-logs'
if (log.type === 'login_success') → 'access-logs'
if (log.type === 'iam_change') → 'audit-logs'
else → 'network-logs'
```

---

## Sample API Response

```json
{
  "timeRange": {
    "start": "2026-01-30T05:27:40Z",
    "end": "2026-01-30T11:27:40Z",
    "hours": 6
  },
  "stats": {
    "totalEvents": 334917,
    "criticalThreats": 9561,
    "failedLogins": 5321,
    "iamChanges": 0,
    "attackSources": 2,
    "eventsPerHour": 2.9
  },
  "logs": [
    {
      "id": "log_0",
      "timestamp": "2026-01-30 11:26:59",
      "type": "network_event",
      "sourceIp": "35.187.171.73",
      "user": "unknown",
      "method": "GET",
      "service": "fury",
      "namespace": "apps",
      "severity": "info",
      "country": "Unknown",
      "message": "Received request..."
    }
  ],
  "anomalies": [
    {
      "id": "anomaly_0_1738324019",
      "timestamp": "2026-01-30 11:26:59",
      "severity": "low",
      "type": "ml_anomaly",
      "description": "Anomalous behavior detected",
      "user": "service-account@fury",
      "sourceIp": "35.187.171.73",
      "confidence": 85,
      "service": "fury",
      "namespace": "apps"
    }
  ],
  "networkFlow": {
    "totalEvents": 5000,
    "networkFlows": 45,
    "activeNodes": 77,
    "sankeyData": {
      "nodes": [
        {"id": 0, "name": "35.187.171.73", "layer": "source"},
        {"id": 1, "name": "fury", "layer": "device"},
        {"id": 2, "name": "network-logs", "layer": "telemetry"}
      ],
      "links": [
        {"source": 0, "target": 1, "value": 1523},
        {"source": 1, "target": 2, "value": 1523}
      ]
    }
  },
  "iamChanges": [],
  "securityEventsTimeline": [
    {
      "timestamp": "2026-01-30 05:00:00",
      "critical_events": 245,
      "warnings": 1123,
      "failed_logins": 89,
      "iam_changes": 0
    }
  ],
  "threatDistribution": {
    "critical": 98,
    "high": 82,
    "medium": 200,
    "low": 11931
  },
  "topAttackSources": [
    {
      "sourceIp": "35.187.171.73",
      "country": "Unknown",
      "attacks": 9458,
      "servicesTargeted": 1,
      "severity": "critical",
      "status": "active"
    }
  ],
  "securityPosture": {
    "overallScore": 58,
    "status": "moderate",
    "categories": {
      "authentication": 70,
      "accessControl": 60,
      "threatDetection": 43,
      "networkSecurity": 50,
      "compliance": 90,
      "incidentResponse": 40
    }
  },
  "networkTraffic": {
    "inbound": 325356,
    "outbound": 325356,
    "blocked": 9561,
    "timeline": []
  },
  "attackPatternHeatmap": {
    "data": [[0,0,0,...], [15,23,45,...], ...],
    "days": ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
    "maxValue": 1523
  },
  "systemStatus": "operational",
  "lastUpdated": "2026-01-30T11:27:40Z"
}
```

---

## React Integration Example

```javascript
import React, { useState, useEffect } from 'react';
import TopAttackersChart from './TopAttackersChart';
import ThreatPieChart from './ThreatPieChart';
import TimelineChart from './TimelineChart';
import D3SankeyDiagram from './D3SankeyDiagram';

const Dashboard = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch(
          'https://192.168.50.236:8443/ui/mock-data?hours=24'
        );
        const json = await response.json();
        setData(json);
      } catch (error) {
        console.error('Failed to fetch SOC data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <div>Loading...</div>;
  if (!data) return <div>Error loading data</div>;

  return (
    <div className="dashboard-grid">
      <div className="chart-container">
        <h2>Top Attack Sources</h2>
        <TopAttackersChart 
          anomalies={data.anomalies} 
          logs={data.logs} 
        />
      </div>

      <div className="chart-container">
        <h2>Threat Distribution</h2>
        <ThreatPieChart anomalies={data.anomalies} />
      </div>

      <div className="chart-container">
        <h2>Security Events Timeline</h2>
        <TimelineChart logs={data.logs} />
      </div>

      <div className="chart-container">
        <h2>Network Flow</h2>
        <D3SankeyDiagram logs={data.logs} />
      </div>
    </div>
  );
};

export default Dashboard;
```

---

## Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | integer | 24 | Time window in hours (1-168) |
| `log_limit` | integer | 500 | Max logs to return (50-5000) |
| `anomaly_limit` | integer | 50 | Max anomalies (1-200) |
| `service` | string | null | Filter by service name |
| `namespace` | string | null | Filter by namespace |

**Examples:**
```
# Last 6 hours
GET /ui/mock-data?hours=6

# Specific service
GET /ui/mock-data?hours=24&service=fury

# More logs
GET /ui/mock-data?hours=12&log_limit=1000
```

---

## Data Freshness

- **Real-time ingestion**: Logs ingested every 5 minutes via Airflow
- **API response time**: < 2 seconds
- **Recommended refresh rate**: 30 seconds
- **Max time window**: 7 days (168 hours)

---

## Error Handling

```javascript
try {
  const response = await fetch(API_URL);
  
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  
  const data = await response.json();
  
  // Validate required fields
  if (!data.logs || !data.anomalies) {
    throw new Error('Missing required fields');
  }
  
  return data;
} catch (error) {
  console.error('API Error:', error);
  // Show fallback UI or cached data
}
```

---

## Production Checklist

- ✅ Use HTTPS endpoint
- ✅ Handle loading states
- ✅ Implement error boundaries
- ✅ Add retry logic for failed requests
- ✅ Cache data with React Query or SWR
- ✅ Implement auto-refresh (30s recommended)
- ✅ Add request timeout (10s)
- ✅ Validate response schema
- ✅ Show empty states when no data
- ✅ Add skeleton loaders

---

## Support

For issues or questions:
- Check API logs: `docker compose logs soc-api`
- Verify ClickHouse: `docker compose ps clickhouse`
- Test endpoint: `curl -sk https://192.168.50.236:8443/ui/mock-data?hours=1`
