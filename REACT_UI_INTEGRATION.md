# 🎨 React UI Integration Guide

## Production-Ready SOC Dashboard API

Your Enterprise SOC now provides **complete, real-time data** for your React UI with **NO dummy/test data**.

---

## 🚀 Quick Start

### Base URL:
```
http://localhost:8088
```

### Primary Endpoint:
```
GET /ui/soc-dashboard?hours=24
```

---

## 📊 Complete API Response

```typescript
interface SOCDashboardResponse {
  timeRange: {
    start: string;      // ISO 8601
    end: string;        // ISO 8601
    hours: number;
  };
  
  stats: {
    totalEvents: number;
    criticalThreats: number;
    failedLogins: number;
    iamChanges: number;
    attackSources: number;
    eventsPerHour: number;
  };
  
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
    severity: 'critical' | 'high' | 'medium' | 'low';
    status: 'active';
  }>;
  
  aiDetectedAnomalies: Array<{
    id: string;
    timestamp: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    type: string;
    description: string;
    user: string;
    sourceIp: string;
    confidence: number;
    service: string;
    namespace: string;
  }>;
  
  networkFlow: {
    totalEvents: number;
    networkFlows: number;
    activeNodes: number;
    sankeyData: {
      nodes: Array<{
        id: number;
        name: string;
        layer: 'source' | 'device' | 'telemetry';
      }>;
      links: Array<{
        source: number;  // Node ID
        target: number;  // Node ID
        value: number;   // Flow volume
      }>;
    };
  };
  
  securityPosture: {
    overallScore: number;  // 0-100
    status: 'excellent' | 'good' | 'moderate' | 'poor';
    categories: {
      authentication: number;
      accessControl: number;
      threatDetection: number;
      networkSecurity: number;
      compliance: number;
      incidentResponse: number;
    };
  };
  
  iamChanges: Array<{
    timestamp: string;
    changedBy: string;
    action: string;
    resource: string;
    service: string;
  }>;
  
  networkTraffic: {
    inbound: number;
    outbound: number;
    blocked: number;
    timeline: Array<any>;
  };
  
  attackPatternHeatmap: {
    data: number[][];  // 7 days x 24 hours
    days: string[];    // ["Sun", "Mon", ...]
    maxValue: number;
  };
  
  systemStatus: 'operational' | 'degraded' | 'down';
  lastUpdated: string;
}
```

---

## 🎯 React Component Examples

### 1. Dashboard Container

```typescript
import { useState, useEffect } from 'react';

const EnterpriseDashboard = () => {
  const [dashboard, setDashboard] = useState<SOCDashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        const response = await fetch('http://localhost:8088/ui/soc-dashboard?hours=24');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        setDashboard(data);
        setError(null);
      } catch (err) {
        setError(err.message);
        console.error('Dashboard fetch failed:', err);
      } finally {
        setLoading(false);
      }
    };
    
    fetchDashboard();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchDashboard, 30000);
    return () => clearInterval(interval);
  }, []);
  
  if (loading) return <LoadingSpinner />;
  if (error) return <ErrorDisplay message={error} />;
  if (!dashboard) return null;
  
  return (
    <div className="enterprise-soc-dashboard">
      <Header 
        title="Enterprise SOC Dashboard"
        lastUpdated={dashboard.lastUpdated}
        status={dashboard.systemStatus}
      />
      
      <StatsBar stats={dashboard.stats} />
      
      <div className="dashboard-grid">
        <SecurityEventsTimeline data={dashboard.securityEventsTimeline} />
        <ThreatDistribution data={dashboard.threatDistribution} />
        <TopAttackSources sources={dashboard.topAttackSources} />
        <AttackPatternHeatmap heatmap={dashboard.attackPatternHeatmap} />
      </div>
      
      <NetworkFlowVisualization sankeyData={dashboard.networkFlow.sankeyData} />
      
      <div className="secondary-section">
        <AnomaliesTable anomalies={dashboard.aiDetectedAnomalies} />
        <SecurityPosture score={dashboard.securityPosture} />
        <IAMChangesTable changes={dashboard.iamChanges} />
        <NetworkTraffic traffic={dashboard.networkTraffic} />
      </div>
    </div>
  );
};
```

---

### 2. Security Events Timeline

```typescript
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';

const SecurityEventsTimeline = ({ data }) => {
  return (
    <div className="security-events-timeline">
      <h3>Security Events Timeline</h3>
      <LineChart width={800} height={300} data={data}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="timestamp" />
        <YAxis />
        <Tooltip />
        <Legend />
        <Line type="monotone" dataKey="critical_events" stroke="#ff0000" name="Critical" />
        <Line type="monotone" dataKey="warnings" stroke="#ffa500" name="Warnings" />
        <Line type="monotone" dataKey="failed_logins" stroke="#ff69b4" name="Failed Logins" />
        <Line type="monotone" dataKey="iam_changes" stroke="#0000ff" name="IAM Changes" />
      </LineChart>
    </div>
  );
};
```

---

### 3. Threat Distribution (Pie Chart)

```typescript
import { PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';

const ThreatDistribution = ({ data }) => {
  const chartData = [
    { name: 'Critical', value: data.critical, color: '#dc3545' },
    { name: 'High', value: data.high, color: '#fd7e14' },
    { name: 'Medium', value: data.medium, color: '#ffc107' },
    { name: 'Low', value: data.low, color: '#0dcaf0' },
  ].filter(item => item.value > 0);
  
  return (
    <div className="threat-distribution">
      <h3>Threat Distribution</h3>
      <PieChart width={400} height={300}>
        <Pie
          data={chartData}
          cx={200}
          cy={150}
          labelLine={false}
          label={({ name, value }) => `${name}: ${value}`}
          outerRadius={80}
          fill="#8884d8"
          dataKey="value"
        >
          {chartData.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.color} />
          ))}
        </Pie>
        <Tooltip />
        <Legend />
      </PieChart>
      
      <div className="threat-stats">
        <div className="stat critical">
          <span className="label">Critical</span>
          <span className="value">{data.critical}</span>
        </div>
        <div className="stat medium">
          <span className="label">Medium</span>
          <span className="value">{data.medium}</span>
        </div>
        <div className="stat low">
          <span className="label">Low</span>
          <span className="value">{data.low}</span>
        </div>
      </div>
    </div>
  );
};
```

---

### 4. Network Flow (Sankey Diagram)

```typescript
import { sankey, sankeyLinkHorizontal } from 'd3-sankey';
import { useEffect, useRef } from 'react';
import * as d3 from 'd3';

const NetworkFlowVisualization = ({ sankeyData }) => {
  const svgRef = useRef<SVGSVGElement>(null);
  
  useEffect(() => {
    if (!svgRef.current || !sankeyData) return;
    
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();
    
    const width = 1200;
    const height = 600;
    const margin = { top: 20, right: 20, bottom: 20, left: 20 };
    
    const sankeyGenerator = sankey()
      .nodeWidth(15)
      .nodePadding(10)
      .extent([[margin.left, margin.top], [width - margin.right, height - margin.bottom]]);
    
    const { nodes, links } = sankeyGenerator({
      nodes: sankeyData.nodes.map(d => ({ ...d })),
      links: sankeyData.links.map(d => ({ ...d }))
    });
    
    // Color scale by layer
    const colorScale = d3.scaleOrdinal()
      .domain(['source', 'device', 'telemetry'])
      .range(['#ff6b6b', '#4ecdc4', '#45b7d1']);
    
    // Draw links
    svg.append('g')
      .attr('class', 'links')
      .selectAll('path')
      .data(links)
      .enter().append('path')
        .attr('d', sankeyLinkHorizontal())
        .attr('stroke', '#888')
        .attr('stroke-width', d => Math.max(1, d.width))
        .attr('fill', 'none')
        .attr('opacity', 0.5)
        .on('mouseover', function() { d3.select(this).attr('opacity', 0.8); })
        .on('mouseout', function() { d3.select(this).attr('opacity', 0.5); });
    
    // Draw nodes
    const node = svg.append('g')
      .attr('class', 'nodes')
      .selectAll('g')
      .data(nodes)
      .enter().append('g');
    
    node.append('rect')
      .attr('x', d => d.x0)
      .attr('y', d => d.y0)
      .attr('height', d => d.y1 - d.y0)
      .attr('width', d => d.x1 - d.x0)
      .attr('fill', d => colorScale(d.layer))
      .attr('stroke', '#000')
      .attr('stroke-width', 0.5);
    
    node.append('text')
      .attr('x', d => d.x0 < width / 2 ? d.x1 + 6 : d.x0 - 6)
      .attr('y', d => (d.y1 + d.y0) / 2)
      .attr('dy', '0.35em')
      .attr('text-anchor', d => d.x0 < width / 2 ? 'start' : 'end')
      .text(d => d.name)
      .style('font-size', '10px');
    
  }, [sankeyData]);
  
  return (
    <div className="network-flow-visualization">
      <h3>Network Flow Visualization</h3>
      <div className="stats-row">
        <div className="stat">
          <label>Total Events</label>
          <span>{sankeyData.nodes.length > 0 ? 
            sankeyData.links.reduce((sum, link) => sum + link.value, 0) : 0}</span>
        </div>
        <div className="stat">
          <label>Active Nodes</label>
          <span>{sankeyData.nodes.length}</span>
        </div>
        <div className="stat">
          <label>Network Flows</label>
          <span>{sankeyData.links.length}</span>
        </div>
      </div>
      <svg ref={svgRef} width={1200} height={600}></svg>
    </div>
  );
};
```

---

### 5. AI-Detected Anomalies Table

```typescript
const AnomaliesTable = ({ anomalies }) => {
  const getSeverityBadge = (severity: string) => {
    const colors = {
      critical: 'bg-red-600',
      high: 'bg-orange-500',
      medium: 'bg-yellow-500',
      low: 'bg-blue-500'
    };
    return (
      <span className={`px-2 py-1 rounded text-white text-xs ${colors[severity]}`}>
        {severity.toUpperCase()}
      </span>
    );
  };
  
  return (
    <div className="anomalies-table">
      <h3>🤖 AI-Detected Anomalies</h3>
      <p className="subtitle">Machine learning powered threat analysis</p>
      
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Type</th>
            <th>Description</th>
            <th>User</th>
            <th>Source IP</th>
            <th>Confidence</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {anomalies.map((anomaly) => (
            <tr key={anomaly.id}>
              <td>{getSeverityBadge(anomaly.severity)}</td>
              <td>{anomaly.type}</td>
              <td>{anomaly.description}</td>
              <td>{anomaly.user}</td>
              <td>{anomaly.sourceIp}</td>
              <td>
                <div className="confidence-bar">
                  <div 
                    className="fill" 
                    style={{ width: `${anomaly.confidence}%` }}
                  />
                  <span>{anomaly.confidence}%</span>
                </div>
              </td>
              <td>{new Date(anomaly.timestamp).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
```

---

### 6. Security Posture Score

```typescript
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis } from 'recharts';

const SecurityPosture = ({ score }) => {
  const radarData = [
    { category: 'Authentication', value: score.categories.authentication },
    { category: 'Access Control', value: score.categories.accessControl },
    { category: 'Threat Detection', value: score.categories.threatDetection },
    { category: 'Incident Response', value: score.categories.incidentResponse },
    { category: 'Network Security', value: score.categories.networkSecurity },
    { category: 'Compliance', value: score.categories.compliance },
  ];
  
  const getStatusColor = (status: string) => {
    const colors = {
      excellent: '#28a745',
      good: '#17a2b8',
      moderate: '#ffc107',
      poor: '#dc3545'
    };
    return colors[status] || '#6c757d';
  };
  
  return (
    <div className="security-posture">
      <h3>🛡️ Security Posture Score</h3>
      
      <div className="overall-score">
        <div 
          className="score-circle" 
          style={{ borderColor: getStatusColor(score.status) }}
        >
          <span className="value">{score.overallScore}</span>
          <span className="label">/100</span>
        </div>
        <div className="status" style={{ color: getStatusColor(score.status) }}>
          {score.status.toUpperCase()}
        </div>
      </div>
      
      <RadarChart width={500} height={400} data={radarData}>
        <PolarGrid />
        <PolarAngleAxis dataKey="category" />
        <PolarRadiusAxis angle={90} domain={[0, 100]} />
        <Radar 
          name="Security Score" 
          dataKey="value" 
          stroke="#8884d8" 
          fill="#8884d8" 
          fillOpacity={0.6} 
        />
      </RadarChart>
      
      <div className="categories">
        {Object.entries(score.categories).map(([key, value]) => (
          <div key={key} className="category">
            <span className="name">{key.replace(/([A-Z])/g, ' $1').trim()}</span>
            <div className="bar">
              <div className="fill" style={{ width: `${value}%` }} />
            </div>
            <span className="value">{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
```

---

### 7. Attack Pattern Heatmap

```typescript
const AttackPatternHeatmap = ({ heatmap }) => {
  const getColor = (value: number) => {
    if (value === 0) return '#f0f0f0';
    const intensity = Math.min(value / heatmap.maxValue, 1);
    return `rgba(220, 53, 69, ${intensity})`;
  };
  
  return (
    <div className="attack-pattern-heatmap">
      <h3>📅 Attack Pattern Heatmap</h3>
      <p className="subtitle">Activity pattern over the last 7 days • Darker colors indicate higher attack volume</p>
      
      <div className="heatmap-grid">
        <div className="day-labels">
          {heatmap.days.map((day) => (
            <div key={day} className="day-label">{day}</div>
          ))}
        </div>
        
        <div className="hours-grid">
          {heatmap.data.map((dayData, dayIndex) => (
            <div key={dayIndex} className="day-row">
              {dayData.map((value, hourIndex) => (
                <div
                  key={`${dayIndex}-${hourIndex}`}
                  className="hour-cell"
                  style={{ backgroundColor: getColor(value) }}
                  title={`${heatmap.days[dayIndex]} ${hourIndex}:00 - ${value} attacks`}
                >
                  {value > 0 && value}
                </div>
              ))}
            </div>
          ))}
        </div>
        
        <div className="hour-labels">
          {Array.from({ length: 24 }, (_, i) => (
            <div key={i} className="hour-label">{i < 10 ? `0${i}` : i}</div>
          ))}
        </div>
      </div>
    </div>
  );
};
```

---

## 🔄 Auto-Refresh Hook

```typescript
import { useState, useEffect, useCallback } from 'react';

export const useDashboardData = (refreshIntervalMs: number = 30000) => {
  const [data, setData] = useState<SOCDashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const fetchData = useCallback(async () => {
    try {
      const response = await fetch('http://localhost:8088/ui/soc-dashboard?hours=24');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const json = await response.json();
      setData(json);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);
  
  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, refreshIntervalMs);
    return () => clearInterval(interval);
  }, [fetchData, refreshIntervalMs]);
  
  return { data, loading, error, refetch: fetchData };
};

// Usage
const MyComponent = () => {
  const { data, loading, error } = useDashboardData(30000);
  
  if (loading) return <LoadingSpinner />;
  if (error) return <ErrorDisplay message={error} />;
  
  return <Dashboard data={data} />;
};
```

---

## 🎨 CSS Styling Example

```css
.enterprise-soc-dashboard {
  background: #0f1419;
  color: #ffffff;
  min-height: 100vh;
  padding: 2rem;
}

.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 1.5rem;
  margin: 2rem 0;
}

.stat {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  border-radius: 12px;
  padding: 1.5rem;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
}

.anomalies-table table {
  width: 100%;
  border-collapse: collapse;
  background: #1a1f2e;
  border-radius: 8px;
  overflow: hidden;
}

.anomalies-table th {
  background: #2d3748;
  padding: 1rem;
  text-align: left;
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.75rem;
  letter-spacing: 0.05em;
}

.anomalies-table td {
  padding: 1rem;
  border-top: 1px solid #2d3748;
}

.confidence-bar {
  position: relative;
  width: 100px;
  height: 20px;
  background: #2d3748;
  border-radius: 4px;
  overflow: hidden;
}

.confidence-bar .fill {
  position: absolute;
  top: 0;
  left: 0;
  height: 100%;
  background: linear-gradient(90deg, #4caf50, #8bc34a);
  transition: width 0.3s ease;
}

.confidence-bar span {
  position: relative;
  z-index: 1;
  font-size: 0.75rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
}
```

---

## ✅ Data Quality Verification

```typescript
// Verify no dummy data
const verifyDataQuality = (dashboard: SOCDashboardResponse) => {
  const dummyPatterns = [
    /test@/i,
    /dummy/i,
    /example\.com/i,
    /fake/i,
    /192\.0\.2\./  // TEST-NET
  ];
  
  const hasDummyData = (text: string) =>
    dummyPatterns.some(pattern => pattern.test(text));
  
  const issues = [];
  
  // Check anomalies
  dashboard.aiDetectedAnomalies.forEach(anomaly => {
    if (hasDummyData(anomaly.user)) {
      issues.push(`Dummy user detected: ${anomaly.user}`);
    }
  });
  
  // Check attack sources
  dashboard.topAttackSources.forEach(source => {
    if (hasDummyData(source.sourceIp)) {
      issues.push(`Dummy IP detected: ${source.sourceIp}`);
    }
  });
  
  if (issues.length > 0) {
    console.warn('Data quality issues:', issues);
  } else {
    console.log('✅ All data verified as production-ready');
  }
  
  return issues.length === 0;
};
```

---

## 📱 Mobile Responsive

```typescript
import { useMediaQuery } from 'react-responsive';

const ResponsiveDashboard = ({ data }) => {
  const isMobile = useMediaQuery({ maxWidth: 768 });
  const isTablet = useMediaQuery({ minWidth: 769, maxWidth: 1024 });
  
  return (
    <div className={`dashboard ${isMobile ? 'mobile' : isTablet ? 'tablet' : 'desktop'}`}>
      {/* Adjust grid layout based on screen size */}
      <div className={`grid-cols-${isMobile ? 1 : isTablet ? 2 : 3}`}>
        {/* Components */}
      </div>
    </div>
  );
};
```

---

**🎉 Your React UI is ready to integrate with production SOC data!**

All endpoints return real data with proper structure - no dummy/test data anywhere!
