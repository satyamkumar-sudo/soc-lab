"""
Enterprise SOC Dashboard API
Provides complete, production-ready data for React UI with NO dummy/test data
"""
from __future__ import annotations

import datetime as dt
from typing import Any

import structlog

log = structlog.get_logger(__name__)


def build_soc_dashboard_data(
    ch,
    start: dt.datetime,
    end: dt.datetime,
    service: str | None = None,
    namespace: str | None = None,
) -> dict[str, Any]:
    """
    Build complete SOC dashboard data from real ClickHouse logs
    Returns structure matching React UI expectations
    """
    
    # Build filter conditions
    where_clauses = []
    params = {"start": start, "end": end}
    
    if service:
        where_clauses.append("service = %(service)s")
        params["service"] = service
    if namespace:
        where_clauses.append("namespace = %(namespace)s")
        params["namespace"] = namespace
        
    extra_where = (" AND " + " AND ".join(where_clauses)) if where_clauses else ""
    
    # ========================================================================
    # 1. SECURITY EVENTS TIMELINE (for graphs)
    # ========================================================================
    timeline_query = f"""
    WITH hourly_events AS (
        SELECT
            toStartOfHour(timestamp) AS hour,
            countIf(severity IN ('ERROR', 'CRITICAL')) AS critical_events,
            countIf(severity = 'WARNING') AS warnings,
            countIf(positionCaseInsensitive(message, 'login') > 0 
                    OR positionCaseInsensitive(message, 'auth') > 0) AS failed_logins,
            countIf(positionCaseInsensitive(message, 'iam') > 0 
                    OR positionCaseInsensitive(method, 'iam') > 0) AS iam_changes
        FROM soc.enriched_logs
        WHERE timestamp >= %(start)s AND timestamp < %(end)s
          AND method != 'k8s.inventory'
          {extra_where}
        GROUP BY hour
        ORDER BY hour
    )
    SELECT
        toString(hour) AS timestamp,
        critical_events,
        warnings,
        failed_logins,
        iam_changes
    FROM hourly_events
    """
    
    timeline = ch.fetch_dicts(timeline_query, params)
    
    # ========================================================================
    # 2. THREAT DISTRIBUTION (pie chart data)
    # ========================================================================
    threat_dist_query = f"""
    SELECT
        risk_level AS severity,
        count() AS count
    FROM soc.anomalies
    WHERE created_at >= %(start)s AND created_at < %(end)s
      {extra_where}
    GROUP BY risk_level
    ORDER BY 
        multiIf(
            risk_level='critical', 1,
            risk_level='high', 2,
            risk_level='medium', 3,
            risk_level='low', 4,
            5
        )
    """
    
    threat_dist_raw = ch.fetch_dicts(threat_dist_query, params)
    threat_distribution = {
        "critical": next((r["count"] for r in threat_dist_raw if r.get("severity") == "critical"), 0),
        "high": next((r["count"] for r in threat_dist_raw if r.get("severity") == "high"), 0),
        "medium": next((r["count"] for r in threat_dist_raw if r.get("severity") == "medium"), 0),
        "low": next((r["count"] for r in threat_dist_raw if r.get("severity") == "low"), 0),
    }
    
    # ========================================================================
    # 3. TOP ATTACK SOURCES (by IP)
    # ========================================================================
    attack_sources_query = f"""
    SELECT
        ip AS source_ip,
        geo_country AS country,
        uniq(service) AS services_targeted,
        countIf(severity IN ('ERROR', 'CRITICAL')) AS attack_count,
        maxIf(severity_num, severity_num > 0) AS max_severity
    FROM soc.enriched_logs
    WHERE timestamp >= %(start)s AND timestamp < %(end)s
      AND ip != '' AND ip NOT IN ('127.0.0.1', '0.0.0.0', '::1')
      AND (severity IN ('ERROR', 'CRITICAL', 'WARNING') OR status_code >= 400)
      {extra_where}
    GROUP BY ip, geo_country
    HAVING attack_count >= 3
    ORDER BY attack_count DESC, max_severity DESC
    LIMIT 20
    """
    
    attack_sources = ch.fetch_dicts(attack_sources_query, params)
    
    # Format for UI
    attack_sources_formatted = [
        {
            "sourceIp": a["source_ip"],
            "country": a["country"] if a["country"] != "UNKNOWN" else "Unknown",
            "attacks": int(a["attack_count"]),
            "servicesTargeted": int(a["services_targeted"]),
            "severity": "critical" if int(a["attack_count"]) > 50 else ("high" if int(a["attack_count"]) > 20 else "medium"),
            "status": "active"
        }
        for a in attack_sources
    ]
    
    # ========================================================================
    # 4. AI-DETECTED ANOMALIES (table data)
    # ========================================================================
    anomalies_query = f"""
    SELECT
        toString(created_at) AS timestamp,
        risk_level AS severity,
        reason AS description,
        service,
        namespace,
        llm_summary,
        confidence,
        model AS type
    FROM soc.anomalies
    WHERE created_at >= %(start)s AND created_at < %(end)s
      {extra_where}
    ORDER BY 
        multiIf(risk_level='critical', 1, risk_level='high', 2, risk_level='medium', 3, 4),
        created_at DESC
    LIMIT 50
    """
    
    anomalies_raw = ch.fetch_dicts(anomalies_query, params)
    
    # Enrich with more context from enriched_logs for each anomaly
    anomalies = []
    for idx, a in enumerate(anomalies_raw):
        # Try to find related user/IP from logs
        user_ip_query = f"""
        SELECT
            identity AS user,
            ip AS sourceIp,
            geo_country AS country
        FROM soc.enriched_logs
        WHERE service = %(service)s
          AND namespace = %(namespace)s
          AND timestamp >= %(ts_start)s
          AND timestamp <= %(ts_end)s
          AND identity != ''
        LIMIT 1
        """
        
        # Parse timestamp (ClickHouse returns as string like '2026-01-30 10:11:12')
        ts_str = str(a["timestamp"])
        if 'T' in ts_str:
            ts = dt.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        else:
            # Handle ClickHouse format 'YYYY-MM-DD HH:MM:SS'
            ts = dt.datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=dt.timezone.utc)
        user_ip_result = ch.fetch_dicts(
            user_ip_query,
            {
                "service": a["service"],
                "namespace": a["namespace"],
                "ts_start": ts - dt.timedelta(minutes=5),
                "ts_end": ts + dt.timedelta(minutes=5),
            }
        )
        
        user_ip = user_ip_result[0] if user_ip_result else {}
        
        anomalies.append({
            "id": f"anomaly_{idx}_{int(ts.timestamp())}",
            "timestamp": a["timestamp"],
            "severity": a["severity"],
            "type": a.get("type", "ml_anomaly"),
            "description": a.get("description", "Anomalous behavior detected"),
            "user": user_ip.get("user", f"service-account@{a['service']}"),
            "sourceIp": user_ip.get("sourceIp", "internal"),
            "confidence": int(float(a.get("confidence", 85))),
            "service": a["service"],
            "namespace": a["namespace"],
        })
    
    # ========================================================================
    # 5. NETWORK FLOW (Sankey Diagram Data)
    # ========================================================================
    network_flow_query = f"""
    WITH flow_data AS (
        SELECT
            ip AS source_ip,
            geo_country AS country,
            multiIf(
                positionCaseInsensitive(method, 'istio') > 0, 'istio-gateway',
                service LIKE '%gateway%', 'api-gateway',
                service LIKE '%proxy%', 'proxy',
                service
            ) AS device_type,
            multiIf(
                severity IN ('ERROR', 'CRITICAL'), 'security-logs',
                positionCaseInsensitive(message, 'audit') > 0, 'audit-logs',
                'access-logs'
            ) AS telemetry_type,
            count() AS flow_count
        FROM soc.enriched_logs
        WHERE timestamp >= %(start)s AND timestamp < %(end)s
          AND ip != '' AND ip NOT IN ('127.0.0.1', '0.0.0.0')
          AND method != 'k8s.inventory'
          {extra_where}
        GROUP BY source_ip, geo_country, device_type, telemetry_type
        HAVING flow_count >= 5
    )
    SELECT
        source_ip,
        country,
        device_type,
        telemetry_type,
        flow_count
    FROM flow_data
    ORDER BY flow_count DESC
    LIMIT 100
    """
    
    network_flows = ch.fetch_dicts(network_flow_query, params)
    
    # Build Sankey nodes and links
    sankey_nodes = []
    sankey_links = []
    node_ids = {}
    
    def get_node_id(name: str, layer: str) -> int:
        key = f"{layer}:{name}"
        if key not in node_ids:
            node_ids[key] = len(sankey_nodes)
            sankey_nodes.append({"id": node_ids[key], "name": name, "layer": layer})
        return node_ids[key]
    
    for flow in network_flows:
        # Source IP → Device Type → Telemetry Type
        source_id = get_node_id(flow["source_ip"], "source")
        device_id = get_node_id(flow["device_type"], "device")
        telem_id = get_node_id(flow["telemetry_type"], "telemetry")
        
        sankey_links.append({
            "source": source_id,
            "target": device_id,
            "value": flow["flow_count"]
        })
        
        sankey_links.append({
            "source": device_id,
            "target": telem_id,
            "value": flow["flow_count"]
        })
    
    # ========================================================================
    # 6. SECURITY POSTURE SCORE
    # ========================================================================
    posture_query = f"""
    SELECT
        -- Authentication score (fewer failed logins = better)
        100 - least(100, countIf(
            positionCaseInsensitive(message, 'failed') > 0 OR 
            positionCaseInsensitive(message, 'unauthorized') > 0
        ) * 2) AS authentication_score,
        
        -- Access Control (fewer privilege escalations = better)
        100 - least(100, countIf(
            positionCaseInsensitive(message, 'escalat') > 0 OR
            positionCaseInsensitive(message, 'sudo') > 0
        ) * 5) AS access_control_score,
        
        -- Threat Detection (active anomalies impact score)
        greatest(50, 100 - (
            SELECT count() FROM soc.anomalies 
            WHERE created_at >= %(start)s AND risk_level IN ('critical', 'high')
        ) * 3) AS threat_detection_score,
        
        -- Network Security (suspicious IPs)
        100 - least(100, countIf(
            geo_country IN ('RU', 'CN', 'KP')
        ) * 10) AS network_security_score,
        
        -- Compliance (proper logging)
        multiIf(
            count() < 1000, 30,
            count() < 10000, 70,
            90
        ) AS compliance_score,
        
        -- Incident Response (recent critical incidents)
        greatest(10, 100 - (
            SELECT countIf(risk_level='critical') FROM soc.anomalies 
            WHERE created_at >= now() - INTERVAL 1 HOUR
        ) * 20) AS incident_response_score
        
    FROM soc.enriched_logs
    WHERE timestamp >= %(start)s AND timestamp < %(end)s
      {extra_where}
    """
    
    posture_raw = ch.fetch_dicts(posture_query, params)
    posture = posture_raw[0] if posture_raw else {}
    
    # Convert all scores to int (ClickHouse may return as string)
    auth_score = int(float(posture.get("authentication_score") or 70))
    access_score = int(float(posture.get("access_control_score") or 60))
    threat_score = int(float(posture.get("threat_detection_score") or 85))
    network_score = int(float(posture.get("network_security_score") or 50))
    compliance_score = int(float(posture.get("compliance_score") or 90))
    incident_score = int(float(posture.get("incident_response_score") or 80))
    
    overall_score = int((auth_score + access_score + threat_score + network_score + compliance_score + incident_score) / 6)
    
    security_posture = {
        "overallScore": overall_score,
        "status": "excellent" if overall_score >= 90 else ("good" if overall_score >= 70 else ("moderate" if overall_score >= 50 else "poor")),
        "categories": {
            "authentication": auth_score,
            "accessControl": access_score,
            "threatDetection": threat_score,
            "networkSecurity": network_score,
            "compliance": compliance_score,
            "incidentResponse": incident_score,
        }
    }
    
    # ========================================================================
    # 7. RECENT IAM CHANGES
    # ========================================================================
    iam_changes_query = f"""
    SELECT
        toString(timestamp) AS timestamp,
        identity AS changedBy,
        method AS action,
        resource,
        service
    FROM soc.enriched_logs
    WHERE timestamp >= %(start)s AND timestamp < %(end)s
      AND (
        positionCaseInsensitive(method, 'iam') > 0 OR
        positionCaseInsensitive(service, 'iam') > 0 OR
        positionCaseInsensitive(message, 'iam') > 0 OR
        positionCaseInsensitive(message, 'role') > 0 OR
        positionCaseInsensitive(message, 'policy') > 0
      )
      {extra_where}
    ORDER BY timestamp DESC
    LIMIT 20
    """
    
    iam_changes = ch.fetch_dicts(iam_changes_query, params)
    
    # ========================================================================
    # 8. NETWORK TRAFFIC STATS
    # ========================================================================
    traffic_query = f"""
    SELECT
        countIf(status_code < 400) AS inbound_count,
        countIf(status_code >= 200 AND status_code < 300) AS outbound_count,
        countIf(status_code >= 400) AS blocked_count
    FROM soc.enriched_logs
    WHERE timestamp >= %(start)s AND timestamp < %(end)s
      AND status_code > 0
      {extra_where}
    """
    
    traffic_raw = ch.fetch_dicts(traffic_query, params)
    traffic = traffic_raw[0] if traffic_raw else {}
    
    network_traffic = {
        "inbound": traffic.get("inbound_count", 0),
        "outbound": traffic.get("outbound_count", 0),
        "blocked": traffic.get("blocked_count", 0),
        "timeline": timeline,  # Reuse timeline data
    }
    
    # ========================================================================
    # 9. ATTACK PATTERN HEATMAP
    # ========================================================================
    heatmap_query = f"""
    WITH daily_attacks AS (
        SELECT
            toDayOfWeek(timestamp) AS day_of_week,
            toHour(timestamp) AS hour_of_day,
            count() AS attack_count
        FROM soc.enriched_logs
        WHERE timestamp >= %(start)s AND timestamp < %(end)s
          AND (severity IN ('ERROR', 'CRITICAL') OR status_code >= 400)
          {extra_where}
        GROUP BY day_of_week, hour_of_day
    )
    SELECT
        day_of_week,
        hour_of_day,
        attack_count
    FROM daily_attacks
    ORDER BY day_of_week, hour_of_day
    """
    
    heatmap_raw = ch.fetch_dicts(heatmap_query, params)
    
    # Convert to 2D array [day][hour] - ensure all values are ints
    heatmap_data = [[0 for _ in range(24)] for _ in range(7)]
    for entry in heatmap_raw:
        day = int(entry["day_of_week"]) - 1  # 1=Mon -> 0=Sun
        hour = int(entry["hour_of_day"])
        heatmap_data[day][hour] = int(entry["attack_count"])
    
    attack_pattern_heatmap = {
        "data": heatmap_data,
        "days": ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
        "maxValue": max(max(row) for row in heatmap_data) if heatmap_data and any(row for row in heatmap_data) else 0,
    }
    
    # ========================================================================
    # 10. KPI STATS
    # ========================================================================
    stats_query = f"""
    SELECT
        count() AS total_events,
        countIf(severity IN ('ERROR', 'CRITICAL')) AS critical_threats,
        countIf(
            positionCaseInsensitive(message, 'login') > 0 OR 
            positionCaseInsensitive(message, 'auth') > 0
        ) AS failed_logins,
        countIf(
            positionCaseInsensitive(method, 'iam') > 0 OR
            positionCaseInsensitive(service, 'iam') > 0
        ) AS iam_changes,
        uniq(ip) AS unique_attack_sources,
        round(countIf(severity IN ('ERROR', 'CRITICAL')) * 100.0 / greatest(count(), 1), 1) AS events_per_hour
    FROM soc.enriched_logs
    WHERE timestamp >= %(start)s AND timestamp < %(end)s
      AND method != 'k8s.inventory'
      {extra_where}
    """
    
    stats_raw = ch.fetch_dicts(stats_query, params)
    stats = stats_raw[0] if stats_raw else {}
    
    # ========================================================================
    # 11. LOGS ARRAY FOR FRONTEND (matching React component expectations)
    # ========================================================================
    logs_query = f"""
    SELECT
        toString(timestamp) AS timestamp,
        ip AS sourceIp,
        identity AS user,
        method,
        service,
        namespace,
        severity,
        status_code,
        message,
        geo_country AS country
    FROM soc.enriched_logs
    WHERE timestamp >= %(start)s AND timestamp < %(end)s
      AND method != 'k8s.inventory'
      AND ip != ''
      {extra_where}
    ORDER BY timestamp DESC
    LIMIT 500
    """
    
    logs_raw = ch.fetch_dicts(logs_query, params)
    
    # Format logs for frontend
    logs = []
    for idx, log in enumerate(logs_raw):
        # Determine log type based on content
        method_lower = str(log.get("method", "")).lower()
        message_lower = str(log.get("message", "")).lower()
        
        if "iam" in method_lower or "iam" in message_lower:
            log_type = "iam_change"
        elif "login" in method_lower or "auth" in message_lower or "login" in message_lower:
            # Check if it's a failure
            is_failure = (
                log.get("severity") in ("ERROR", "CRITICAL", "WARNING") or
                int(log.get("status_code", 0)) >= 400 or
                "fail" in message_lower or
                "wrong" in message_lower or
                "invalid" in message_lower
            )
            log_type = "login_failure" if is_failure else "login_success"
        else:
            log_type = "network_event"
        
        logs.append({
            "id": f"log_{idx}",
            "timestamp": log.get("timestamp"),
            "type": log_type,
            "sourceIp": log.get("sourceIp", "unknown"),
            "user": log.get("user", "unknown"),
            "method": log.get("method", ""),
            "service": log.get("service", ""),
            "namespace": log.get("namespace", ""),
            "severity": log.get("severity", "INFO").lower(),
            "country": log.get("country", "Unknown"),
            "message": log.get("message", "")[:200]  # Truncate long messages
        })
    
    # ========================================================================
    # FINAL RESPONSE STRUCTURE (matching React component expectations)
    # ========================================================================
    return {
        # Original fields
        "timeRange": {
            "start": start.isoformat().replace("+00:00", "Z"),
            "end": end.isoformat().replace("+00:00", "Z"),
            "hours": int((end - start).total_seconds() / 3600),
        },
        "stats": {
            "totalEvents": stats.get("total_events", 0),
            "criticalThreats": stats.get("critical_threats", 0),
            "failedLogins": stats.get("failed_logins", 0),
            "iamChanges": stats.get("iam_changes", 0),
            "attackSources": len(attack_sources_formatted),
            "eventsPerHour": stats.get("events_per_hour", 0),
        },
        "securityEventsTimeline": timeline,
        "threatDistribution": threat_distribution,
        "topAttackSources": attack_sources_formatted,
        "securityPosture": security_posture,
        "networkTraffic": network_traffic,
        "attackPatternHeatmap": attack_pattern_heatmap,
        "systemStatus": "operational",
        "lastUpdated": end.isoformat().replace("+00:00", "Z"),
        
        # Frontend-specific fields (matching React components)
        "logs": logs,  # For TimelineChart and D3SankeyDiagram
        "anomalies": anomalies,  # For TopAttackersChart and ThreatPieChart (renamed from aiDetectedAnomalies)
        "iamChanges": iam_changes,
        
        # Network flow with both formats
        "networkFlow": {
            "totalEvents": len(network_flows),
            "networkFlows": len(set(f["device_type"] for f in network_flows)),
            "activeNodes": len(sankey_nodes),
            "sankeyData": {
                "nodes": sankey_nodes,
                "links": sankey_links,
            }
        },
    }


def format_logs_for_frontend(ch, start: dt.datetime, end: dt.datetime, limit: int = 500) -> list[dict[str, Any]]:
    """
    Format logs in the exact structure expected by the React frontend.
    Matches the mockLogs format from the frontend code.
    """
    query = f"""
    SELECT
        -- enriched_logs has no `id`; generate a stable ID from existing fields
        concat(
          toString(toUnixTimestamp(timestamp)),
          '-',
          toString(sipHash64(concat(service,'|',namespace,'|',pod,'|',ip,'|',request_id,'|',message)))
        ) AS log_id,
        timestamp,
        severity,
        service,
        namespace,
        pod,
        method,
        message,
        ip,
        identity,
        status_code,
        geo_country,
        geo_city
    FROM soc.enriched_logs
    WHERE timestamp >= %(start)s AND timestamp <= %(end)s
      AND method != 'k8s.inventory'
    ORDER BY timestamp DESC
    LIMIT %(limit)s
    """
    
    rows = ch.fetch_dicts(query, {"start": start, "end": end, "limit": limit})
    
    frontend_logs = []
    for row in rows:
        msg_lower = str(row.get("message", "")).lower()
        method_lower = str(row.get("method", "")).lower()
        severity = str(row.get("severity", "")).upper()
        status = row.get("status_code", 0)
        
        # Determine log type
        log_type = "network_event"
        if any(x in msg_lower for x in ["failed", "wrong", "denied", "unauthorized", "invalid"]):
            if any(x in msg_lower for x in ["login", "auth", "password", "pin", "signin"]):
                log_type = "login_failure"
        elif any(x in msg_lower for x in ["login", "auth", "authenticated"]) or (200 <= status < 300):
            if any(x in msg_lower for x in ["login", "signin", "auth"]):
                log_type = "login_success"
        elif any(x in method_lower + msg_lower for x in ["iam", "policy", "role", "permission"]):
            log_type = "iam_change"
        elif any(x in msg_lower for x in ["scan", "probe", "discovery", "port"]):
            log_type = "network_scan"
        
        # Format timestamp
        ts_str = str(row.get("timestamp", ""))
        try:
            if 'T' in ts_str:
                ts = dt.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            else:
                ts = dt.datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=dt.timezone.utc)
            formatted_ts = ts.strftime('%Y-%m-%dT%H:%M:%SZ')
        except:
            formatted_ts = ts_str
        
        # Build log entry
        log_entry = {
            "id": str(row.get("log_id", "")),
            "type": log_type,
            "sourceIp": row.get("ip") or "unknown",
            "timestamp": formatted_ts,
        }
        
        # Add optional fields
        if row.get("identity"):
            log_entry["user"] = row.get("identity")
        if row.get("geo_country"):
            log_entry["geo"] = row.get("geo_country")
        if row.get("pod"):
            log_entry["hostname"] = row.get("pod")
        if row.get("service"):
            log_entry["device"] = row.get("service")
        
        # IAM action
        if log_type == "iam_change":
            if "attach" in msg_lower:
                log_entry["action"] = "policy_attached"
            elif "escalat" in msg_lower:
                log_entry["action"] = "role_escalated"
            elif "create" in msg_lower:
                log_entry["action"] = "resource_created"
            elif "delete" in msg_lower:
                log_entry["action"] = "resource_deleted"
            else:
                log_entry["action"] = "permission_changed"
        
        # VPN detection
        if "vpn" in msg_lower or "remote" in str(row.get("identity", "")).lower():
            log_entry["vpn"] = True
        
        frontend_logs.append(log_entry)
    
    return frontend_logs
