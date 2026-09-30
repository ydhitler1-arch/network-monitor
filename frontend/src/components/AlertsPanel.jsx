import React, { useMemo } from "react";

// Maps severity value → CSS class (defined in index.css)
const SEVERITY_CLASS = {
  critical: "sev-critical",
  high:     "sev-high",
  warning:  "sev-warning",
  medium:   "sev-medium",
  low:      "sev-low",
  info:     "sev-info",
};

function SeverityBadge({ severity }) {
  const cls = SEVERITY_CLASS[severity] ?? "sev-info";
  return <span className={`badge ${cls}`}>{severity}</span>;
}

function formatAge(seconds) {
  if (seconds < 60)  return `${Math.round(seconds)}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  return `${Math.round(seconds / 3600)}h ago`;
}

export default function AlertsPanel({ alerts }) {
  const stats = useMemo(() => {
    if (!alerts.length) return null;
    const hosts = new Set();
    const bySeverity = {};
    alerts.forEach((a) => {
      bySeverity[a.severity] = (bySeverity[a.severity] ?? 0) + 1;
      // Extract IPs from message text (simple regex)
      const ips = a.message.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? [];
      ips.forEach((ip) => hosts.add(ip));
    });
    const newestTs = Math.max(...alerts.map((a) => a.timestamp));
    const ageSec = (Date.now() / 1000) - newestTs;
    return { total: alerts.length, hosts: hosts.size, ageSec, bySeverity };
  }, [alerts]);

  return (
    <div className="panel alerts-panel">
      <h2>Security Alerts ({alerts.length})</h2>

      {alerts.length === 0 ? (
        <div className="empty">No alerts yet — this is a good thing.</div>
      ) : (
        <>
          {/* Scrollable alert table */}
          <div className="alerts-scroll">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.id} className={`alert-row sev-row-${a.severity}`}>
                    <td className="alert-time">
                      {new Date(a.timestamp * 1000).toLocaleTimeString()}
                    </td>
                    <td>
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="alert-msg">{a.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pinned summary footer */}
          {stats && (
            <div className="alerts-footer">
              <span>{stats.total} alert{stats.total !== 1 ? "s" : ""}</span>
              <span className="dot">·</span>
              <span>{stats.hosts} unique host{stats.hosts !== 1 ? "s" : ""}</span>
              <span className="dot">·</span>
              <span>updated {formatAge(stats.ageSec)}</span>
              <span className="dot">·</span>
              <span className="sev-breakdown">
                {["critical","high","medium","low","warning","info"]
                  .filter((s) => stats.bySeverity[s])
                  .map((s) => (
                    <span key={s} className={`sev-chip sev-chip-${s}`}>
                      {stats.bySeverity[s]} {s}
                    </span>
                  ))}
              </span>
            </div>
          )}
        </>
      )}
    </div>
  );
}
