import React, { useMemo } from "react";

// ── Severity config ────────────────────────────────────────────────────────
const SEV_ORDER = ["critical", "high", "medium", "low", "warning", "info"];

const SEV_META = {
  critical: { label: "CRITICAL", cls: "sev-critical" },
  high:     { label: "HIGH",     cls: "sev-high" },
  medium:   { label: "MEDIUM",   cls: "sev-medium" },
  low:      { label: "LOW",      cls: "sev-low" },
  warning:  { label: "WARNING",  cls: "sev-warning" },
  info:     { label: "INFO",     cls: "sev-info" },
};

function SeverityBadge({ severity }) {
  const meta = SEV_META[severity] ?? SEV_META.info;
  // Log severity at render time so it can be verified in browser console.
  // eslint-disable-next-line no-console
  console.debug("[AlertsPanel] rendering badge severity=%s  css=%s", severity, meta.cls);
  return <span className={`badge ${meta.cls}`}>{meta.label}</span>;
}

function relativeTime(ts) {
  const sec = Math.max(0, Date.now() / 1000 - ts);
  if (sec < 60)   return `${Math.round(sec)}s ago`;
  if (sec < 3600) return `${Math.round(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.round(sec / 3600)}h ago`;
  return `${Math.round(sec / 86400)}d ago`;
}

// ── Findings panel (persistent port state) ─────────────────────────────────
function FindingsPanel({ findings }) {
  const stats = useMemo(() => {
    const counts = {};
    const hosts = new Set(findings.map((f) => f.host));
    findings.forEach((f) => { counts[f.severity] = (counts[f.severity] ?? 0) + 1; });
    return { total: findings.length, hosts: hosts.size, counts };
  }, [findings]);

  if (findings.length === 0) {
    return (
      <div className="panel alerts-panel">
        <h2>Security Findings</h2>
        <div className="empty">No risky ports detected yet — this is a good sign.</div>
      </div>
    );
  }

  return (
    <div className="panel alerts-panel">
      <h2>Security Findings ({findings.length})</h2>

      <div className="alerts-scroll">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Host</th>
              <th>Port / Service</th>
              <th>Seen</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} className={`alert-row sev-row-${f.severity}`}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td className="alert-time">{f.host}</td>
                <td className="alert-msg">
                  <strong>{f.port}</strong>{" "}
                  <span style={{ color: "var(--muted)" }}>({f.service})</span>
                  <br />
                  <span style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                    {f.description}
                  </span>
                </td>
                <td className="alert-time">×{f.seen_count}</td>
                <td className="alert-time">{relativeTime(f.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Summary footer */}
      <div className="alerts-footer">
        <span>{stats.total} finding{stats.total !== 1 ? "s" : ""}</span>
        <span className="dot">·</span>
        <span>{stats.hosts} host{stats.hosts !== 1 ? "s" : ""}</span>
        <span className="dot">·</span>
        <span className="sev-breakdown">
          {SEV_ORDER.filter((s) => stats.counts[s]).map((s) => (
            <span key={s} className={`sev-chip sev-chip-${s}`}>
              {stats.counts[s]} {s}
            </span>
          ))}
        </span>
      </div>
    </div>
  );
}

// ── Event log (new devices, traffic spikes, first-seen alerts) ─────────────
function AlertLog({ alerts }) {
  if (alerts.length === 0) return null;

  return (
    <div className="panel alerts-panel">
      <h2>Event Log ({alerts.length})</h2>
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
                <td><SeverityBadge severity={a.severity} /></td>
                <td className="alert-msg">{a.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Main export ───────────────────────────────────────────────────────────
export default function AlertsPanel({ alerts = [], findings = [] }) {
  return (
    <>
      <FindingsPanel findings={findings} />
      <AlertLog alerts={alerts} />
    </>
  );
}
