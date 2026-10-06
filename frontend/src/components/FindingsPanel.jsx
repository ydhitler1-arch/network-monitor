import React from "react";

const timeAgo = (ts) => {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};

export default function FindingsPanel({ findings }) {
  const open = findings.filter((f) => f.status !== "closed");
  const closed = findings.length - open.length;

  return (
    <div className="panel">
      <h2>Security Findings ({open.length} open)</h2>
      {findings.length === 0 ? (
        <div className="empty">No risky open ports found on your network.</div>
      ) : (
        <div className="scroll-panel">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Host</th>
                <th>Service</th>
                <th>Last seen</th>
                <th>Seen</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr
                  key={f.id}
                  className={f.status === "closed" ? "finding-closed" : undefined}
                  title={f.description}
                >
                  <td>
                    <span className={`badge ${f.severity}`}>{f.severity}</span>
                  </td>
                  <td>{f.host}</td>
                  <td>
                    {f.service} ({f.port})
                    {f.status === "closed" && <span className="finding-tag"> closed</span>}
                  </td>
                  <td>{timeAgo(f.last_seen)}</td>
                  <td>{f.seen_count}×</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {closed > 0 && (
        <div className="empty">
          {closed} closed finding{closed === 1 ? "" : "s"} shown dimmed — the port is no longer open.
        </div>
      )}
    </div>
  );
}
