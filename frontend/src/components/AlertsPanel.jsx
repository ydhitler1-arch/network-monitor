import React from "react";

export default function AlertsPanel({ alerts }) {
  return (
    <div className="panel">
      <h2>Security Alerts ({alerts.length})</h2>
      {alerts.length === 0 ? (
        <div className="empty">No alerts yet — this is a good thing.</div>
      ) : (
        <div className="scroll-panel">
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
                <tr key={a.id}>
                  <td>{new Date(a.timestamp * 1000).toLocaleTimeString()}</td>
                  <td>
                    <span className={`badge ${a.severity}`}>{a.severity}</span>
                  </td>
                  <td>{a.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
