import React, { useState } from "react";
import { scanPorts } from "../api.js";

export default function PortScanTable({ devices, highRiskPorts, onScanComplete }) {
  const [host, setHost] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const handleScan = async (e) => {
    e.preventDefault();
    if (!host) return;
    setScanning(true);
    setError("");
    try {
      const data = await scanPorts(host.trim());
      setResult(data);
      onScanComplete?.();
    } catch (err) {
      setError(err.message);
      setResult(null);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="panel">
      <h2>Port Scan</h2>
      <form className="form-row" onSubmit={handleScan}>
        <input
          type="text"
          list="known-hosts"
          placeholder="Host or IP (e.g. 192.168.1.1)"
          value={host}
          onChange={(e) => setHost(e.target.value)}
          style={{ flex: 1, minWidth: 200 }}
        />
        <datalist id="known-hosts">
          {devices.map((d) => (
            <option key={d.mac} value={d.ip} />
          ))}
        </datalist>
        <button type="submit" disabled={scanning || !host}>
          {scanning ? "Scanning…" : "Scan Common Ports"}
        </button>
      </form>

      {error && <div className="error-banner">{error}</div>}

      {result && (
        <>
          <div className="empty">
            {result.host} · {result.open_ports.length} open of {result.scanned_ports} scanned ·{" "}
            {result.duration_s}s · engine: {result.engine}
          </div>
          {result.open_ports.length === 0 ? (
            <div className="empty">No open ports found.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Service</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {result.open_ports.map((p) => (
                  <tr key={p.port}>
                    <td>{p.port}</td>
                    <td>{p.service}</td>
                    <td>
                      {highRiskPorts[p.port] ? (
                        <span className="badge risky" title={highRiskPorts[p.port]}>
                          high risk
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
