import React, { useState } from "react";
import { rescanDevices } from "../api.js";

export default function DeviceList({ devices, scannedAt, onScanned }) {
  const [scanning, setScanning] = useState(false);

  const handleRescan = async () => {
    setScanning(true);
    try {
      const data = await rescanDevices();
      onScanned(data.devices, Date.now() / 1000);
    } catch (e) {
      // surfaced via the app-level error banner on next poll
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="panel">
      <div className="form-row" style={{ justifyContent: "space-between" }}>
        <h2 style={{ margin: 0 }}>Connected Devices ({devices.length})</h2>
        <button onClick={handleRescan} disabled={scanning}>
          {scanning ? "Scanning…" : "Rescan Network"}
        </button>
      </div>
      {scannedAt && (
        <div className="empty">Last scanned: {new Date(scannedAt * 1000).toLocaleTimeString()}</div>
      )}
      {devices.length === 0 ? (
        <div className="empty">No devices discovered yet.</div>
      ) : (
        <div className="scroll-panel">
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>MAC Address</th>
                <th>Hostname</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.mac}>
                  <td>{d.ip}</td>
                  <td>{d.mac}</td>
                  <td>{d.hostname || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
