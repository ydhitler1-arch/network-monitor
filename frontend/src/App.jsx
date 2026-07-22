import React, { useEffect, useRef, useState } from "react";
import TrafficChart from "./components/TrafficChart.jsx";
import DeviceList from "./components/DeviceList.jsx";
import PortScanTable from "./components/PortScanTable.jsx";
import AlertsPanel from "./components/AlertsPanel.jsx";
import Login from "./components/Login.jsx";
import {
  getTrafficHistory,
  getDevices,
  getAlerts,
  getMeta,
  getAuthStatus,
  logout,
} from "./api.js";

const TRAFFIC_POLL_MS = 2000;
const DEVICES_POLL_MS = 10000;
const ALERTS_POLL_MS = 5000;

export default function App() {
  const [authenticated, setAuthenticated] = useState(null); // null = still checking
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [devices, setDevices] = useState([]);
  const [devicesScannedAt, setDevicesScannedAt] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [meta, setMeta] = useState(null);
  const [error, setError] = useState("");
  const mounted = useRef(true);

  useEffect(() => {
    getAuthStatus()
      .then((data) => setAuthenticated(!!data.authenticated))
      .catch(() => setAuthenticated(false));
  }, []);

  useEffect(() => {
    if (!authenticated) return undefined;
    mounted.current = true;
    getMeta().then(setMeta).catch(() => {});

    const handleError = (e) => {
      if (!mounted.current) return;
      if (e.status === 401) {
        setAuthenticated(false);
      } else {
        setError(e.message);
      }
    };

    const pollTraffic = () => {
      getTrafficHistory(120)
        .then((data) => mounted.current && setTrafficHistory(data))
        .catch(handleError);
    };
    const pollDevices = () => {
      getDevices()
        .then((data) => {
          if (!mounted.current) return;
          setDevices(data.devices || []);
          setDevicesScannedAt(data.scanned_at);
        })
        .catch(handleError);
    };
    const pollAlerts = () => {
      getAlerts(100)
        .then((data) => mounted.current && setAlerts(data))
        .catch(handleError);
    };

    pollTraffic();
    pollDevices();
    pollAlerts();

    const t1 = setInterval(pollTraffic, TRAFFIC_POLL_MS);
    const t2 = setInterval(pollDevices, DEVICES_POLL_MS);
    const t3 = setInterval(pollAlerts, ALERTS_POLL_MS);

    return () => {
      mounted.current = false;
      clearInterval(t1);
      clearInterval(t2);
      clearInterval(t3);
    };
  }, [authenticated]);

  const refreshDevices = (newDevices, scannedAt) => {
    setDevices(newDevices);
    setDevicesScannedAt(scannedAt);
  };

  const refreshAlerts = () => {
    getAlerts(100).then(setAlerts).catch(() => {});
  };

  const handleLogout = async () => {
    try {
      await logout();
    } finally {
      setAuthenticated(false);
      setTrafficHistory([]);
      setDevices([]);
      setAlerts([]);
      setError("");
    }
  };

  if (authenticated === null) {
    return (
      <div className="app">
        <p className="empty">Loading…</p>
      </div>
    );
  }

  if (!authenticated) {
    return <Login onSuccess={() => setAuthenticated(true)} />;
  }

  return (
    <div className="app">
      <div className="app-header">
        <h1>Network Monitor</h1>
        <div className="header-right">
          <span className="status">
            {meta
              ? `nmap: ${meta.nmap_available ? "available" : "socket fallback"} · scapy: ${
                  meta.scapy_available ? "available" : "ARP-table fallback"
                }`
              : ""}
          </span>
          <button onClick={handleLogout}>Log out</button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="grid">
        <div>
          <TrafficChart history={trafficHistory} />
          <DeviceList devices={devices} scannedAt={devicesScannedAt} onScanned={refreshDevices} />
          <PortScanTable
            devices={devices}
            highRiskPorts={meta?.high_risk_ports || {}}
            onScanComplete={refreshAlerts}
          />
        </div>
        <div>
          <AlertsPanel alerts={alerts} />
        </div>
      </div>
    </div>
  );
}
