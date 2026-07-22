import React, { useEffect, useState } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { getExtendedTrafficHistory } from "../api.js";

const EXTENDED_POLL_MS = 15000;

function formatRate(bytesPerSec) {
  if (bytesPerSec >= 1024 * 1024) return `${(bytesPerSec / (1024 * 1024)).toFixed(2)} MB/s`;
  if (bytesPerSec >= 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${Math.round(bytesPerSec)} B/s`;
}

export default function TrafficChart({ history }) {
  const [range, setRange] = useState("live");
  const [extendedHistory, setExtendedHistory] = useState([]);

  useEffect(() => {
    if (range !== "extended") return undefined;
    let cancelled = false;
    const load = () => {
      getExtendedTrafficHistory(2000)
        .then((data) => !cancelled && setExtendedHistory(data))
        .catch(() => {});
    };
    load();
    const interval = setInterval(load, EXTENDED_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [range]);

  const activeHistory = range === "live" ? history : extendedHistory;
  const latest = activeHistory[activeHistory.length - 1];
  const chartData = activeHistory.map((h) => ({
    time:
      range === "live"
        ? new Date(h.timestamp * 1000).toLocaleTimeString()
        : new Date(h.timestamp * 1000).toLocaleString([], {
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          }),
    Download: Math.round(h.recv_rate),
    Upload: Math.round(h.send_rate),
  }));

  return (
    <div className="panel">
      <div className="form-row" style={{ justifyContent: "space-between" }}>
        <h2 style={{ margin: 0 }}>Live Traffic</h2>
        <div className="range-toggle">
          <button className={range === "live" ? "active" : ""} onClick={() => setRange("live")}>
            Live
          </button>
          <button
            className={range === "extended" ? "active" : ""}
            onClick={() => setRange("extended")}
          >
            Extended
          </button>
        </div>
      </div>
      <div className="stat-row">
        <div className="stat">
          <div className="label">Download</div>
          <div className="value down">{latest ? formatRate(latest.recv_rate) : "—"}</div>
        </div>
        <div className="stat">
          <div className="label">Upload</div>
          <div className="value up">{latest ? formatRate(latest.send_rate) : "—"}</div>
        </div>
      </div>
      {range === "extended" && chartData.length === 0 ? (
        <div className="empty">No extended history yet — check back in a few minutes.</div>
      ) : (
        <div style={{ width: "100%", height: 220 }}>
          <ResponsiveContainer>
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="down" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3fca6f" stopOpacity={0.5} />
                  <stop offset="95%" stopColor="#3fca6f" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="up" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#4da3ff" stopOpacity={0.5} />
                  <stop offset="95%" stopColor="#4da3ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2f3a" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#8b93a3" }} minTickGap={30} />
              <YAxis
                tick={{ fontSize: 10, fill: "#8b93a3" }}
                tickFormatter={(v) => formatRate(v)}
                width={70}
              />
              <Tooltip
                contentStyle={{ background: "#171a21", border: "1px solid #2a2f3a", fontSize: 12 }}
                formatter={(value) => formatRate(value)}
              />
              <Area type="monotone" dataKey="Download" stroke="#3fca6f" fill="url(#down)" />
              <Area type="monotone" dataKey="Upload" stroke="#4da3ff" fill="url(#up)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
