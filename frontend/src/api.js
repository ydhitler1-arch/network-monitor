const BASE_URL = "/api";

async function request(path, options) {
  const res = await fetch(`${BASE_URL}${path}`, { credentials: "include", ...options });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const err = new Error(body.error || `Request failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export const getTrafficCurrent = () => request("/traffic/current");
export const getTrafficHistory = (limit = 120) => request(`/traffic/history?limit=${limit}`);
export const getExtendedTrafficHistory = (limit = 2000) =>
  request(`/traffic/history/extended?limit=${limit}`);
export const getDevices = () => request("/devices");
export const rescanDevices = () => request("/devices/scan", { method: "POST" });
export const getAlerts = (limit = 100) => request(`/alerts?limit=${limit}`);
export const getMeta = () => request("/meta");

export const scanPorts = (host, ports, engine) => {
  const params = new URLSearchParams({ host });
  if (ports) params.set("ports", ports);
  if (engine) params.set("engine", engine);
  return request(`/ports/scan?${params.toString()}`);
};

export const getAuthStatus = () => request("/auth/status");
export const login = (username, password) =>
  request("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
export const logout = () => request("/auth/logout", { method: "POST" });
