const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api").replace(/\/$/, "");

export async function api(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: { "Content-Type": "application/json", ...options.headers },
    });
  } catch {
    throw new Error(`Cannot reach SentinelAI API at ${API_BASE}. Start the backend and refresh.`);
  }

  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    const message = payload && typeof payload === "object"
      ? payload.error?.message || payload.detail?.message || payload.detail
      : null;
    throw new Error(typeof message === "string" ? message : `Request failed (${response.status}).`);
  }
  return payload;
}

export const get = (path) => api(path);
export const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body) });
export const patch = (path, body) => api(path, { method: "PATCH", body: JSON.stringify(body) });
