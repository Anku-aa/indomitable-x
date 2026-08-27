export const API_BASE = "http://127.0.0.1:8000";
const DEMO_KEY = "4e4e9597bf8e08e728a8b6fd12ab9826";

export async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      Authorization: `Bearer ${DEMO_KEY}`,
      ...(options.headers || {})
    }
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || `API ${response.status}`);
  return body;
}

export const safeText = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
}[char]));

export function statusOf(entry) {
  const status = entry.status || entry.result?.status || "denied";
  if (["SYSTEM", "system", "guardian_analysis"].includes(status) || entry.decision === "SYSTEM") return "system";
  if (status === "pending_approval") return "pending";
  if (status === "approved") return "approved";
  if (status === "rejected") return "rejected";
  if (status === "executed" || status.startsWith("approved_by")) return "executed";
  return "denied";
}
