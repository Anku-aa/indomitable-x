export const WORKFLOW_NODES = [
  ["query_received", "QUERY", "Natural-language request"],
  ["authentication", "AUTH", "Identity verified"],
  ["llm_interpreter", "LLM", "Intent to structured query"],
  ["policy_engine", "POLICY", "Permissions and risk"],
  ["decision", "DECISION", "Allow, approval or deny"],
  ["database", "DATABASE", "Governed execution"],
  ["audit_log", "AUDIT", "Tamper-evident record"],
];

export const AGENT_OPTIONS = [
  "recruiter_agent",
  "hr_analytics_agent",
  "senior_hr_agent",
  "rogue_agent",
];

// Vite exposes only explicitly prefixed values to the browser bundle.
export const DEMO_AGENT_KEYS = {
  recruiter_agent: import.meta.env.VITE_RECRUITER_BEARER_KEY || "",
};
