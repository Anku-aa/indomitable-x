import { useSelector } from "react-redux";
import { statusOf } from "../api";

function Metric({ label, value, foot }) {
  return <div className="metric"><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-foot">{foot}</div></div>;
}

export default function Metrics() {
  const audit = useSelector((state) => state.telemetry.audit);
  const approvals = useSelector((state) => state.telemetry.approvals);
  const quarantine = useSelector((state) => state.telemetry.guardian.quarantined_agents || []);

  return <div className="metrics"><Metric label="Requests / trail" value={audit.length} foot="AUDIT EVENTS" /><Metric label="Executed" value={audit.filter((entry) => ["executed", "approved"].includes(statusOf(entry))).length} foot="POLICY ALLOWED" /><Metric label="Review queue" value={approvals.length} foot="HUMAN APPROVAL" /><Metric label="Quarantined" value={quarantine.length} foot="GUARDIAN SIGNAL" /></div>;
}
