import { useSelector } from "react-redux";
import { api } from "../api";

export default function Approvals({ toast, onChanged, onResolved }) {
  const items = useSelector((state) => state.telemetry.approvals);
  const quarantined = useSelector((state) => (state.telemetry.guardian.quarantined_agents || []).map((agent) => agent.agent_id));
  const unique = [...new Map(items.map((item) => [String(item.id), item])).values()];

  async function review(item, approve) {
    const held = item.status === "auto_held_quarantine" || quarantined.includes(item.agent_id);
    if (approve && held && !window.confirm("This agent is quarantined. Confirm explicit override and approval?")) return;
    const reviewer = window.prompt("Reviewer name", "console operator") || "console operator";
    try {
      const response = await api(`/approvals/${item.id}`, { method: "POST", body: JSON.stringify({ approve, reviewer, confirm_quarantine_override: held && approve }) });
      onResolved(response);
      await onChanged();
      toast(approve ? "Request approved" : "Request rejected");
    } catch (error) {
      toast(error.message);
    }
  }

  return (
    <div className="panel">
      <div className="panel-head"><div className="panel-title">Approvals</div><div className="panel-tag">{unique.length} waiting</div></div>
      <div className="approval-list">
        {unique.map((item) => {
          const held = item.status === "auto_held_quarantine" || quarantined.includes(item.agent_id);
          return (
            <article className={`approval ${held ? "held" : ""}`} key={item.id}>
              <div className="approval-id">REQUEST #{item.id} // RISK {item.policy?.risk_score || "--"}{item.parsed_query?.operation === "DELETE" ? " // DESTRUCTIVE" : ""}</div>
              <div className="approval-query">{item.query}</div>
              <div className="approval-meta">AGENT // {item.agent_id}<br />STATE // {item.status}</div>
              {held && <div className="warning">WARNING // Quarantined after submission. Explicit override required.</div>}
              <div className="approval-actions"><button className="approve" onClick={() => review(item, true)}>{held ? "Override + approve" : "Approve"}</button><button className="reject" onClick={() => review(item, false)}>Reject</button></div>
            </article>
          );
        })}
        {!unique.length && <div className="empty">No requests waiting.</div>}
      </div>
    </div>
  );
}
