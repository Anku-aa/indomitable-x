import { useState } from "react";
import { useSelector } from "react-redux";

export default function AgentRisk() {
  const agents = useSelector((state) => state.telemetry.guardian.agents || []);
  const latestResponse = useSelector((state) => state.telemetry.latestResponse);
  const [details, setDetails] = useState(null);

  return (
    <section className="section" id="agent-risk" data-reveal>
      <div className="section-head"><div><div className="section-number">03 // Adaptive privilege control</div><h2 className="section-title">AGENT RISK</h2></div><p className="section-note">Runtime state derived from the latest audit window. YAML policy remains unchanged.</p></div>
      <div className="risk-grid">
        {agents.map((agent) => {
          const restricted = agent.risk_level === "RESTRICTED";
          const quarantined = agent.risk_level === "QUARANTINED";
          const latest = latestResponse?.adaptive_risk?.agent_id === agent.agent_id ? latestResponse : null;
          return (
            <article className={`risk-card ${agent.risk_level?.toLowerCase() || "normal"}`} key={agent.agent_id}>
              <div className="risk-card-head"><div><div className="risk-agent">{agent.agent_id}</div><div className="risk-label">{agent.risk_level || "NORMAL"}</div></div><div className="risk-score">{agent.risk_score || 0}<span>/10</span></div></div>
              {latest && <div className={`risk-latest ${latest.status === "denied" ? "blocked" : ""}`}>LATEST REQUEST // {latest.status.replaceAll("_", " ")} // RISK {latest.adaptive_risk?.risk_score || agent.risk_score}/10</div>}
              {restricted && <div className="risk-alert">🚨 BEHAVIORAL RISK DETECTED<br /><span>Agent: {agent.agent_id} // Risk: {agent.risk_score}/10 // Status: RESTRICTED</span></div>}
              <div className="risk-reason">WHY // {agent.reason || "No behavioral risk indicators observed"}</div>
              <div className="risk-stats"><span>DENIED // {agent.denied_requests || 0}</span><span>SENSITIVE // {agent.sensitive_attempts || 0}</span><span>HIGH-RISK // {agent.high_risk_requests || 0}</span></div>
              <div className="risk-privilege">PRIVILEGE // {quarantined ? "QUARANTINED" : restricted ? "RESTRICTED — risky actions blocked" : agent.privilege_state || "POLICY PRIVILEGES"}</div>
              <button className="outline-button risk-details" onClick={() => setDetails(details === agent.agent_id ? null : agent.agent_id)}>{details === agent.agent_id ? "Hide details" : "Why? / details"}</button>
              {details === agent.agent_id && <div className="risk-detail"><div>FACTORS // LAST {agent.window_size || 0} EVENTS</div>{(agent.risk_factors || []).map((factor) => <p key={factor}>+ {factor}</p>)}{!(agent.risk_factors || []).length && <p>No violations recorded.</p>}<div className="risk-violations">RECENT VIOLATIONS</div>{(agent.recent_violations || []).map((violation, index) => <p key={`${violation.timestamp}-${index}`}>{violation.decision} // {violation.query}</p>)}</div>}
            </article>
          );
        })}
      </div>
    </section>
  );
}
