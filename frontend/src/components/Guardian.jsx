import { useSelector } from "react-redux";
import { api } from "../api";

export default function Guardian({ toast, onChanged }) {
  const guardian = useSelector((state) => state.telemetry.guardian);

  async function run() {
    try {
      await api("/guardian/run", { method: "POST" });
      await onChanged();
      toast("Guardian analysis complete");
    } catch (error) {
      toast(error.message);
    }
  }

  async function lift(agent) {
    try {
      await api(`/guardian/lift/${agent}`, { method: "POST" });
      await onChanged();
      toast("Quarantine lifted");
    } catch (error) {
      toast(error.message);
    }
  }

  return (
    <section className="section" id="guardian" data-reveal>
      <div className="section-head">
        <div><div className="section-number">04 // Autonomous defense</div><h2 className="section-title">GUARDIAN</h2></div>
        <div><p className="section-note">Independent behavior analysis. Human judgment remains final.</p><button className="outline-button guardian-run" onClick={run}>Run guardian check</button></div>
      </div>
      <div className="guardian-grid">
        {(guardian.agents || []).map((agent) => (
          <article className={`guardian-card ${agent.status === "quarantined" ? "quarantined" : agent.status === "restricted" ? "restricted" : ""}`} key={agent.agent_id}>
            <span className="guardian-verdict">{agent.status === "quarantined" ? "QUARANTINED" : agent.risk_level || "CLEAR"}</span>
            <div className="guardian-agent">{agent.agent_id} // RISK {agent.risk_score || 0}/10</div>
            <div className="guardian-reason">{agent.reasoning || "No active indicators"}</div>
            {agent.status === "quarantined" && <button className="outline-button lift-button" onClick={() => lift(agent.agent_id)}>Lift quarantine</button>}
          </article>
        ))}
      </div>
    </section>
  );
}
