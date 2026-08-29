import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { Link, useLocation } from "react-router-dom";
import { api } from "./api";
import {
  requestFailed,
  requestFinished,
  requestStarted,
  responseReceived,
  snapshotReceived,
  workflowCleared,
} from "./store";
import { useToast } from "./hooks/useToast";
import CustomCursor from "./components/CustomCursor";
import ThreeBackdrop from "./components/ThreeBackdrop";
import HeroMotion from "./components/HeroMotion";
import Hero from "./components/Hero";
import Metrics from "./components/Metrics";
import Workflow from "./components/Workflow";
import AuditStream from "./components/AuditStream";
import Approvals from "./components/Approvals";
import AgentRisk from "./components/AgentRisk";
import Guardian from "./components/Guardian";
import Compliance from "./components/Compliance";
import { DEMO_AGENT_KEYS } from "./config/appConfig";

function App() {
  const dispatch = useDispatch();
  const location = useLocation();
  const { connected, loading, error, latestResponse } = useSelector((state) => state.telemetry);
  const [toast, setToast] = useToast();
  const [query, setQuery] = useState("");
  const [selectedAgent, setSelectedAgent] = useState("recruiter_agent");
  const [agentKey, setAgentKey] = useState(() => localStorage.getItem("agenate_key_recruiter_agent") || DEMO_AGENT_KEYS.recruiter_agent);

  async function refreshTelemetry() {
    try {
      const [audit, approvals, guardian] = await Promise.all([api("/audit-log"), api("/approvals"), api("/guardian/status")]);
      dispatch(snapshotReceived({ audit: audit.audit_log || [], approvals: approvals.approvals || [], guardian }));
    } catch (refreshError) {
      dispatch(requestFailed(refreshError.message));
    }
  }

  useEffect(() => {
    refreshTelemetry();
    const interval = setInterval(refreshTelemetry, 5000);
    return () => clearInterval(interval);
  }, [location.key]);

  useEffect(() => {
    const observer = new IntersectionObserver((entries) => entries.forEach((entry) => {
      if (entry.isIntersecting) entry.target.classList.add("is-visible");
    }), { threshold: 0.12 });
    document.querySelectorAll(".section[data-reveal]").forEach((section) => observer.observe(section));
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    setAgentKey(localStorage.getItem(`agenate_key_${selectedAgent}`) || DEMO_AGENT_KEYS[selectedAgent] || "");
  }, [selectedAgent]);

  async function send() {
    if (!query.trim() || loading) return;
    if (agentKey) localStorage.setItem(`agenate_key_${selectedAgent}`, agentKey);
    dispatch(workflowCleared());
    dispatch(requestStarted());
    document.getElementById("governance-path")?.scrollIntoView({ behavior: "smooth", block: "center" });
    try {
      const response = await api("/agent/query", { method: "POST", apiKey: agentKey, body: JSON.stringify({ agent_id: selectedAgent, query: query.trim() }) });
      dispatch(responseReceived(response));
      setQuery("");
      await refreshTelemetry();
      setToast(`Gateway response // ${response.status}`);
      dispatch(requestFinished());
      document.getElementById("audit")?.scrollIntoView({ behavior: "smooth" });
    } catch (sendError) {
      dispatch(responseReceived({ status: "authentication_failed", trace: [{ step: "query_received", label: "Query Received", status: "success" }, { step: "authentication", label: "Authentication", status: "failed", error: sendError.message }, { step: "database", label: "Database", status: "blocked" }, { step: "audit_log", label: "Audit Log", status: "not_written" }] }));
      dispatch(requestFailed(sendError.message));
      setToast(`Gateway rejected // ${sendError.message}`);
    }
  }

  return (
    <>
      <CustomCursor />
      <ThreeBackdrop />
      <div className="noise-overlay" />
      <div className="react-page">
        <nav className="nav"><Link className="logo" to="/">Agen<span>ate</span></Link><div className="nav-links"><a href="#workspace">Control room</a><a href="#guardian">Guardian</a><a href="#compliance">Compliance</a></div><a className="nav-cta" href="#request">Open console</a></nav>
        <main>
          <Hero query={query} setQuery={setQuery} send={send} loading={loading} selectedAgent={selectedAgent} setSelectedAgent={setSelectedAgent} agentKey={agentKey} setAgentKey={setAgentKey} />
          <div id="governance-path"><Workflow response={latestResponse} /></div>
          <section className="section" id="workspace" data-reveal><div className="section-head"><div><div className="section-number">01 // Control room</div><h2 className="section-title">LIVE SIGNAL</h2></div><p className="section-note">Every request leaves a trace. Every sensitive field has a reason.</p></div><Metrics /></section>
          <section className="section" id="audit" data-reveal><div className="section-head"><div><div className="section-number">02 // Evidence</div><h2 className="section-title">AUDIT STREAM</h2></div><p className="section-note">Recent events, decisions and redaction evidence.</p></div><div className="workspace-grid"><AuditStream /><Approvals toast={setToast} onChanged={refreshTelemetry} onResolved={(response) => dispatch(responseReceived(response))} /></div></section>
          <AgentRisk />
          <Guardian toast={setToast} onChanged={refreshTelemetry} />
          <Compliance toast={setToast} />
        </main>
        <footer className="footer"><span><strong>AGENATE</strong> // governed intelligence</span><span>{connected ? "API LINK // ONLINE" : "API LINK // OFFLINE"} // hr_records // 3400 rows</span></footer>
      </div>
      {(loading || error || toast) && <div className="toast show">{loading ? "EVALUATING..." : error || toast}</div>}
      <HeroMotion />
    </>
  );
}

export default App;
