import { useEffect, useMemo, useRef, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { Link, useLocation } from "react-router-dom";
import gsap from "gsap";
import * as THREE from "three";
import { api, API_BASE, statusOf } from "./api";
import { reportReceived, requestFailed, requestFinished, requestStarted, snapshotReceived } from "./store";

function useToast() {
  const [message, setMessage] = useState("");
  useEffect(() => { if (!message) return undefined; const timer = setTimeout(() => setMessage(""), 2800); return () => clearTimeout(timer); }, [message]);
  return [message, setMessage];
}

function CustomCursor() {
  const dot = useRef(null);
  const ring = useRef(null);
  useEffect(() => {
    if (window.matchMedia("(pointer: coarse)").matches) return undefined;
    document.body.classList.add("has-custom-cursor");
    const move = (event) => {
      if (dot.current) { dot.current.style.left = `${event.clientX}px`; dot.current.style.top = `${event.clientY}px`; }
      if (ring.current) { ring.current.style.left = `${event.clientX}px`; ring.current.style.top = `${event.clientY}px`; }
    };
    const over = (event) => { if (event.target.closest("a,button,input,textarea")) ring.current?.classList.add("cursor-active"); };
    const out = (event) => { if (event.target.closest("a,button,input,textarea")) ring.current?.classList.remove("cursor-active"); };
    window.addEventListener("pointermove", move);
    document.addEventListener("pointerover", over);
    document.addEventListener("pointerout", out);
    return () => { document.body.classList.remove("has-custom-cursor"); window.removeEventListener("pointermove", move); document.removeEventListener("pointerover", over); document.removeEventListener("pointerout", out); };
  }, []);
  return <><div ref={dot} className="cursor-dot" aria-hidden="true" /><div ref={ring} className="cursor-ring" aria-hidden="true" /></>;
}

function ThreeBackdrop() {
  const canvas = useRef(null);
  useEffect(() => {
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(42, window.innerWidth / window.innerHeight, 0.1, 100);
    camera.position.z = 7;
    const renderer = new THREE.WebGLRenderer({ canvas: canvas.current, alpha: true, antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
    renderer.setSize(window.innerWidth, window.innerHeight);
    const points = new THREE.BufferGeometry();
    const positions = new Float32Array(220 * 3);
    for (let index = 0; index < positions.length; index += 3) {
      positions[index] = (Math.random() - 0.5) * 13;
      positions[index + 1] = (Math.random() - 0.5) * 8;
      positions[index + 2] = (Math.random() - 0.5) * 7;
    }
    points.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    const stars = new THREE.Points(points, new THREE.PointsMaterial({ color: 0xdfff00, size: 0.025, transparent: true, opacity: 0.65 }));
    const ring = new THREE.Mesh(new THREE.TorusGeometry(2.2, 0.006, 8, 90), new THREE.MeshBasicMaterial({ color: 0xdfff00, transparent: true, opacity: 0.18 }));
    ring.rotation.x = 1.1;
    scene.add(stars, ring);
    let frame;
    const animate = () => { stars.rotation.y += 0.0007; ring.rotation.z += 0.0012; renderer.render(scene, camera); frame = requestAnimationFrame(animate); };
    animate();
    const resize = () => { camera.aspect = window.innerWidth / window.innerHeight; camera.updateProjectionMatrix(); renderer.setSize(window.innerWidth, window.innerHeight); };
    window.addEventListener("resize", resize);
    return () => { cancelAnimationFrame(frame); window.removeEventListener("resize", resize); renderer.dispose(); points.dispose(); };
  }, []);
  return <canvas ref={canvas} className="three-backdrop" aria-hidden="true" />;
}

function HeroMotion() {
  useEffect(() => {
    const timeline = gsap.timeline();
    timeline.from(".hero-word", { yPercent: 115, opacity: 0, duration: 1.15, stagger: 0.12, ease: "power4.out", delay: 0.35 });
    timeline.from([".hero-kicker", ".hero-bottom", ".query-card"], { y: 24, opacity: 0, duration: 0.8, stagger: 0.12, ease: "power3.out" }, "-=0.65");
    const orbit = gsap.to(".hero-orb", { rotation: 16, x: "-3vw", y: "2vh", duration: 12, repeat: -1, yoyo: true, ease: "sine.inOut" });
    return () => { timeline.kill(); orbit.kill(); };
  }, []);
  return null;
}

function ResultTable({ entry }) {
  const [expanded, setExpanded] = useState(false);
  const result = entry.result?.result || entry.result;
  const rows = Array.isArray(result?.rows) ? result.rows : [];
  if (!rows.length) return null;
  const total = Number(result.row_count) || rows.length;
  const visible = expanded ? rows : rows.slice(0, 5);
  const columns = Object.keys(rows[0]).slice(0, 7);
  return <div className="result-box">
    <table><thead><tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr></thead>
      <tbody>{visible.map((row, index) => <tr key={`${entry.id}-${index}`}>{columns.map((column) => <td className={row[column] === "***REDACTED***" ? "redacted" : ""} key={column}>{String(row[column] ?? "")}</td>)}</tr>)}</tbody>
    </table>
    <div className="result-actions"><span className="result-count">Showing {visible.length.toLocaleString()} of {total.toLocaleString()} rows</span>{total > 5 && <button className="result-expand" onClick={() => setExpanded((value) => !value)}>{expanded ? "Collapse rows" : `Show all ${total.toLocaleString()} rows`}</button>}</div>
  </div>;
}

const WORKFLOW_NODES = [
  ["query_received", "QUERY", "Natural-language request"],
  ["authentication", "AUTH", "Identity verified"],
  ["llm_interpreter", "LLM", "Intent to structured query"],
  ["policy_engine", "POLICY", "Permissions and risk"],
  ["decision", "DECISION", "Allow, approval or deny"],
  ["database", "DATABASE", "Governed execution"],
  ["audit_log", "AUDIT", "Tamper-evident record"],
];

function Workflow({ response }) {
  const trace = response?.trace || [];
  const [selectedStep, setSelectedStep] = useState("policy_engine");
  const byStep = new Map(trace.map((item) => [item.step, item]));
  const finalStatus = response?.status || "idle";
  return <section className="workflow-section" aria-live="polite">
    <div className="workflow-head"><div><div className="section-number">LIVE REQUEST TRACE</div><h2 className="workflow-title">GOVERNANCE PATH</h2></div><span className={`workflow-status ${finalStatus}`}>{finalStatus.replaceAll("_", " ")}</span></div>
    <div className="workflow-track">{WORKFLOW_NODES.map(([step, code, description], index) => {
      const item = byStep.get(step);
      const state = item?.status || (response ? "blocked" : "idle");
      const blocked = state === "blocked" || state === "denied";
      return <div className="workflow-stage" key={step}>
        <article className={`workflow-node ${state} ${selectedStep === step ? "selected" : ""}`} onClick={() => setSelectedStep(step)} role="button" tabIndex="0" onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") setSelectedStep(step); }}><div className="workflow-icon">{blocked ? "!" : index + 1}</div><div className="workflow-code">{code}</div><div className="workflow-label">{item?.label || description}</div><div className="workflow-node-status">{state.replaceAll("_", " ")}</div></article>
        {index < WORKFLOW_NODES.length - 1 && <div className={`workflow-connector ${item ? "active" : ""}`} aria-hidden="true">→</div>}
      </div>;
    })}</div>
    {response && <div className="workflow-detail"><div className="workflow-detail-title">{byStep.get(selectedStep)?.label || "Request details"}</div><pre>{JSON.stringify(byStep.get(selectedStep) || { status: finalStatus }, null, 2)}</pre></div>}
  </section>;
}

function AuditStream() {
  const entries = useSelector((state) => state.telemetry.audit);
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState(new Set());
  const filtered = useMemo(() => entries.filter((entry) => !query || `${entry.agent_id} ${entry.query} ${entry.decision}`.toLowerCase().includes(query.toLowerCase())), [entries, query]);
  return <div className="panel"><div className="panel-head"><div className="panel-title">Recent activity</div><div className="panel-tag">{filtered.length} events</div></div>
    <input className="reviewer audit-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search agent, query or decision" />
    <div className="audit-list">{filtered.slice(0, 25).map((entry, index) => { const id = String(entry.id); const kind = statusOf(entry); const open = index === 0 || expanded.has(id); return <article className={`audit-item ${kind} ${open ? "" : "collapsed"}`} key={id}>
      <button className="audit-toggle" onClick={() => setExpanded((current) => { const next = new Set(current); next.has(id) ? next.delete(id) : next.add(id); return next; })}><div className="audit-top"><span className="status">{kind}</span><span className="audit-time">{entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : "--"}</span></div>{!open && <><div className="audit-agent">{entry.agent_id} // RISK {entry.risk_score || 0}/10</div><div className="audit-query">{entry.query}</div></>}</button>
      {open && <><div className="audit-agent">{entry.agent_id} // {entry.decision} // RISK {entry.risk_score || 0}/10</div><div className="audit-query">{entry.query}</div><div className="audit-reason">{(entry.reasons || []).join(" / ") || "No policy exceptions"}</div><ResultTable entry={entry} /></>}
    </article>; })}{!filtered.length && <div className="empty">No matching audit events.</div>}</div>
  </div>;
}

function Approvals({ toast, onChanged }) {
  const items = useSelector((state) => state.telemetry.approvals);
  const quarantined = useSelector((state) => (state.telemetry.guardian.quarantined_agents || []).map((agent) => agent.agent_id));
  const unique = [...new Map(items.map((item) => [String(item.id), item])).values()];
  async function review(item, approve) {
    const held = item.status === "auto_held_quarantine" || quarantined.includes(item.agent_id);
    if (approve && held && !window.confirm("This agent is quarantined. Confirm explicit override and approval?")) return;
    const reviewer = window.prompt("Reviewer name", "console operator") || "console operator";
    try { await api(`/approvals/${item.id}`, { method: "POST", body: JSON.stringify({ approve, reviewer, confirm_quarantine_override: held && approve }) }); await onChanged(); toast(approve ? "Request approved" : "Request rejected"); } catch (error) { toast(error.message); }
  }
  return <div className="panel"><div className="panel-head"><div className="panel-title">Approvals</div><div className="panel-tag">{unique.length} waiting</div></div><div className="approval-list">{unique.map((item) => { const held = item.status === "auto_held_quarantine" || quarantined.includes(item.agent_id); return <article className={`approval ${held ? "held" : ""}`} key={item.id}><div className="approval-id">REQUEST #{item.id} // RISK {item.policy?.risk_score || "--"}{item.parsed_query?.operation === "DELETE" ? " // DESTRUCTIVE" : ""}</div><div className="approval-query">{item.query}</div><div className="approval-meta">AGENT // {item.agent_id}<br />STATE // {item.status}</div>{held && <div className="warning">WARNING // Quarantined after submission. Explicit override required.</div>}<div className="approval-actions"><button className="approve" onClick={() => review(item, true)}>{held ? "Override + approve" : "Approve"}</button><button className="reject" onClick={() => review(item, false)}>Reject</button></div></article>; })}{!unique.length && <div className="empty">No requests waiting.</div>}</div></div>;
}

function Guardian({ toast, onChanged }) {
  const guardian = useSelector((state) => state.telemetry.guardian);
  async function run() { try { await api("/guardian/run", { method: "POST" }); await onChanged(); toast("Guardian analysis complete"); } catch (error) { toast(error.message); } }
  async function lift(agent) { try { await api(`/guardian/lift/${agent}`, { method: "POST" }); await onChanged(); toast("Quarantine lifted"); } catch (error) { toast(error.message); } }
  return <section className="section" id="guardian" data-reveal><div className="section-head"><div><div className="section-number">03 // Autonomous defense</div><h2 className="section-title">GUARDIAN</h2></div><div><p className="section-note">Independent behavior analysis. Human judgment remains final.</p><button className="outline-button guardian-run" onClick={run}>Run guardian check</button></div></div><div className="guardian-grid">{(guardian.agents || []).map((agent) => <article className={`guardian-card ${agent.status === "quarantined" ? "quarantined" : ""}`} key={agent.agent_id}><span className="guardian-verdict">{agent.status === "quarantined" ? "QUARANTINED" : "CLEAR"}</span><div className="guardian-agent">{agent.agent_id}</div><div className="guardian-reason">{agent.reasoning || "No active indicators"}</div>{agent.status === "quarantined" && <button className="outline-button lift-button" onClick={() => lift(agent.agent_id)}>Lift quarantine</button>}</article>)}</div></section>;
}

function Compliance({ toast }) {
  const dispatch = useDispatch();
  const report = useSelector((state) => state.telemetry.report);
  async function generate() { try { const response = await api("/compliance/report?hours=24"); dispatch(reportReceived(response)); toast("Compliance report generated"); } catch (error) { toast(error.message); } }
  const stats = report?.stats || {};
  return <section className="section" id="compliance" data-reveal><div className="section-head"><div><div className="section-number">04 // Officer view</div><h2 className="section-title">COMPLIANCE</h2></div><div className="report-actions"><button className="outline-button" onClick={() => window.open(`${API_BASE}/compliance/report/pdf?hours=24`)}>Download PDF</button><button className="lime-button" onClick={generate}>Generate report</button></div></div><div className="report">{report ? <><div className="report-summary">{report.summary}</div><div className="report-stats">{Object.entries(stats.decision_breakdown || {}).map(([key, value]) => <span className="stat-pill" key={key}>{key} // {value}</span>)}</div><div className="audit-reason">{stats.total_requests || 0} events analyzed // {report.audit_trail_total || 0} trail records included</div></> : <div className="empty">Generate a time-bounded report from the immutable audit trail.</div>}</div></section>;
}

function App() {
  const dispatch = useDispatch();
  const location = useLocation();
  const { connected, loading, error } = useSelector((state) => state.telemetry);
  const [toast, setToast] = useToast();
  const [query, setQuery] = useState("");
  const [lastResponse, setLastResponse] = useState(null);
  async function refreshTelemetry() {
    try {
      const [audit, approvals, guardian] = await Promise.all([api("/audit-log"), api("/approvals"), api("/guardian/status")]);
      dispatch(snapshotReceived({ audit: audit.audit_log || [], approvals: approvals.approvals || [], guardian }));
    } catch (refreshError) {
      dispatch(requestFailed(refreshError.message));
    }
  }
  useEffect(() => { refreshTelemetry(); const interval = setInterval(refreshTelemetry, 5000); return () => clearInterval(interval); }, [location.key]);
  useEffect(() => {
    const observer = new IntersectionObserver((entries) => entries.forEach((entry) => {
      if (entry.isIntersecting) entry.target.classList.add("is-visible");
    }), { threshold: 0.12 });
    document.querySelectorAll(".section[data-reveal]").forEach((section) => observer.observe(section));
    return () => observer.disconnect();
  }, []);
  async function send() { if (!query.trim() || loading) return; dispatch(requestStarted()); try { const response = await api("/agent/query", { method: "POST", body: JSON.stringify({ query: query.trim() }) }); setLastResponse(response); setQuery(""); await refreshTelemetry(); setToast(`Gateway response // ${response.status}`); dispatch(requestFinished()); document.getElementById("audit")?.scrollIntoView({ behavior: "smooth" }); } catch (sendError) { setLastResponse({ status: "authentication_failed", trace: [{ step: "query_received", label: "Query Received", status: "success" }, { step: "authentication", label: "Authentication", status: "failed" }, { step: "database", label: "Database", status: "blocked" }, { step: "audit_log", label: "Audit Log", status: "success" }] }); dispatch(requestFailed(sendError.message)); setToast(`Gateway rejected // ${sendError.message}`); } }
  return <><CustomCursor /><ThreeBackdrop /><div className="noise-overlay" /><div className="react-page"><nav className="nav"><Link className="logo" to="/">AGENT<span>GATE</span></Link><div className="nav-links"><a href="#workspace">Control room</a><a href="#guardian">Guardian</a><a href="#compliance">Compliance</a><a className="nav-cta" href="#request">Transmit</a></div><a className="nav-cta" href="#request">Open console</a></nav>
    <main><Hero query={query} setQuery={setQuery} send={send} loading={loading} /><Workflow response={lastResponse} /><section className="section" id="workspace" data-reveal><div className="section-head"><div><div className="section-number">01 // Control room</div><h2 className="section-title">LIVE SIGNAL</h2></div><p className="section-note">Every request leaves a trace. Every sensitive field has a reason.</p></div><Metrics /></section><div className="marquee"><div className="marquee-track">INTERPRET <span>///</span> EVALUATE <span>///</span> REDACT <span>///</span> AUDIT <span>///</span> APPROVE <span>///</span></div></div>
      <section className="section" id="audit" data-reveal><div className="section-head"><div><div className="section-number">02 // Evidence</div><h2 className="section-title">AUDIT STREAM</h2></div><p className="section-note">Recent events, decisions and redaction evidence.</p></div><div className="workspace-grid"><AuditStream /><Approvals toast={setToast} onChanged={refreshTelemetry} /></div></section><Guardian toast={setToast} onChanged={refreshTelemetry} /><Compliance toast={setToast} /></main><footer className="footer"><span><strong>AGENTGATE</strong> // governed intelligence</span><span>{connected ? "API LINK // ONLINE" : "API LINK // OFFLINE"} // hr_records // 3400 rows</span></footer></div>{(loading || error || toast) && <div className="toast show">{loading ? "EVALUATING..." : error || toast}</div>}<HeroMotion /></>;
}

function Hero({ query, setQuery, send, loading }) { return <><section id="hero"><div className="hero-grid" /><div className="hero-orb" /><div className="hero-meta">// Autonomous governance<br />// hr_records / 3,400 records<br />// system online</div><div className="hero-kicker">Your agents can ask. They cannot decide.</div><h1 className="hero-title"><span className="hero-line"><span className="hero-word">AGENTS</span></span><span className="hero-line"><span className="hero-word accent">WITH</span></span><span className="hero-line"><span className="hero-word">BOUNDARIES</span></span></h1><div className="hero-bottom"><p className="hero-desc">AgentGate is the control layer between <strong>natural language</strong> and your database. Interpret intent. Enforce policy. Redact risk. Keep proof.</p><div className="scroll-note">Scroll to inspect<br />↓ ↓ ↓</div></div><div className="query-card" id="request"><div className="query-label">// Send governed request</div><textarea value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => { if ((event.metaKey || event.ctrlKey) && event.key === "Enter") send(); }} rows="3" placeholder="Ask your data something..." /><div className="query-row"><span className="query-hint">⌘ + ENTER to transmit</span><button className="lime-button" onClick={send} disabled={loading}>{loading ? "Evaluating..." : "Transmit ↗"}</button></div></div></section><div className="marquee"><div className="marquee-track">INTERPRET <span>///</span> EVALUATE <span>///</span> REDACT <span>///</span> AUDIT <span>///</span> APPROVE <span>///</span></div></div></>; }
function Metrics() { const audit = useSelector((state) => state.telemetry.audit); const approvals = useSelector((state) => state.telemetry.approvals); const quarantine = useSelector((state) => state.telemetry.guardian.quarantined_agents || []); return <div className="metrics"><Metric label="Requests / trail" value={audit.length} foot="AUDIT EVENTS" /><Metric label="Executed" value={audit.filter((entry) => ["executed", "approved"].includes(statusOf(entry))).length} foot="POLICY ALLOWED" /><Metric label="Review queue" value={approvals.length} foot="HUMAN APPROVAL" /><Metric label="Quarantined" value={quarantine.length} foot="GUARDIAN SIGNAL" /></div>; }
function Metric({ label, value, foot }) { return <div className="metric"><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-foot">{foot}</div></div>; }

export default App;
