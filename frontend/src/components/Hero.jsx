import { AGENT_OPTIONS } from "../config/appConfig";

export default function Hero({ query, setQuery, send, loading, selectedAgent, setSelectedAgent, agentKey, setAgentKey }) {
  return (
    <>
      <section id="hero">
        <div className="hero-grid" /><div className="hero-orb" />
        <div className="hero-meta">// Autonomous governance<br />// hr_records / 3,400 records<br />// system online</div>
        <div className="hero-kicker">YOUR AGENTS CAN ACT. AGENATE DECIDES.</div>
        <h1 className="hero-title"><span className="hero-line"><span className="hero-word">AGENTS</span></span><span className="hero-line"><span className="hero-word accent">WITH</span></span><span className="hero-line"><span className="hero-word">BOUNDARIES</span></span></h1>
        <div className="hero-bottom"><p className="hero-desc">Agenate is the control layer between <strong>natural language</strong> and your database. Interpret intent. Enforce policy. Redact risk. Keep proof.</p><div className="scroll-note">Scroll to inspect<br />↓ ↓ ↓</div></div>
        <div className="query-card" id="request">
          <div className="query-label">// Send governed request</div>
          <div className="agent-picker"><label htmlFor="agent-select">Identity / agent</label><select id="agent-select" value={selectedAgent} onChange={(event) => setSelectedAgent(event.target.value)}>{AGENT_OPTIONS.map((agent) => <option value={agent} key={agent}>{agent}</option>)}</select></div>
          <input className="agent-key" type="password" value={agentKey} onChange={(event) => setAgentKey(event.target.value)} placeholder="Bearer key for selected agent" autoComplete="off" />
          <textarea value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => { if (event.key !== "Enter" || event.shiftKey) return; event.preventDefault(); send(); }} rows="3" placeholder="Ask your data something..." />
          <div className="query-row"><span className="query-hint">Key stays local // ENTER to transmit // SHIFT + ENTER for newline</span><button className="lime-button" onClick={send} disabled={loading}>{loading ? "Evaluating..." : "Transmit ↗"}</button></div>
        </div>
      </section>
      <div className="marquee"><div className="marquee-track">INTERPRET <span>///</span> EVALUATE <span>///</span> REDACT <span>///</span> AUDIT <span>///</span> APPROVE <span>///</span></div></div>
    </>
  );
}
