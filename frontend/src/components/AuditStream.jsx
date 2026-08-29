import { useMemo, useState } from "react";
import { useSelector } from "react-redux";
import { statusOf } from "../api";
import ResultTable from "./ResultTable";

export default function AuditStream() {
  const entries = useSelector((state) => state.telemetry.audit);
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState(new Set());
  const filtered = useMemo(
    () => entries.filter((entry) => !query || `${entry.agent_id} ${entry.query} ${entry.decision}`.toLowerCase().includes(query.toLowerCase())),
    [entries, query],
  );

  return (
    <div className="panel">
      <div className="panel-head"><div className="panel-title">Recent activity</div><div className="panel-tag">{filtered.length} events</div></div>
      <input className="reviewer audit-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search agent, query or decision" />
      <div className="audit-list">
        {filtered.map((entry) => {
          const id = String(entry.id);
          const kind = statusOf(entry);
          const open = expanded.has(id);
          return (
            <article className={`audit-item ${kind} ${open ? "" : "collapsed"}`} key={id}>
              <button className="audit-toggle" onClick={() => setExpanded((current) => {
                const next = new Set(current);
                next.has(id) ? next.delete(id) : next.add(id);
                return next;
              })}>
                <div className="audit-top"><span className="status">{kind}</span><span className="audit-time">{entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : "--"}</span></div>
                {!open && <><div className="audit-agent">{entry.agent_id} // RISK {entry.risk_score || 0}/10</div><div className="audit-query">{entry.query}</div></>}
              </button>
              {open && <><div className="audit-agent">{entry.agent_id} // {entry.decision} // RISK {entry.risk_score || 0}/10</div><div className="audit-query">{entry.query}</div><div className="audit-reason">{(entry.reasons || []).join(" / ") || "No policy exceptions"}</div><ResultTable entry={entry} /></>}
            </article>
          );
        })}
        {!filtered.length && <div className="empty">No matching audit events.</div>}
      </div>
    </div>
  );
}
