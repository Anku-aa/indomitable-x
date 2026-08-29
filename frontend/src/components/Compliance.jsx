import { useDispatch, useSelector } from "react-redux";
import { api, API_BASE } from "../api";
import { reportReceived } from "../store";

export default function Compliance({ toast }) {
  const dispatch = useDispatch();
  const report = useSelector((state) => state.telemetry.report);

  async function generate() {
    try {
      const response = await api("/compliance/report?hours=24");
      dispatch(reportReceived(response));
      toast("Compliance report generated");
    } catch (error) {
      toast(error.message);
    }
  }

  const stats = report?.stats || {};
  return (
    <section className="section" id="compliance" data-reveal>
      <div className="section-head"><div><div className="section-number">04 // Officer view</div><h2 className="section-title">COMPLIANCE</h2></div><div className="report-actions"><button className="outline-button" onClick={() => window.open(`${API_BASE}/compliance/report/pdf?hours=24`)}>Download PDF</button><button className="lime-button" onClick={generate}>Generate report</button></div></div>
      <div className="report">{report ? <><div className="report-summary">{report.summary}</div><div className="report-stats">{Object.entries(stats.decision_breakdown || {}).map(([key, value]) => <span className="stat-pill" key={key}>{key} // {value}</span>)}</div><div className="audit-reason">{stats.total_requests || 0} events analyzed // {report.audit_trail_total || 0} trail records included</div></> : <div className="empty">Generate a time-bounded report from the immutable audit trail.</div>}</div>
    </section>
  );
}
