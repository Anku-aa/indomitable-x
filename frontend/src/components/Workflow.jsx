import { useState } from "react";
import { WORKFLOW_NODES } from "../config/appConfig";

export default function Workflow({ response }) {
  const trace = response?.trace || [];
  const [selectedStep, setSelectedStep] = useState("policy_engine");
  const byStep = new Map(trace.map((item) => [item.step, item]));
  const finalStatus = response?.status || "idle";

  return (
    <section className="workflow-section" aria-live="polite">
      <div className="workflow-head">
        <div><div className="section-number">LIVE REQUEST TRACE</div><h2 className="workflow-title">GOVERNANCE PATH</h2></div>
        <span className={`workflow-status ${finalStatus}`}>{finalStatus.replaceAll("_", " ")}</span>
      </div>
      <div className="workflow-track">
        {WORKFLOW_NODES.map(([step, code, description], index) => {
          const item = byStep.get(step);
          const state = item?.status || (response?.status === "processing" ? "processing" : response ? "blocked" : "idle");
          const blocked = state === "blocked" || state === "denied";
          return (
            <div className="workflow-stage" key={step}>
              <article
                className={`workflow-node ${state} ${selectedStep === step ? "selected" : ""}`}
                onClick={() => setSelectedStep(step)}
                role="button"
                tabIndex="0"
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") setSelectedStep(step);
                }}
              >
                <div className="workflow-icon">{blocked ? "!" : index + 1}</div>
                <div className="workflow-code">{code}</div>
                <div className="workflow-label">{item?.label || description}</div>
                <div className="workflow-node-status">{state.replaceAll("_", " ")}</div>
              </article>
              {index < WORKFLOW_NODES.length - 1 && <div className={`workflow-connector ${item ? "active" : ""}`} aria-hidden="true">→</div>}
            </div>
          );
        })}
      </div>
      {response && (
        <div className="workflow-detail">
          <div className="workflow-detail-title">{byStep.get(selectedStep)?.label || "Request details"}</div>
          <pre>{JSON.stringify(byStep.get(selectedStep) || { status: finalStatus }, null, 2)}</pre>
        </div>
      )}
    </section>
  );
}
