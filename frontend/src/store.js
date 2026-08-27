import { configureStore, createSlice } from "@reduxjs/toolkit";

const telemetrySlice = createSlice({
  name: "telemetry",
  initialState: {
    audit: [],
    approvals: [],
    guardian: { agents: [], quarantined_agents: [] },
    report: null,
    latestResponse: null,
    connected: false,
    loading: false,
    error: ""
  },
  reducers: {
    snapshotReceived(state, action) {
      Object.assign(state, action.payload, { connected: true, error: "" });
    },
    reportReceived(state, action) { state.report = action.payload; },
    workflowCleared(state) { state.latestResponse = null; },
    responseReceived(state, action) { state.latestResponse = action.payload; },
    requestStarted(state) { state.loading = true; state.error = ""; state.latestResponse = { status: "processing", trace: [] }; },
    requestFinished(state) { state.loading = false; },
    requestFailed(state, action) { state.loading = false; state.error = action.payload; }
  }
});

export const { snapshotReceived, reportReceived, workflowCleared, responseReceived, requestStarted, requestFinished, requestFailed } = telemetrySlice.actions;
export const store = configureStore({ reducer: { telemetry: telemetrySlice.reducer } });
