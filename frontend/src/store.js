import { configureStore, createSlice } from "@reduxjs/toolkit";

const telemetrySlice = createSlice({
  name: "telemetry",
  initialState: {
    audit: [],
    approvals: [],
    guardian: { agents: [], quarantined_agents: [] },
    report: null,
    connected: false,
    loading: false,
    error: ""
  },
  reducers: {
    snapshotReceived(state, action) {
      Object.assign(state, action.payload, { connected: true, error: "" });
    },
    reportReceived(state, action) { state.report = action.payload; },
    requestStarted(state) { state.loading = true; state.error = ""; },
    requestFinished(state) { state.loading = false; },
    requestFailed(state, action) { state.loading = false; state.error = action.payload; }
  }
});

export const { snapshotReceived, reportReceived, requestStarted, requestFinished, requestFailed } = telemetrySlice.actions;
export const store = configureStore({ reducer: { telemetry: telemetrySlice.reducer } });
