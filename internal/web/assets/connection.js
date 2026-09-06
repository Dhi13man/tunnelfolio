"use strict";

import { api } from "./api.js";
import { appState, hasFreshAuthority, isReadOnly } from "./state.js";

const lifecycleCopy = {
  disconnected: "Disconnected",
  starting: "Starting tunnel",
  switching: "Switching tunnel",
  restoring: "Restoring tunnel",
  disconnecting: "Disconnecting tunnel",
  failed: "Tunnel operation failed",
  state_conflict: "Managed tunnel conflict",
  observation_unavailable: "Status unavailable",
  active: "Connected",
};

function formatBytes(value) {
  if (!Number.isFinite(value) || value < 0) return "unavailable";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount >= 10 || unit === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`;
}

function formatObserved(value) {
  const date = new Date(value || NaN);
  if (Number.isNaN(date.valueOf())) return "Last checked time unavailable";
  return `Last checked ${date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
}

function evidence(status) {
  const lifecycle = status?.lifecycle;
  if (["starting", "switching", "restoring", "disconnecting"].includes(lifecycle)) return lifecycleCopy[lifecycle];
  if (["failed", "state_conflict", "observation_unavailable"].includes(lifecycle)) return status?.error || lifecycleCopy[lifecycle];
  if (!status?.connected || !status.profile) return status?.error || "No managed tunnel is active.";
  const protocol = status.profile.protocol;
  const protocolStatus = status.protocol_status;
  if (protocolStatus?.state === "observation_unavailable") {
    return `${protocol === "wireguard" ? "WireGuard interface" : "OpenVPN process"} active · protocol observation unavailable`;
  }
  if (protocol === "openvpn") return protocolStatus?.state === "active" ? "OpenVPN active" : "OpenVPN process observed";
  const peers = protocolStatus?.peers || [];
  const handshake = peers.reduce((latest, peer) => Math.max(latest, peer.latest_handshake || 0), 0);
  return handshake > 0 ? "WireGuard interface active · handshake observed" : "WireGuard interface active · no handshake observed";
}

function markerState(status, observationAvailable) {
  if (!observationAvailable || ["failed", "state_conflict", "observation_unavailable"].includes(status?.lifecycle)) return "danger";
  if (["starting", "switching", "restoring", "disconnecting"].includes(status?.lifecycle)) return "warning";
  if (status?.lifecycle !== "active" || !status.connected) return "neutral";
  if (!appState.polling || isReadOnly() || status.protocol_status?.state === "observation_unavailable") return "warning";
  if (status.profile?.protocol === "wireguard" && !status.protocol_status?.peers?.some(peer => peer.latest_handshake > 0)) return "warning";
  return "active";
}

function setText(element, text) {
  if (element.textContent !== text) element.textContent = text;
}

export function createConnectionController({ onStatus, onError, onConnected, onInspect }) {
  const section = document.querySelector("#current-tunnel");
  const title = document.querySelector("#current-title");
  const profileOpen = document.querySelector("#current-profile-open");
  const emptyTitle = document.querySelector("#current-empty-title");
  const stateText = document.querySelector("#current-state");
  const metrics = document.querySelector("#current-metrics");
  const observed = document.querySelector("#current-observed");
  const freshness = document.querySelector("#current-freshness");
  const disconnect = document.querySelector("#disconnect");
  const refresh = document.querySelector("#status-refresh");
  const retry = document.querySelector("#status-retry");
  const pause = document.querySelector("#status-pause");
  const announcer = document.querySelector("#status-announcer");
  let timer = null;
  let lastAnnouncement = "";
  let lastLifecycle = "";
  let lastObservationAvailable;
  let inFlight = false;
  let pendingAction = "";

  function announce(message) {
    if (!message || message === lastAnnouncement) return;
    lastAnnouncement = message;
    announcer.textContent = message;
  }

  function render(status, { stale = appState.statusStale, userInitiated = false } = {}) {
    const priorLifecycle = lastLifecycle;
    const observationAvailable = !!status && !stale && status.observation_available !== false && status.lifecycle !== "observation_unavailable";
    const observationChanged = lastObservationAvailable !== undefined && lastObservationAvailable !== observationAvailable;
    appState.status = status;
    appState.statusStale = stale;
    lastLifecycle = status?.lifecycle || "observation_unavailable";
    lastObservationAvailable = observationAvailable;
    section.dataset.state = markerState(status, observationAvailable);
    if (pendingAction && observationAvailable && section.dataset.state !== "danger") section.dataset.state = "warning";
    section.setAttribute("aria-busy", inFlight || ["starting", "switching", "restoring", "disconnecting"].includes(lastLifecycle) ? "true" : "false");
    const profileName = status?.profile?.display_name;
    const heading = profileName
      ? `${observationAvailable ? "" : "Last known: "}${profileName}`
      : observationAvailable ? lifecycleCopy[lastLifecycle] || "Tunnel status" : "Status unavailable";
    setText(profileOpen, profileName ? heading : "");
    setText(emptyTitle, profileName ? "" : heading);
    profileOpen.hidden = !profileName;
    emptyTitle.hidden = !!profileName;
    if (profileName) profileOpen.setAttribute("aria-label", `${heading} · View profile details`);
    const stateMessage = stale
      ? "Status unavailable · last known observation"
      : !observationAvailable && lastLifecycle !== "state_conflict"
        ? status?.error || "Tunnel status is unavailable."
        : evidence(status);
    setText(stateText, stateMessage);
    const protocolStatus = status?.protocol_status;
    const metricText = status?.connected && protocolStatus && status.profile?.protocol === "wireguard" && protocolStatus.state !== "observation_unavailable"
      ? `${observationAvailable && appState.polling ? "" : "Last known totals · "}Received ${formatBytes(protocolStatus.received_bytes)} · sent ${formatBytes(protocolStatus.sent_bytes)}`
      : "";
    setText(metrics, metricText);
    const checked = formatObserved(status?.observed_at);
    setText(observed, `${appState.polling ? "Updates active" : "Updates paused"} · ${checked}${observationAvailable ? "" : " · last known status"}${stale && status?.profile ? ` · ${evidence(status)}` : ""}`);
    const freshnessParts = [];
    if (!observationAvailable) freshnessParts.push(`Last known status · ${checked}. Refresh status to check the host.`);
    if (!appState.polling) freshnessParts.push(observationAvailable ? `Updates paused · ${checked}` : "Updates paused.");
    if (isReadOnly()) freshnessParts.push("Read-only access · tunnel changes are disabled.");
    if (pendingAction) freshnessParts.push(`${pendingAction} · awaiting host confirmation.`);
    setText(freshness, freshnessParts.join(" "));
    freshness.hidden = !freshnessParts.length;
    retry.hidden = observationAvailable;
    retry.disabled = inFlight;
    const recoveryAllowed = !stale && status?.can_disconnect === true && !isReadOnly();
    disconnect.hidden = !status?.connected && !status?.can_disconnect;
    disconnect.disabled = inFlight || isReadOnly() || (!hasFreshAuthority() && !recoveryAllowed) || ["starting", "switching", "restoring", "disconnecting"].includes(lastLifecycle);
    onStatus(status);
    if (observationChanged) {
      announce(observationAvailable ? "Tunnel status observation restored" : "Tunnel status is unavailable. Last known status remains visible.");
    } else if ((priorLifecycle && priorLifecycle !== lastLifecycle) || userInitiated) {
      if (!observationAvailable) announce(stateMessage);
      else if (lastLifecycle === "active") announce(`${status.profile?.display_name || "Current profile"} · ${evidence(status)}`);
      else if (lastLifecycle === "disconnected") announce("Tunnel disconnected");
      else if (lastLifecycle === "state_conflict") announce(stateMessage);
      else announce(lifecycleCopy[lastLifecycle] || "Tunnel status changed");
    }
  }

  async function refreshStatus({ userInitiated = false } = {}) {
    if (inFlight && !userInitiated) return;
    try {
      const status = await api.status();
      render(status, { stale: false, userInitiated });
      return status;
    } catch (error) {
      if (appState.status) render(appState.status, { stale: true });
      else render({ lifecycle: "observation_unavailable", observation_available: false, error: "Tunnel state could not be observed." }, { stale: true });
      onError(new Error("Could not refresh host status. Last known information is not current. Use Retry status to check again."), { focus: userInitiated });
      return null;
    }
  }

  async function disconnectTunnel() {
    if (inFlight) return;
    inFlight = true;
    appState.connectionBusy = true;
    disconnect.disabled = true;
    pendingAction = "Disconnecting tunnel";
    announce(pendingAction);
    render(appState.status);
    title.focus();
    try {
      await api.disconnect();
      await refreshStatus({ userInitiated: true });
      title.focus();
    } catch (error) {
      onError(error, { focus: true });
      await refreshStatus({ userInitiated: true });
    } finally {
      inFlight = false;
      appState.connectionBusy = false;
      pendingAction = "";
      if (appState.status) render(appState.status);
    }
  }

  function schedule() {
    clearInterval(timer);
    timer = appState.polling ? setInterval(() => refreshStatus(), 5000) : null;
  }

  function togglePolling() {
    appState.polling = !appState.polling;
    pause.setAttribute("aria-pressed", String(!appState.polling));
    if (appState.status) render(appState.status);
    announce(appState.polling ? "Automatic status updates resumed" : "Automatic status updates paused");
    schedule();
  }

  refresh.addEventListener("click", () => refreshStatus({ userInitiated: true }));
  retry.addEventListener("click", () => refreshStatus({ userInitiated: true }));
  profileOpen.addEventListener("click", () => {
    if (appState.status?.profile) onInspect(appState.status.profile);
  });
  pause.addEventListener("click", togglePolling);
  disconnect.addEventListener("click", disconnectTunnel);

  return {
    refresh: refreshStatus,
    connect: async profile => {
      if (inFlight) return;
      inFlight = true;
      appState.connectionBusy = true;
      const switching = appState.status?.connected && appState.status.profile?.id !== profile.id;
      pendingAction = `${switching ? "Switching" : "Connecting"} to ${profile.display_name}`;
      announce(pendingAction);
      render(appState.status);
      title.focus();
      try {
        await api.connect(profile.id);
        await refreshStatus({ userInitiated: true });
        try {
          await onConnected?.();
        } catch (refreshError) {
          onError(new Error("The connection request completed, but the updated library could not be loaded. Refresh the page before changing favorites or settings."), { focus: true });
          return;
        }
        title.focus();
      } catch (error) {
        onError(error, { focus: true });
        await refreshStatus({ userInitiated: true });
      } finally {
        inFlight = false;
        appState.connectionBusy = false;
        pendingAction = "";
        if (appState.status) render(appState.status);
      }
    },
    start: () => schedule(),
    render,
  };
}
