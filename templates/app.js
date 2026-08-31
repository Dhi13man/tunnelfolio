"use strict";

const state = {
  profiles: [],
  favorites: [],
  recents: [],
  tipDismissed: false,
  capabilities: [],
  status: { lifecycle: "loading", activeID: "" },
  query: "",
  backend: "all",
  pending: false,
};

const elements = {
  connection: document.querySelector("#connection"),
  connectionTitle: document.querySelector("#connection-title"),
  connectionDetail: document.querySelector("#connection-detail"),
  connectionMeta: document.querySelector("#connection-meta"),
  connectionActions: document.querySelector("#connection-actions"),
  errorPanel: document.querySelector("#error-panel"),
  errorMessage: document.querySelector("#error-message"),
  errorDismiss: document.querySelector("#error-dismiss"),
  profileList: document.querySelector("#profile-list"),
  emptyState: document.querySelector("#empty-state"),
  resultCount: document.querySelector("#result-count"),
  search: document.querySelector("#profile-search"),
  backend: document.querySelector("#backend-filter"),
  recentSection: document.querySelector("#recent-section"),
  recentList: document.querySelector("#recent-list"),
  dialog: document.querySelector("#settings-dialog"),
  dialogTitle: document.querySelector("#settings-title"),
  settingsOpen: document.querySelector("#settings-open"),
  settingsClose: document.querySelector("#settings-close"),
  favoritesClear: document.querySelector("#favorites-clear"),
  recentsClear: document.querySelector("#recents-clear"),
  favoritesSummary: document.querySelector("#favorites-summary"),
  recentsSummary: document.querySelector("#recents-summary"),
  capabilityList: document.querySelector("#capability-list"),
  announcer: document.querySelector("#status-announcer"),
};

function asText(value) {
  return typeof value === "string" ? value : "";
}

function titleCase(value) {
  return asText(value).replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, letter => letter.toUpperCase());
}

function profileID(profile) {
  return asText(profile.id || profile.profile_id || profile.file);
}

function normalizedProfile(profile) {
  const backend = asText(profile.backend || profile.protocol || "unknown");
  const provider = asText(profile.provider || "generic");
  return {
    id: profileID(profile),
    name: asText(profile.name) || profileID(profile),
    backend,
    provider,
    available: profile.available !== false,
    country: asText(profile.country_name || profile.country),
    flag: asText(profile.flag),
    region: asText(profile.region),
    capabilities: profile.capabilities || {},
  };
}

function uniqueStrings(values) {
  return Array.isArray(values) ? [...new Set(values.filter(value => typeof value === "string"))] : [];
}

function capabilityNames(value) {
  if (Array.isArray(value)) return uniqueStrings(value);
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).filter(([, enabled]) => Boolean(enabled)).map(([name]) => name);
}

async function api(method, path, body) {
  const options = { method, headers: { Accept: "application/json" } };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let payload = {};
  try {
    payload = await response.json();
  } catch (error) {
    if (response.ok) return payload;
    throw new Error("The server returned an unreadable response", { cause: error });
  }
  if (!response.ok) {
    const message = payload && payload.error && (payload.error.message || payload.error);
    throw new Error(asText(message) || "The request failed");
  }
  return payload;
}

function showError(message) {
  elements.errorMessage.textContent = message;
  elements.errorPanel.hidden = false;
  elements.announcer.textContent = `Error: ${message}`;
}

function clearError() {
	const restoreFocus = elements.errorPanel.contains(document.activeElement);
  elements.errorPanel.hidden = true;
  elements.errorMessage.textContent = "";
	if (restoreFocus) elements.connectionTitle.focus();
}

function announce(message) {
  elements.announcer.textContent = "";
  window.requestAnimationFrame(() => { elements.announcer.textContent = message; });
}

function activeProfile() {
  return state.profiles.find(profile => profile.id === state.status.activeID) || state.status.profile || null;
}

function normalizeStatus(payload) {
  const rawProfile = payload.profile && typeof payload.profile === "object" ? normalizedProfile(payload.profile) : null;
  const activeID = (rawProfile && rawProfile.id) || asText(payload.profile_id || payload.profile || payload.interface || payload.active_profile);
  let lifecycle = asText(payload.lifecycle || payload.state || payload.status).toLowerCase();
  if (!lifecycle || lifecycle === "ok") lifecycle = payload.connected ? "connected" : "disconnected";
  return {
    lifecycle,
    activeID,
    profile: rawProfile,
    connectedSince: Number(payload.connected_since || payload.connected_at || 0),
    rxBytes: Number.isFinite(payload.metrics?.received_bytes) ? payload.metrics.received_bytes : null,
    txBytes: Number.isFinite(payload.metrics?.sent_bytes) ? payload.metrics.sent_bytes : null,
    capabilities: capabilityNames(payload.capabilities),
    detail: asText(payload.detail || payload.message),
  };
}

function createButton(label, className, action, disabled = false, focusKey = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.disabled = disabled;
	if (focusKey) button.dataset.focusKey = focusKey;
  button.addEventListener("click", action);
  return button;
}

function appendMeta(list, label, value) {
  if (!value) return;
  const wrapper = document.createElement("div");
  const term = document.createElement("dt");
  const detail = document.createElement("dd");
  term.textContent = label;
  detail.textContent = value;
  wrapper.append(term, detail);
  list.append(wrapper);
}

function formatBytes(value) {
  if (!Number.isFinite(value) || value < 0) return "";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1; }
  return `${amount >= 10 || unit === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`;
}

function renderStatus() {
  const status = state.status;
  const profile = activeProfile();
  const lifecycle = status.lifecycle || "disconnected";
  const busy = state.pending || ["connecting", "switching", "disconnecting"].includes(lifecycle);
  elements.connection.dataset.lifecycle = lifecycle;
  elements.connection.setAttribute("aria-busy", busy ? "true" : "false");
  elements.connectionMeta.replaceChildren();
  elements.connectionActions.replaceChildren();

  const labels = {
    loading: ["Checking status…", "Contacting the VPN manager"],
    disconnected: ["Disconnected", "Choose a profile to establish a VPN connection"],
    connecting: ["Connecting…", profile ? `Starting ${profile.name}` : "Starting the selected profile"],
    switching: ["Switching profiles…", profile ? `Changing to ${profile.name}` : "Changing the active profile"],
    disconnecting: ["Disconnecting…", "Stopping the active VPN connection"],
    connected: [profile ? profile.name : "Connected", status.detail || "VPN connection is active"],
    failed: ["Connection needs attention", status.detail || "The last VPN operation failed"],
    error: ["Connection needs attention", status.detail || "Status is unavailable"],
  };
  const copy = labels[lifecycle] || [titleCase(lifecycle) || "Unknown status", status.detail || "Waiting for a status update"];
  elements.connectionTitle.textContent = copy[0];
  elements.connectionDetail.textContent = copy[1];

  if (profile) {
    appendMeta(elements.connectionMeta, "Backend", titleCase(profile.backend));
    appendMeta(elements.connectionMeta, "Provider", titleCase(profile.provider));
    appendMeta(elements.connectionMeta, "Location", [profile.flag, profile.country || profile.region].filter(Boolean).join(" "));
  }
  appendMeta(elements.connectionMeta, "Received", formatBytes(status.rxBytes));
  appendMeta(elements.connectionMeta, "Sent", formatBytes(status.txBytes));
  elements.connectionMeta.hidden = elements.connectionMeta.childElementCount === 0;

  if (["connected", "failed", "error"].includes(lifecycle) && status.activeID) {
    elements.connectionActions.append(createButton("Disconnect", "button button-danger", disconnect, busy));
  }
}

function metadataTag(text) {
  const tag = document.createElement("span");
  tag.className = "tag";
  tag.textContent = text;
  return tag;
}

function toggleFavorite(profile) {
  const previous = [...state.favorites];
  state.favorites = state.favorites.includes(profile.id) ? state.favorites.filter(id => id !== profile.id) : [...state.favorites, profile.id];
  renderProfiles();
  updatePreferences({ favorites: state.favorites }).catch(error => {
    state.favorites = previous;
    renderProfiles();
    showError(`Favorite was not saved. ${error.message}`);
  });
}

function profileCard(profile) {
  const card = document.createElement("article");
  card.className = "profile-card";
  card.dataset.active = String(profile.id === state.status.activeID);
  const copy = document.createElement("div");
  const heading = document.createElement("h3");
  heading.className = "profile-heading";
  if (profile.flag) {
    const flag = document.createElement("span");
    flag.className = "profile-flag";
    flag.setAttribute("aria-hidden", "true");
    flag.textContent = profile.flag;
    heading.append(flag);
  }
  const name = document.createElement("span");
  name.className = "profile-name";
  name.textContent = profile.name;
  heading.append(name);
  const metadata = document.createElement("p");
  metadata.className = "profile-metadata";
  metadata.append(metadataTag(titleCase(profile.backend)), metadataTag(titleCase(profile.provider)));
  if (profile.country) metadata.append(metadataTag(profile.country));
  else if (profile.region) metadata.append(metadataTag(profile.region));
  copy.append(heading, metadata);

  const actions = document.createElement("div");
  actions.className = "card-actions";
  const favorite = state.favorites.includes(profile.id);
  const favoriteButton = createButton(favorite ? "★" : "☆", "button button-secondary favorite-button", () => toggleFavorite(profile), state.pending);
	favoriteButton.dataset.focusKey = `favorite:${profile.id}`;
  favoriteButton.setAttribute("aria-label", `${favorite ? "Remove" : "Add"} ${profile.name} ${favorite ? "from" : "to"} favorites`);
  favoriteButton.setAttribute("aria-pressed", String(favorite));
  const isActive = profile.id === state.status.activeID && state.status.lifecycle === "connected";
  const connectLabel = profile.available ? (isActive ? "Connected" : "Connect") : "Unavailable";
  const connectButton = createButton(connectLabel, "button button-primary", () => connect(profile), state.pending || isActive || !profile.available);
	connectButton.dataset.focusKey = `connect:${profile.id}`;
	connectButton.setAttribute("aria-label", profile.available ? `${connectLabel} to ${profile.name}` : `${profile.name} is unavailable`);
  actions.append(favoriteButton, connectButton);
  card.append(copy, actions);
  return card;
}

function matchingProfiles() {
  const query = state.query.trim().toLocaleLowerCase();
  return state.profiles.filter(profile => {
    const backendMatches = state.backend === "all" || profile.backend === state.backend;
    const haystack = [profile.name, profile.id, profile.backend, profile.provider, profile.country, profile.region].join(" ").toLocaleLowerCase();
    return backendMatches && (!query || haystack.includes(query));
  }).sort((left, right) => {
    const favoriteDifference = Number(state.favorites.includes(right.id)) - Number(state.favorites.includes(left.id));
    return favoriteDifference || left.name.localeCompare(right.name);
  });
}

function renderRecents() {
  elements.recentList.replaceChildren();
  const profiles = state.recents.map(id => state.profiles.find(profile => profile.id === id)).filter(Boolean);
  for (const profile of profiles) {
    elements.recentList.append(createButton(profile.name, "button button-secondary quick-button", () => connect(profile), state.pending, `recent:${profile.id}`));
  }
  elements.recentSection.hidden = profiles.length === 0;
}

function renderProfiles() {
	const focusKey = document.activeElement?.dataset?.focusKey || "";
  const profiles = matchingProfiles();
  elements.profileList.replaceChildren(...profiles.map(profileCard));
  elements.profileList.setAttribute("aria-busy", "false");
  elements.emptyState.hidden = profiles.length !== 0;
  elements.resultCount.textContent = `${profiles.length} ${profiles.length === 1 ? "profile" : "profiles"}`;
  renderRecents();
  renderSettings();
	if (focusKey) {
		const replacement = [...document.querySelectorAll("[data-focus-key]")].find(element => element.dataset.focusKey === focusKey);
		if (replacement && !replacement.disabled) replacement.focus();
	}
}

function renderBackendOptions() {
  const selected = state.backend;
  const all = document.createElement("option");
  all.value = "all";
  all.textContent = "All backends";
  const options = [...new Set(state.profiles.map(profile => profile.backend).filter(Boolean))].sort().map(backend => {
    const option = document.createElement("option");
    option.value = backend;
    option.textContent = titleCase(backend);
    return option;
  });
  elements.backend.replaceChildren(all, ...options);
  elements.backend.value = options.some(option => option.value === selected) ? selected : "all";
}

function renderSettings() {
  elements.favoritesSummary.textContent = state.favorites.length ? `${state.favorites.length} saved` : "No saved favorites";
  elements.recentsSummary.textContent = state.recents.length ? `${state.recents.length} saved` : "No recent profiles";
  elements.favoritesClear.disabled = state.favorites.length === 0;
  elements.recentsClear.disabled = state.recents.length === 0;
  const capabilities = [...new Set([...state.capabilities, ...state.status.capabilities])].sort();
  elements.capabilityList.replaceChildren();
  if (capabilities.length === 0) {
    const item = document.createElement("li");
    item.textContent = "Not reported by this server";
    elements.capabilityList.append(item);
    return;
  }
  for (const capability of capabilities) {
    const item = document.createElement("li");
    item.className = "tag";
    item.textContent = titleCase(capability);
    elements.capabilityList.append(item);
  }
}

async function updatePreferences(partial) {
	const saved = await api("PUT", "/api/preferences", {
		favorites: partial.favorites ?? state.favorites,
		recents: partial.recents ?? state.recents,
		tip_dismissed: partial.tip_dismissed ?? state.tipDismissed,
	});
  state.favorites = uniqueStrings(saved.favorites ?? state.favorites);
  state.recents = uniqueStrings(saved.recents ?? state.recents);
	state.tipDismissed = Boolean(saved.tip_dismissed ?? state.tipDismissed);
}

async function connect(profile) {
  if (state.pending) return;
  clearError();
  state.pending = true;
  const switching = Boolean(state.status.activeID);
  state.status = { ...state.status, lifecycle: switching ? "switching" : "connecting", activeID: profile.id, profile };
	announce(`${switching ? "Switching" : "Connecting"} to ${profile.name}`);
	elements.connectionTitle.focus();
  renderStatus();
  renderProfiles();
  try {
    const result = await api("POST", "/api/connect", { profile: profile.id });
    state.recents = uniqueStrings(result.recents ?? [profile.id, ...state.recents]);
    state.status = { ...state.status, lifecycle: "connected", activeID: profile.id, profile };
    announce(`Connected to ${profile.name}`);
    await refreshStatus();
  } catch (error) {
    state.status = { ...state.status, lifecycle: "failed", detail: error.message };
    showError(`Could not connect to ${profile.name}. ${error.message}`);
		try { await refreshStatus(); } catch (_) { /* Preserve the actionable mutation error. */ }
  } finally {
    state.pending = false;
    renderStatus();
    renderProfiles();
  }
}

async function disconnect() {
  if (state.pending) return;
  clearError();
  state.pending = true;
  state.status = { ...state.status, lifecycle: "disconnecting" };
	announce("Disconnecting VPN");
	elements.connectionTitle.focus();
  renderStatus();
  renderProfiles();
  try {
    await api("POST", "/api/disconnect");
    state.status = { lifecycle: "disconnected", activeID: "", capabilities: state.status.capabilities };
    announce("VPN disconnected");
  } catch (error) {
    state.status = { ...state.status, lifecycle: "failed", detail: error.message };
    showError(`Could not disconnect. ${error.message}`);
  } finally {
    state.pending = false;
    renderStatus();
    renderProfiles();
  }
}

async function refreshStatus() {
  state.status = normalizeStatus(await api("GET", "/api/status"));
  renderStatus();
  renderProfiles();
}

async function initialize() {
  try {
    const [profilesPayload, preferences, status] = await Promise.all([
      api("GET", "/api/profiles"),
      api("GET", "/api/preferences"),
      api("GET", "/api/status"),
    ]);
    const profiles = Array.isArray(profilesPayload) ? profilesPayload : profilesPayload.profiles;
    state.profiles = Array.isArray(profiles) ? profiles.map(normalizedProfile).filter(profile => profile.id) : [];
    state.capabilities = capabilityNames(profilesPayload.capabilities);
    state.favorites = uniqueStrings(preferences.favorites);
    state.recents = uniqueStrings(preferences.recents);
		state.tipDismissed = Boolean(preferences.tip_dismissed);
    state.status = normalizeStatus(status);
    renderBackendOptions();
    renderStatus();
    renderProfiles();
  } catch (error) {
    state.status = { lifecycle: "error", activeID: "", detail: error.message, capabilities: [] };
    elements.profileList.replaceChildren();
    elements.profileList.setAttribute("aria-busy", "false");
    elements.emptyState.hidden = false;
    elements.emptyState.querySelector("h3").textContent = "Profiles unavailable";
    elements.emptyState.querySelector("p").textContent = "Resolve the server error, then reload this page.";
    showError(`Tunnelfolio could not load. ${error.message}`);
    renderStatus();
  }
}

elements.profileTools = document.querySelector("#profile-tools");
elements.profileTools.addEventListener("submit", event => event.preventDefault());
elements.search.addEventListener("input", event => { state.query = event.currentTarget.value; renderProfiles(); });
elements.backend.addEventListener("change", event => { state.backend = event.currentTarget.value; renderProfiles(); });
elements.errorDismiss.addEventListener("click", clearError);
elements.settingsOpen.addEventListener("click", () => { elements.dialog.showModal(); elements.dialogTitle.focus(); });
elements.settingsClose.addEventListener("click", () => elements.dialog.close());
elements.dialog.addEventListener("close", () => elements.settingsOpen.focus());
elements.favoritesClear.addEventListener("click", async () => {
  if (!window.confirm("Remove all saved favorites?")) return;
  const previous = [...state.favorites];
  state.favorites = [];
  renderProfiles();
  try { await updatePreferences({ favorites: [] }); announce("Favorites cleared"); }
  catch (error) { state.favorites = previous; renderProfiles(); showError(`Favorites were not cleared. ${error.message}`); }
});
elements.recentsClear.addEventListener("click", async () => {
  if (!window.confirm("Remove all recent profiles?")) return;
  const previous = [...state.recents];
  state.recents = [];
  renderProfiles();
  try { await updatePreferences({ recents: [] }); announce("Recent profiles cleared"); }
  catch (error) { state.recents = previous; renderProfiles(); showError(`Recent profiles were not cleared. ${error.message}`); }
});

initialize();
window.setInterval(() => {
  if (!state.pending && !document.hidden) refreshStatus().catch(error => showError(`Status refresh failed. ${error.message}`));
}, 5000);
