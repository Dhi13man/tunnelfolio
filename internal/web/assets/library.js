"use strict";

import { appState, isReadOnly } from "./state.js";

function protocolName(protocol) {
  return protocol === "wireguard" ? "WireGuard" : "OpenVPN";
}

function rowState(profile) {
  const connected = appState.status?.connected && appState.status.profile?.id === profile.id;
  const labels = [protocolName(profile.protocol)];
  if (!profile.available) labels.push("Unavailable");
  if (appState.selectedID === profile.id) labels.push("Shown in details");
  if (connected) labels.push("Connected");
  return labels.join(" · ");
}

function matches(profile) {
  const { view, group, location, protocol, search } = appState.filters;
  if (view === "favorites" && !profile.favorite) return false;
  if (view === "recent" && !profile.recent) return false;
  if (group && profile.group !== group) return false;
  if (location && profile.location !== location) return false;
  if (protocol && profile.protocol !== protocol) return false;
  const needle = search.trim().toLocaleLowerCase();
  if (!needle) return true;
  return [profile.display_name, profile.group, profile.location, profile.protocol, profile.identifier]
    .some(value => String(value || "").toLocaleLowerCase().includes(needle));
}

function appendText(parent, className, text) {
  const span = document.createElement("span");
  span.className = className;
  span.textContent = text;
  parent.append(span);
  return span;
}

export function createLibraryController({ onSelect, onImport, onRetry }) {
  const main = document.querySelector("#main-content");
  const list = document.querySelector("#profile-list");
  const count = document.querySelector("#result-count");
  const group = document.querySelector("#group-filter");
  const location = document.querySelector("#location-filter");
  const protocol = document.querySelector("#protocol-filter");
  const search = document.querySelector("#profile-search");
  const views = [...document.querySelectorAll('input[name="profile-view"]')];
  const skip = document.querySelector("#skip-profile-list");
  const firstUse = document.querySelector("#library-empty");
  const filteredEmpty = document.querySelector("#filtered-empty");
  const loadError = document.querySelector("#library-error");
  const importEmpty = document.querySelector("#empty-import");
  const clearFilters = document.querySelector("#clear-filters");
  const retry = document.querySelector("#library-retry");
  let failed = false;

  function refreshGroups() {
    const selected = appState.filters.group;
    const groups = [...new Set(appState.profiles.map(profile => profile.group))]
      .sort((left, right) => left.localeCompare(right, undefined, { sensitivity: "base" }));
    group.replaceChildren();
    const all = document.createElement("option");
    all.value = "";
    all.textContent = "All groups";
    group.append(all);
    for (const value of groups) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      group.append(option);
    }
    if (groups.includes(selected)) group.value = selected;
    else {
      appState.filters.group = "";
      group.value = "";
    }
  }

  function refreshLocations() {
    const selected = appState.filters.location;
    const locations = [...new Set(appState.profiles.map(profile => profile.location).filter(Boolean))]
      .sort((left, right) => left.localeCompare(right, undefined, { sensitivity: "base" }));
    location.replaceChildren();
    const all = document.createElement("option");
    all.value = "";
    all.textContent = "All locations";
    location.append(all);
    for (const value of locations) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      location.append(option);
    }
    location.hidden = locations.length === 0;
    location.labels[0].hidden = locations.length === 0;
    if (locations.includes(selected)) location.value = selected;
    else {
      appState.filters.location = "";
      location.value = "";
    }
  }

  function render() {
    main.setAttribute("aria-busy", "false");
    loadError.hidden = !failed;
    if (failed) {
      list.replaceChildren();
      count.textContent = "Library unavailable";
      firstUse.hidden = true;
      filteredEmpty.hidden = true;
      return;
    }
    refreshGroups();
    refreshLocations();
    const profiles = appState.profiles.filter(matches);
    list.replaceChildren();
    for (const profile of profiles) {
      const item = document.createElement("li");
      item.className = "profile-row";
      const button = document.createElement("button");
      button.type = "button";
      button.className = "profile-row-button";
      button.dataset.profileId = profile.id;
      button.dataset.focusKey = `profile:${profile.id}`;
      button.dataset.selected = String(appState.selectedID === profile.id);
      if (appState.selectedID === profile.id) button.setAttribute("aria-current", "true");
      button.dataset.connected = String(appState.status?.connected && appState.status.profile?.id === profile.id);
      appendText(button, "profile-name", profile.display_name);
      appendText(button, "profile-meta", [profile.group, profile.location].filter(Boolean).join(" · "));
      appendText(button, "profile-state", rowState(profile));
      button.addEventListener("click", () => {
        appState.profileScroll = {
          library: document.querySelector("#library-screen").scrollTop,
          window: window.scrollY,
        };
        onSelect(profile, button);
      });
      item.append(button);
      list.append(item);
    }
    const anyProfiles = appState.profiles.length > 0;
    firstUse.hidden = anyProfiles;
    filteredEmpty.hidden = !anyProfiles || profiles.length > 0;
    list.hidden = profiles.length === 0;
    skip.hidden = !appState.selectedID || profiles.length === 0;
    count.textContent = `${profiles.length} ${profiles.length === 1 ? "profile" : "profiles"}`;
    importEmpty.disabled = isReadOnly();
  }

  function updateConnectionMarkers() {
    for (const button of list.querySelectorAll(".profile-row-button")) {
      const profile = appState.profiles.find(candidate => candidate.id === button.dataset.profileId);
      if (!profile) continue;
      const connected = appState.status?.connected && appState.status.profile?.id === profile.id;
      button.dataset.connected = String(connected);
      const state = button.querySelector(".profile-state");
      if (state) state.textContent = rowState(profile);
    }
  }

  function restoreSelectedRow({ focus = true } = {}) {
    main.dataset.screen = "library";
    const button = list.querySelector(`[data-profile-id="${CSS.escape(appState.selectedID)}"]`);
    if (button && focus) button.focus({ preventScroll: true });
    const saved = appState.profileScroll || { library: 0, window: 0 };
    const restoreScroll = () => {
      document.querySelector("#library-screen").scrollTop = saved.library || 0;
      window.scrollTo({ top: saved.window || 0, behavior: "instant" });
    };
    restoreScroll();
    requestAnimationFrame(restoreScroll);
  }

  function clearAllFilters() {
    appState.filters = { view: "all", group: "", location: "", protocol: "", search: "" };
    views.find(input => input.value === "all").checked = true;
    group.value = "";
    location.value = "";
    protocol.value = "";
    search.value = "";
    render();
    search.focus();
  }

  views.forEach(input => input.addEventListener("change", () => {
    if (!input.checked) return;
    appState.filters.view = input.value;
    render();
  }));
  group.addEventListener("change", () => { appState.filters.group = group.value; render(); });
  location.addEventListener("change", () => { appState.filters.location = location.value; render(); });
  protocol.addEventListener("change", () => { appState.filters.protocol = protocol.value; render(); });
  search.addEventListener("input", () => { appState.filters.search = search.value; render(); });
  document.querySelector("#profile-filters").addEventListener("submit", event => event.preventDefault());
  importEmpty.addEventListener("click", event => onImport(event.currentTarget));
  clearFilters.addEventListener("click", clearAllFilters);
  retry.addEventListener("click", onRetry);

  return {
    render,
    updateConnectionMarkers,
    restoreSelectedRow,
    visibleProfileIDs: () => appState.profiles.filter(matches).map(profile => profile.id),
    fail: value => { failed = value; render(); },
    row: id => list.querySelector(`[data-profile-id="${CSS.escape(id)}"]`),
  };
}
