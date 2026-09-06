"use strict";

import { appState, isReadOnly, profileByID } from "./state.js";

function protocolName(protocol) {
  return protocol === "wireguard" ? "WireGuard" : "OpenVPN";
}

function rowState(profile) {
  const connected = appState.status?.connected && appState.status.profile?.id === profile.id;
  const labels = [];
  if (!profile.available) labels.push("Unavailable");
  if (connected) labels.push(appState.statusStale || appState.status?.observation_available === false || appState.status?.lifecycle === "state_conflict" ? "Last known current" : "Current tunnel");
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

function icon(name, className) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", `icon ${className}`);
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#icon-${name}`);
  svg.append(use);
  return svg;
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
  const filters = document.querySelector("#profile-filters");
  const toggle = document.querySelector("#filters-toggle");
  const panel = document.querySelector("#filter-panel");
  const chips = document.querySelector("#active-filters");
  const context = document.querySelector("#library-context");
  let failed = false;
  let chipSignature = "";

  function refreshFacet(select, key, label) {
    const values = [...new Set(appState.profiles.map(profile => profile[key]).filter(Boolean))]
      .sort((left, right) => left.localeCompare(right, undefined, { sensitivity: "base" }));
    const selected = appState.filters[key];
    if (selected && !values.includes(selected)) values.push(selected);
    const signature = JSON.stringify(values);
    if (select.dataset.options !== signature) {
      const options = [new Option(label, ""), ...values.map(value => new Option(key === "protocol" ? protocolName(value) : value, value))];
      select.replaceChildren(...options);
      select.dataset.options = signature;
    }
    select.value = selected;
    document.querySelector(`#${key}-filter-field`).hidden = values.length === 0;
  }

  function renderChips() {
    const entries = Object.entries(appState.filters).filter(([key, value]) => value && !(key === "view" && value === "all"));
    const signature = JSON.stringify(entries);
    const facetCount = entries.filter(([key]) => ["group", "location", "protocol"].includes(key)).length;
    const label = toggle.querySelector("span");
    if (label) label.textContent = facetCount ? `Filters (${facetCount})` : "Filters";
    else toggle.textContent = facetCount ? `Filters (${facetCount})` : "Filters";
    if (signature === chipSignature) return;
    chipSignature = signature;
    chips.replaceChildren();
    for (const [key, value] of entries) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "filter-chip";
      const text = key === "protocol" ? protocolName(value) : key === "view" ? (value === "favorites" ? "Favorites" : "Recent") : value;
      button.append(document.createTextNode(`${key === "search" ? "Search" : key[0].toUpperCase() + key.slice(1)}: ${text}`), icon("close", ""));
      button.setAttribute("aria-label", `Remove ${key === "search" ? "Search" : key[0].toUpperCase() + key.slice(1)}: ${text} filter`);
      button.addEventListener("click", () => {
        appState.filters[key] = key === "view" ? "all" : "";
        render();
        (chips.querySelector("button") || search).focus();
      });
      chips.append(button);
    }
    chips.hidden = entries.length === 0;
  }

  function render() {
    main.setAttribute("aria-busy", "false");
    document.querySelector("#library-loading").hidden = true;
    loadError.hidden = !failed;
    const anyProfiles = appState.profiles.length > 0;
    filters.hidden = !anyProfiles;
    document.querySelector("#import-open").classList.toggle("button-primary", !anyProfiles && !failed);
    if (failed && !anyProfiles) {
      list.hidden = true;
      count.textContent = "Library unavailable";
      firstUse.hidden = true;
      filteredEmpty.hidden = true;
      context.hidden = true;
      skip.hidden = true;
      return;
    }
    refreshFacet(group, "group", "All groups");
    refreshFacet(location, "location", "All locations");
    refreshFacet(protocol, "protocol", "All protocols");
    search.value = appState.filters.search;
    views.forEach(input => { input.checked = input.value === appState.filters.view; });
    renderChips();
    const profiles = appState.profiles.filter(matches);
    const shared = {};
    for (const key of ["group", "location", "protocol"]) {
      const value = profiles[0]?.[key];
      if (value && profiles.every(profile => profile[key] === value)) shared[key] = value;
    }
    context.textContent = [shared.group, shared.location, shared.protocol && protocolName(shared.protocol)].filter(Boolean).join(" · ");
    context.hidden = !context.textContent;
    list.setAttribute("aria-describedby", "library-context");
    const existing = new Map([...list.children].map(item => [item.firstElementChild.dataset.profileId, item]));
    profiles.forEach((profile, index) => {
      let item = existing.get(profile.id);
      if (!item) {
        item = document.createElement("li");
        item.className = "profile-row";
        const button = document.createElement("button");
        button.type = "button";
        button.className = "profile-row-button";
        button.dataset.profileId = profile.id;
        button.dataset.focusKey = `profile:${profile.id}`;
        button.append(icon(profile.protocol === "wireguard" ? "wireguard" : "openvpn", "profile-symbol"));
        const copy = appendText(button, "profile-copy", "");
        appendText(copy, "profile-name", "");
        appendText(copy, "profile-meta", "");
        button.append(icon("star", "profile-favorite"));
        appendText(button, "profile-state", "");
        button.addEventListener("click", () => onSelect(profileByID(button.dataset.profileId), button));
        item.append(button);
      }
      const button = item.firstElementChild;
      button.querySelector(".profile-name").textContent = profile.display_name;
      const metadata = button.querySelector(".profile-meta");
      metadata.textContent = [!shared.group && profile.group, !shared.location && profile.location, !shared.protocol && protocolName(profile.protocol)].filter(Boolean).join(" · ");
      metadata.hidden = !metadata.textContent;
      button.querySelector(".profile-favorite").toggleAttribute("hidden", !profile.favorite);
      button.dataset.selected = String(appState.selectedID === profile.id);
      if (appState.selectedID === profile.id) button.setAttribute("aria-current", "true");
      else button.removeAttribute("aria-current");
      if (list.children[index] !== item) list.insertBefore(item, list.children[index] || null);
      existing.delete(profile.id);
    });
    existing.forEach(item => item.remove());
    updateConnectionMarkers();
    firstUse.hidden = anyProfiles || failed;
    filteredEmpty.hidden = !anyProfiles || profiles.length > 0;
    list.hidden = profiles.length === 0;
    skip.hidden = !appState.selectedID || profiles.length === 0;
    count.textContent = `${profiles.length} ${profiles.length === 1 ? "profile" : "profiles"}`;
    importEmpty.disabled = isReadOnly();
  }

  function updateConnectionMarkers() {
    const byID = new Map(appState.profiles.map(profile => [profile.id, profile]));
    for (const button of list.querySelectorAll(".profile-row-button")) {
      const profile = byID.get(button.dataset.profileId);
      if (!profile) continue;
      const connected = appState.status?.connected && appState.status.profile?.id === profile.id;
      button.dataset.connected = String(connected && !appState.statusStale && appState.status?.observation_available !== false && appState.status?.lifecycle !== "state_conflict");
      const state = button.querySelector(".profile-state");
      state.textContent = rowState(profile);
      state.hidden = !state.textContent;
      button.setAttribute("aria-label", [profile.display_name, protocolName(profile.protocol), profile.favorite && "Favorite", appState.selectedID === profile.id && "Selected", rowState(profile)].filter(Boolean).join(" · "));
    }
  }

  function restoreSelectedRow({ focus = true } = {}) {
    const button = list.querySelector(`[data-profile-id="${CSS.escape(appState.selectedID)}"]`);
    const target = button || (!list.hidden && list.firstElementChild?.firstElementChild) || document.querySelector(failed && !appState.profiles.length ? "#library-error-title" : appState.profiles.length ? "#filtered-empty-title" : "#library-empty-title") || search;
    const saved = appState.profileScroll || { library: 0, window: 0 };
    const restoreScroll = () => {
      document.querySelector("#library-screen").scrollTop = saved.library || 0;
      window.scrollTo({ top: saved.window || 0, behavior: "instant" });
      if (focus) {
        target.focus({ preventScroll: true });
        const bounds = target.getBoundingClientRect();
        if (bounds.top < 0 || bounds.bottom > window.innerHeight) target.scrollIntoView({ block: "nearest", behavior: "instant" });
      }
    };
    restoreScroll();
    requestAnimationFrame(() => {
      if (!focus || document.activeElement === target) restoreScroll();
    });
  }

  function clearAllFilters() {
    appState.filters = { view: "all", group: "", location: "", protocol: "", search: "" };
    render();
    search.focus();
  }

  toggle.addEventListener("click", () => {
    panel.hidden = !panel.hidden;
    toggle.setAttribute("aria-expanded", String(!panel.hidden));
  });
  views.forEach(input => input.addEventListener("change", () => {
    if (!input.checked) return;
    appState.filters.view = input.value;
    render();
  }));
  group.addEventListener("change", () => { appState.filters.group = group.value; render(); });
  location.addEventListener("change", () => { appState.filters.location = location.value; render(); });
  protocol.addEventListener("change", () => { appState.filters.protocol = protocol.value; render(); });
  search.addEventListener("input", () => { appState.filters.search = search.value; render(); });
  filters.addEventListener("submit", event => event.preventDefault());
  importEmpty.addEventListener("click", event => onImport(event.currentTarget));
  document.querySelector("#clear-filters").addEventListener("click", clearAllFilters);
  document.querySelector("#reset-filters").addEventListener("click", clearAllFilters);
  document.querySelector("#library-retry").addEventListener("click", onRetry);

  return {
    render,
    updateConnectionMarkers,
    restoreSelectedRow,
    visibleProfileIDs: () => appState.profiles.filter(matches).map(profile => profile.id),
    fail: value => { failed = value; render(); },
    row: id => list.querySelector(`[data-profile-id="${CSS.escape(id)}"]`),
  };
}
