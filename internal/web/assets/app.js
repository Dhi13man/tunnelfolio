"use strict";

import { api } from "./api.js";
import { createConnectionController } from "./connection.js";
import { createDetailController } from "./detail.js";
import { createImportController } from "./import.js";
import { createLibraryController } from "./library.js";
import { appState, isReadOnly, profileByID } from "./state.js";

const narrow = matchMedia("(max-width: 69.99rem)");
const main = document.querySelector("#main-content");
const pageError = document.querySelector("#page-error");
const pageErrorTitle = document.querySelector("#page-error-title");
const pageErrorText = document.querySelector("#page-error-text");
const pageErrorDismiss = document.querySelector("#page-error-dismiss");
const pageErrorAnnouncer = document.querySelector("#page-error-announcer");
let errorReturnTarget = null;
let library;
let detail;
let importer;
let preferencesLoaded = false;

function showError(error, { focus = false, operation = "", recovery = "" } = {}) {
  errorReturnTarget = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const message = [operation && `${operation} failed.`, error?.message || "The request could not be completed.", recovery].filter(Boolean).join(" ");
  pageErrorText.textContent = message;
  pageError.hidden = false;
  if (focus) {
    pageErrorAnnouncer.textContent = "";
    pageErrorTitle.focus();
  } else if (pageErrorAnnouncer.textContent !== message) pageErrorAnnouncer.textContent = message;
}

function dismissError() {
  pageError.hidden = true;
  pageErrorAnnouncer.textContent = "";
  const target = errorReturnTarget?.isConnected && !errorReturnTarget.disabled && errorReturnTarget.getClientRects().length
    ? errorReturnTarget
    : document.querySelector("#current-title");
  target?.focus();
}

pageErrorDismiss.addEventListener("click", dismissError);

function createConfirmation() {
  const dialog = document.querySelector("#confirm-dialog");
  const title = document.querySelector("#confirm-title");
  const text = document.querySelector("#confirm-text");
  const cancel = document.querySelector("#confirm-cancel");
  const action = document.querySelector("#confirm-action");
  let settle = null;
  let opener = null;

  function finish(value) {
    if (!settle) return;
    const resolve = settle;
    settle = null;
    dialog.close(value ? "confirmed" : "cancelled");
    resolve(value);
  }
  cancel.addEventListener("click", () => finish(false));
  action.addEventListener("click", () => finish(true));
  dialog.addEventListener("cancel", event => {
    event.preventDefault();
    finish(false);
  });
  dialog.addEventListener("close", () => {
    const target = opener?.isConnected && !opener.disabled ? opener : document.querySelector("#main-content");
    target?.focus();
  });

  return options => new Promise(resolve => {
    opener = options.opener || document.activeElement;
    settle = resolve;
    title.textContent = options.title;
    text.textContent = options.message;
    action.textContent = options.action;
    dialog.showModal();
    title.focus();
  });
}

const confirmChange = createConfirmation();

function protocolAvailability(status) {
  for (const protocol of ["openvpn", "wireguard"]) {
    const row = document.querySelector(`#${protocol}-availability`);
    const availability = status?.protocols?.[protocol] || appState.health?.protocols?.[protocol];
    const name = protocol === "wireguard" ? "WireGuard" : "OpenVPN";
    row.dataset.available = String(availability?.available === true);
    row.lastChild.textContent = ` ${name} · ${availability?.available ? "available" : availability?.reason || "unavailable"}`;
  }
}

const connection = createConnectionController({
  onStatus: status => {
    protocolAvailability(status);
    library?.updateConnectionMarkers();
    detail?.updateStatus();
  },
  onError: showError,
  onInspect: profile => selectProfile(profileByID(profile.id) || profile),
  onConnected: () => loadProfiles({ refreshPreferences: true }),
});

function selectProfile(profile, { recordHistory = true, focus = true } = {}) {
  if (!profile) return;
  if (main.dataset.screen !== "detail" || !narrow.matches) {
    appState.profileScroll = {
      library: document.querySelector("#library-screen").scrollTop,
      window: window.scrollY,
    };
  }
  appState.selectedID = profile.id;
  main.dataset.screen = "detail";
  library.render();
  detail.render(profile);
  if (recordHistory) {
    const state = { screen: "detail", profile: profile.id };
    if (window.history.state?.screen === "detail") window.history.replaceState(state, "");
    else window.history.pushState(state, "");
  }
  if (focus) {
    detail.focusHeading({ preventScroll: !narrow.matches });
  }
}

function returnToLibrary({ recordHistory = true, focus = true } = {}) {
  if (recordHistory && window.history.state?.screen === "detail") {
    window.history.back();
    return;
  }
  main.dataset.screen = "library";
  if (window.history.state?.screen === "detail") window.history.replaceState({ screen: "library" }, "");
  library.render();
  library.restoreSelectedRow({ focus });
}

function resolveMissingSelection(removedID, previousVisibleIDs, announcement) {
  const visibleIDs = library.visibleProfileIDs();
  const survivors = new Set(visibleIDs);
  const oldIndex = previousVisibleIDs.indexOf(removedID);
  let replacementID = "";
  for (let distance = 1; distance < previousVisibleIDs.length && !replacementID; distance += 1) {
    replacementID = [previousVisibleIDs[oldIndex + distance], previousVisibleIDs[oldIndex - distance]]
      .find(id => survivors.has(id)) || "";
  }
  appState.selectedID = replacementID || visibleIDs[Math.min(Math.max(oldIndex, 0), visibleIDs.length - 1)] || "";
  main.dataset.screen = "library";
  window.history.replaceState({ screen: "library" }, "");
  library.render();
  if (appState.selectedID) detail.render();
  else detail.empty("The selected profile is no longer in this library.");
  document.querySelector("#status-announcer").textContent = announcement;
  if (!document.querySelector("dialog[open]")) library.restoreSelectedRow();
}

async function loadProfiles({ refreshPreferences = false } = {}) {
  const oldVisibleIDs = library.visibleProfileIDs();
  try {
    const [profiles, preferences] = await Promise.all([
      api.profiles(),
      refreshPreferences ? api.preferences() : Promise.resolve(null),
    ]);
    appState.profiles = profiles;
    if (preferences) {
      appState.preferences = preferences;
      preferencesLoaded = true;
    }
    applyPreferenceFlags();
    library.fail(false);
    if (appState.selectedID && !profileByID(appState.selectedID)) {
      resolveMissingSelection(appState.selectedID, oldVisibleIDs, "The selected profile is no longer in the library");
    } else {
      library.render();
      if (appState.selectedID) detail.render();
    }
    return appState.profiles;
  } catch (error) {
    library.fail(true);
    throw error;
  }
}

library = createLibraryController({
  onSelect: profile => selectProfile(profile),
  onImport: opener => importer?.open(opener),
  onRetry: () => loadProfiles().catch(error => showError(error, { focus: true, operation: "Loading profiles", recovery: "Use Retry in the Profiles section to reload the library." })),
});

detail = createDetailController({
  connection,
  confirm: confirmChange,
  onError: showError,
  onChanged: () => library.render(),
  visibleProfileIDs: () => library.visibleProfileIDs(),
  savePreferences: async patch => {
    const latest = await api.preferences();
    appState.preferences = await api.savePreferences({ ...latest, ...patch(latest) });
    preferencesLoaded = true;
    applyPreferenceFlags();
    return appState.preferences;
  },
  onRemoved: (removed, previousVisibleIDs) => {
    if (appState.selectedID === removed.id) resolveMissingSelection(removed.id, previousVisibleIDs, `${removed.display_name} removed from the library`);
    else {
      library.render();
      document.querySelector("#status-announcer").textContent = `${removed.display_name} removed from the library`;
    }
  },
  onReturn: () => returnToLibrary(),
});

importer = createImportController({
  onLibraryChanged: loadProfiles,
  onFinish: () => returnToLibrary({ recordHistory: false, focus: false }),
  reconcileImport: async ids => {
    const profiles = await loadProfiles();
    const present = new Set(profiles.map(profile => profile.id));
    return ids.filter(id => present.has(id)).length;
  },
});

function applyPreferenceFlags() {
  if (!preferencesLoaded) return;
  const favorites = new Set(appState.preferences.favorites);
  const recents = new Set(appState.preferences.recents);
  for (const profile of appState.profiles) {
    profile.favorite = favorites.has(profile.id);
    profile.recent = recents.has(profile.id);
  }
}

function createSettingsController() {
  const opener = document.querySelector("#settings-open");
  const dialog = document.querySelector("#settings-dialog");
  const title = document.querySelector("#settings-title");
  const form = document.querySelector("#settings-form");
  const error = document.querySelector("#settings-error");
  form.setAttribute("aria-describedby", "settings-state settings-error");
  const state = document.querySelector("#settings-state");
  const retry = document.querySelector("#settings-retry");
  const save = document.querySelector("#save-settings");
  const closeButton = document.querySelector("#settings-close");
  const clearFavorites = document.querySelector("#clear-favorites");
  const clearRecents = document.querySelector("#clear-recents");
  const modes = [...form.querySelectorAll('input[name="startup-mode"]')];
  let busy = false;
  let loading = false;
  let loaded = false;

  function updateControls() {
    const restricted = !loaded || busy || loading || isReadOnly();
    save.disabled = restricted;
    clearFavorites.disabled = restricted || appState.preferences.favorites.length === 0;
    clearRecents.disabled = restricted || appState.preferences.recents.length === 0;
    modes.forEach(mode => { mode.disabled = restricted; });
    closeButton.disabled = busy;
    retry.hidden = loaded || loading;
    retry.disabled = busy || loading;
    form.setAttribute("aria-busy", String(busy || loading));
    state.textContent = loading ? "Loading host settings…"
      : busy ? "Saving host preferences…"
        : !loaded ? "Host settings are unavailable. Retry loading them before making changes."
          : isReadOnly() ? "Read-only mode · host preferences cannot be changed."
            : "Startup changes apply only when you save. Library maintenance actions apply separately.";
  }

  function populateDraft() {
    modes.forEach(mode => { mode.checked = loaded && mode.value === appState.preferences.startup_mode; });
    updateControls();
  }

  async function loadSettings() {
    if (loading || busy) return;
    loading = true;
    updateControls();
    try {
      const [preferences, health] = await Promise.all([api.preferences(), appState.health ? Promise.resolve(appState.health) : api.health()]);
      appState.preferences = preferences;
      appState.health = health;
      preferencesLoaded = true;
      loaded = true;
      applyPreferenceFlags();
      library.render();
      detail.updateStatus();
      protocolAvailability(appState.status);
      document.body.dataset.readOnly = String(isReadOnly());
      document.querySelector("#read-only-notice").hidden = !isReadOnly();
      document.querySelector("#import-open").disabled = isReadOnly();
      error.hidden = true;
      populateDraft();
    } catch (requestError) {
      loaded = false;
      error.textContent = `Could not load host settings. ${requestError.message} Retry loading settings; saved preferences have not been changed.`;
      error.hidden = false;
      if (dialog.open) error.focus();
    } finally {
      loading = false;
      updateControls();
      if (dialog.open && document.activeElement === retry && retry.hidden) title.focus();
    }
  }

  function open() {
    loaded = preferencesLoaded && Boolean(appState.health);
    error.hidden = true;
    populateDraft();
    dialog.showModal();
    title.focus();
    if (!loaded) loadSettings();
  }
  function close() { if (!busy) dialog.close("close"); }
  async function savePreferences(preferences, announcement, operation) {
    if (busy || loading || !loaded || isReadOnly()) return false;
    busy = true;
    error.hidden = true;
    updateControls();
    try {
      const latest = await api.preferences();
      appState.preferences = await api.savePreferences({ ...latest, ...preferences });
      preferencesLoaded = true;
      applyPreferenceFlags();
      library.render();
      detail.render();
      document.querySelector("#status-announcer").textContent = announcement;
      return true;
    } catch (requestError) {
      error.textContent = `${operation} failed. ${requestError.message} Your startup draft is preserved. Check the host connection before trying again.`;
      error.hidden = false;
      error.focus();
      return false;
    } finally {
      busy = false;
      updateControls();
    }
  }

  opener.addEventListener("click", open);
  closeButton.addEventListener("click", close);
  retry.addEventListener("click", loadSettings);
  dialog.addEventListener("cancel", event => { if (busy) event.preventDefault(); });
  dialog.addEventListener("close", () => opener.focus());
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const startup = form.querySelector('input[name="startup-mode"]:checked')?.value;
    if (!startup || save.disabled) return;
    if (await savePreferences({ startup_mode: startup }, "Startup setting saved", "Saving the startup setting")) close();
  });
  clearFavorites.addEventListener("click", async () => {
    if (clearFavorites.disabled) return;
    if (!await confirmChange({ title: "Clear all favorites?", message: "Every saved favorite will be removed. Profiles remain in the library. Your unsaved Startup choice will not be saved.", action: "Clear favorites", opener: clearFavorites })) return;
    if (await savePreferences({ favorites: [] }, "Favorites cleared", "Clearing favorites")) (clearRecents.disabled ? title : clearRecents).focus();
  });
  clearRecents.addEventListener("click", async () => {
    if (clearRecents.disabled) return;
    if (!await confirmChange({ title: "Clear recent profiles?", message: "The saved recent-profile list will be cleared. Profiles remain in the library. Your unsaved Startup choice will not be saved.", action: "Clear recents", opener: clearRecents })) return;
    if (await savePreferences({ recents: [] }, "Recent profiles cleared", "Clearing recent profiles")) (clearFavorites.disabled ? title : clearFavorites).focus();
  });
}

createSettingsController();
document.querySelector("#skip-profile-list").addEventListener("click", event => {
  event.preventDefault();
  const profile = profileByID(appState.selectedID);
  if (profile) selectProfile(profile);
});

window.addEventListener("popstate", event => {
  const profile = event.state?.profile ? profileByID(event.state.profile) : null;
  if (profile) selectProfile(profile, { recordHistory: false });
  else {
    if (event.state?.screen === "detail") window.history.replaceState({ screen: "library" }, "");
    returnToLibrary({ recordHistory: false });
  }
});
narrow.addEventListener("change", () => {
  if (main.dataset.screen === "detail") {
    if (narrow.matches) {
      if (!document.querySelector("dialog[open]")) detail.focusHeading();
    } else {
      library.restoreSelectedRow({ focus: false });
    }
  }
});
window.history.replaceState({ screen: "library" }, "");

async function initialize() {
  const [health, preferences, profiles] = await Promise.allSettled([api.health(), api.preferences(), api.profiles()]);
  if (health.status === "fulfilled") appState.health = health.value;
  else showError(health.reason, { operation: "Loading host capabilities", recovery: "Open Settings and retry loading host settings." });
  if (preferences.status === "fulfilled") {
    appState.preferences = preferences.value;
    preferencesLoaded = true;
  } else showError(preferences.reason, { operation: "Loading preferences", recovery: "Open Settings and retry loading host settings. Saved preferences have not been changed." });
  if (profiles.status === "fulfilled") {
    appState.profiles = profiles.value;
    applyPreferenceFlags();
    library.fail(false);
  } else {
    library.fail(true);
    showError(profiles.reason, { operation: "Loading profiles", recovery: "Use Retry in the Profiles section. Host status remains available independently." });
  }
  const readOnly = isReadOnly();
  document.body.dataset.readOnly = String(readOnly);
  document.querySelector("#import-open").disabled = readOnly;
  document.querySelector("#read-only-notice").hidden = !readOnly;
  if (readOnly) document.querySelector("#import-open").title = "Imports are disabled in read-only mode";
  library.render();
  detail.empty();
  await connection.refresh();
  connection.start();
}

initialize().catch(error => showError(error, { focus: true }));
