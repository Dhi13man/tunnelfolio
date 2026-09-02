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

function showError(error, { focus = false } = {}) {
  errorReturnTarget = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const message = error?.message || "The request could not be completed.";
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
  const target = errorReturnTarget?.isConnected && !errorReturnTarget.disabled
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
  onConnected: () => loadProfiles({ refreshPreferences: true }),
});

function selectProfile(profile, { recordHistory = true, focus = true } = {}) {
  appState.selectedID = profile.id;
  library.render();
  detail.render(profile);
  if (narrow.matches) {
    main.dataset.screen = "detail";
    if (recordHistory && window.history.state?.profile !== profile.id) window.history.pushState({ screen: "detail", profile: profile.id }, "");
  }
  if (focus) detail.focusHeading();
}

function returnToLibrary({ recordHistory = true, focus = true } = {}) {
  if (narrow.matches && recordHistory && window.history.state?.screen === "detail") {
    window.history.back();
    return;
  }
  main.dataset.screen = "library";
  library.render();
  library.restoreSelectedRow({ focus });
}

async function loadProfiles({ refreshPreferences = false } = {}) {
  try {
    const oldVisibleIDs = library.visibleProfileIDs();
    const oldSelectedIndex = oldVisibleIDs.indexOf(appState.selectedID);
    const [profiles, preferences] = await Promise.all([
      api.profiles(),
      refreshPreferences ? api.preferences() : Promise.resolve(null),
    ]);
    appState.profiles = profiles;
    if (preferences) appState.preferences = preferences;
    applyPreferenceFlags();
    library.fail(false);
    if (appState.selectedID && !profileByID(appState.selectedID)) {
      const newVisibleIDs = new Set(library.visibleProfileIDs());
      const candidates = [];
      for (let distance = 1; distance < oldVisibleIDs.length; distance += 1) {
        if (oldVisibleIDs[oldSelectedIndex + distance]) candidates.push(oldVisibleIDs[oldSelectedIndex + distance]);
        if (oldVisibleIDs[oldSelectedIndex - distance]) candidates.push(oldVisibleIDs[oldSelectedIndex - distance]);
      }
      const replacementID = candidates.find(id => newVisibleIDs.has(id)) || [...newVisibleIDs][Math.min(Math.max(oldSelectedIndex, 0), newVisibleIDs.size - 1)] || "";
      const replacement = profileByID(replacementID);
      appState.selectedID = replacement?.id || "";
      if (replacement) detail.render(replacement);
      else detail.empty("The selected profile is no longer in this library.");
      main.dataset.screen = "library";
      window.history.replaceState({ screen: "library" }, "");
      document.querySelector("#status-announcer").textContent = "The selected profile is no longer in the library";
      requestAnimationFrame(() => {
        if (replacement) library.restoreSelectedRow();
        else document.querySelector(appState.profiles.length ? "#filtered-empty-title" : "#library-empty-title")?.focus();
      });
    }
    library.render();
    if (appState.selectedID) detail.render();
    return appState.profiles;
  } catch (error) {
    library.fail(true);
    throw error;
  }
}

library = createLibraryController({
  onSelect: profile => selectProfile(profile),
  onImport: opener => importer?.open(opener),
  onRetry: () => loadProfiles().catch(error => showError(error, { focus: true })),
});

detail = createDetailController({
  connection,
  confirm: confirmChange,
  onError: showError,
  onChanged: () => library.render(),
  savePreferences: async patch => {
    const latest = await api.preferences();
    appState.preferences = await api.savePreferences({ ...latest, ...patch });
    applyPreferenceFlags();
    return appState.preferences;
  },
  onRemoved: (removed, replacement) => {
    library.render();
    document.querySelector("#status-announcer").textContent = `${removed.display_name} removed from the library`;
    if (replacement) {
      detail.render(replacement);
      if (narrow.matches) {
        main.dataset.screen = "library";
        window.history.replaceState({ screen: "library" }, "");
      }
      library.restoreSelectedRow();
    } else {
      detail.empty();
      main.dataset.screen = "library";
      document.querySelector("#library-empty-title").focus();
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
  const save = document.querySelector("#save-settings");
  const clearFavorites = document.querySelector("#clear-favorites");
  const clearRecents = document.querySelector("#clear-recents");

  function populate() {
    const mode = form.querySelector(`input[name="startup-mode"][value="${appState.preferences.startup_mode}"]`);
    if (mode) mode.checked = true;
    save.disabled = isReadOnly();
    clearFavorites.disabled = isReadOnly() || appState.preferences.favorites.length === 0;
    clearRecents.disabled = isReadOnly() || appState.preferences.recents.length === 0;
  }
  function open() {
    error.hidden = true;
    populate();
    dialog.showModal();
    title.focus();
  }
  function close() { dialog.close("close"); }
  async function savePreferences(preferences, announcement) {
    error.hidden = true;
    try {
      const latest = await api.preferences();
      appState.preferences = await api.savePreferences({ ...latest, ...preferences });
      applyPreferenceFlags();
      library.render();
      detail.render();
      populate();
      document.querySelector("#status-announcer").textContent = announcement;
      return true;
    } catch (requestError) {
      error.textContent = requestError.message;
      error.hidden = false;
      error.focus();
      return false;
    }
  }

  opener.addEventListener("click", open);
  document.querySelector("#settings-close").addEventListener("click", close);
  dialog.addEventListener("close", () => opener.focus());
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const startup = form.querySelector('input[name="startup-mode"]:checked')?.value;
    if (!startup) return;
    save.disabled = true;
    const saved = await savePreferences({ startup_mode: startup }, "Startup setting saved");
    save.disabled = isReadOnly();
    if (saved) close();
  });
  clearFavorites.addEventListener("click", async () => {
    if (!await confirmChange({ title: "Clear all favorites?", message: "Every saved favorite will be removed. Profiles remain in the library.", action: "Clear favorites", opener: clearFavorites })) return;
    if (await savePreferences({ favorites: [] }, "Favorites cleared")) (clearRecents.disabled ? title : clearRecents).focus();
  });
  clearRecents.addEventListener("click", async () => {
    if (!await confirmChange({ title: "Clear recent profiles?", message: "The saved recent-profile list will be cleared. Profiles remain in the library.", action: "Clear recents", opener: clearRecents })) return;
    if (await savePreferences({ recents: [] }, "Recent profiles cleared")) (clearFavorites.disabled ? title : clearFavorites).focus();
  });
}

createSettingsController();
document.querySelector("#skip-profile-list").addEventListener("click", event => {
  event.preventDefault();
  const profile = profileByID(appState.selectedID);
  if (profile && narrow.matches) selectProfile(profile);
  else detail.focusHeading();
});

window.addEventListener("popstate", event => {
  const profile = event.state?.profile ? profileByID(event.state.profile) : null;
  if (profile && narrow.matches) selectProfile(profile, { recordHistory: false });
  else returnToLibrary({ recordHistory: false });
});
narrow.addEventListener("change", event => {
  if (!event.matches) main.dataset.screen = "library";
  else main.dataset.screen = window.history.state?.screen === "detail" && appState.selectedID ? "detail" : "library";
});
window.history.replaceState({ screen: "library" }, "");

async function initialize() {
  const [health, preferences, profiles] = await Promise.allSettled([api.health(), api.preferences(), api.profiles()]);
  if (health.status === "fulfilled") appState.health = health.value;
  else showError(health.reason);
  if (preferences.status === "fulfilled") appState.preferences = preferences.value;
  else showError(preferences.reason);
  if (profiles.status === "fulfilled") {
    appState.profiles = profiles.value;
    applyPreferenceFlags();
    library.fail(false);
  } else {
    library.fail(true);
    showError(profiles.reason);
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
