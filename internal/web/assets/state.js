"use strict";

export const appState = {
  health: null,
  profiles: [],
  preferences: { favorites: [], recents: [], startup_mode: "manual" },
  status: null,
  selectedID: "",
  filters: { view: "all", group: "", location: "", protocol: "", search: "" },
  profileScroll: { library: 0, window: 0 },
  statusStale: true,
  connectionBusy: false,
  polling: true,
  importBusy: false,
};

export function profileByID(id) {
  return appState.profiles.find(profile => profile.id === id) || null;
}

export function replaceProfile(profile) {
  const index = appState.profiles.findIndex(candidate => candidate.id === profile.id);
  if (index === -1) appState.profiles.push(profile);
  else appState.profiles[index] = profile;
  appState.profiles.sort((left, right) =>
    left.display_name.localeCompare(right.display_name, undefined, { sensitivity: "base" }) ||
    left.id.localeCompare(right.id),
  );
}

export function removeProfileState(id) {
  appState.profiles = appState.profiles.filter(profile => profile.id !== id);
  appState.preferences.favorites = appState.preferences.favorites.filter(candidate => candidate !== id);
  appState.preferences.recents = appState.preferences.recents.filter(candidate => candidate !== id);
}

export function isReadOnly() {
  return appState.health?.read_only === true;
}

export function hasFreshAuthority() {
  return !isReadOnly() && !appState.statusStale && appState.status?.observation_available !== false;
}
