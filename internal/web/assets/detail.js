"use strict";

import { api } from "./api.js";
import { appState, hasFreshAuthority, profileByID, removeProfileState, replaceProfile } from "./state.js";

function element(name, className, text) {
  const node = document.createElement(name);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function addDefinition(list, term, value) {
  list.append(element("dt", "", term), element("dd", "", value || "—"));
}

function active(profile) {
  return appState.status?.connected && appState.status.profile?.id === profile.id;
}

function transitionBusy() {
  return appState.connectionBusy || ["starting", "switching", "restoring", "disconnecting"].includes(appState.status?.lifecycle);
}

function formatHandshake(value) {
  if (!value) return "No handshake observed";
  const date = new Date(value * 1000);
  return Number.isNaN(date.valueOf()) ? "Handshake time unavailable" : date.toLocaleString();
}

export function createDetailController({ connection, confirm, onError, onChanged, onRemoved, onReturn, savePreferences }) {
  const container = document.querySelector("#detail-content");
  const back = document.querySelector("#detail-back");
  const editDialog = document.querySelector("#edit-dialog");
  const editForm = document.querySelector("#edit-form");
  const editTitle = document.querySelector("#edit-title");
  const editError = document.querySelector("#edit-error");
  const editName = document.querySelector("#edit-name");
  const editGroup = document.querySelector("#edit-group");
  const editLocation = document.querySelector("#edit-location");
  let editOpener = null;

  function empty(message = "Choose one profile from the library to inspect its runtime identity and available actions.") {
    back.hidden = true;
    container.replaceChildren();
    container.append(element("p", "eyebrow", "Selected profile"));
    const heading = element("h2", "", "No profile selected");
    heading.id = "detail-title";
    heading.tabIndex = -1;
    container.append(heading, element("p", "muted", message));
  }

  function render(profile = profileByID(appState.selectedID)) {
    if (!profile) {
      empty(appState.selectedID ? "The selected profile is no longer in this library." : undefined);
      return;
    }
    back.hidden = false;
    container.replaceChildren();
    container.append(element("p", "eyebrow", "Selected profile"));
    const heading = element("h2", "", `Profile details: ${profile.display_name}`);
    heading.id = "detail-title";
    heading.tabIndex = -1;
    container.append(heading);

    const status = element("p", "detail-status", "");
    status.id = "detail-status";
    container.append(status);

    const definitions = element("dl");
    addDefinition(definitions, "Protocol", profile.protocol === "wireguard" ? "WireGuard" : "OpenVPN");
    addDefinition(definitions, "Group", profile.group);
    addDefinition(definitions, "Location", profile.location);
    addDefinition(definitions, "Runtime identifier", profile.identifier);
    addDefinition(definitions, "Original file", profile.original_filename);
    addDefinition(definitions, "Imported", new Date(profile.imported_at).toLocaleString());
    container.append(definitions);

    const protocolDetails = element("dl");
    protocolDetails.id = "protocol-details";
    protocolDetails.setAttribute("aria-label", "Current protocol details");
    container.append(protocolDetails);

    const actions = element("div", "detail-actions");
    const connect = element("button", "button button-primary", "Connect");
    connect.type = "button";
    connect.dataset.detailAction = "connect";
    connect.addEventListener("click", () => connection.connect(profile));
    actions.append(connect);

    const favorite = element("button", "button", profile.favorite ? "Remove favorite" : "Add favorite");
    favorite.type = "button";
    favorite.dataset.detailAction = "favorite";
    favorite.disabled = profile.capabilities?.favorite === false;
    favorite.addEventListener("click", async () => {
      const favorites = profile.favorite
        ? appState.preferences.favorites.filter(id => id !== profile.id)
        : [...appState.preferences.favorites, profile.id];
      favorite.disabled = true;
      try {
        await savePreferences({ favorites });
        profile = profileByID(profile.id);
        render(profile);
        onChanged();
        document.querySelector('[data-detail-action="favorite"]')?.focus();
      } catch (error) {
        favorite.disabled = false;
        onError(error, { focus: true });
      }
    });
    actions.append(favorite);

    const edit = element("button", "button", "Edit metadata");
    edit.type = "button";
    edit.dataset.detailAction = "edit";
    edit.disabled = profile.capabilities?.edit_metadata === false;
    edit.addEventListener("click", () => openEdit(profile, edit));
    actions.append(edit);

    const remove = element("button", "button", "Remove profile");
    remove.type = "button";
    remove.dataset.detailAction = "remove";
    remove.disabled = active(profile) || transitionBusy() || profile.capabilities?.remove === false;
    remove.addEventListener("click", () => requestRemoval(profile, remove));
    actions.append(remove);
    container.append(actions);

    if (active(profile)) container.append(element("p", "field-hint", "Disconnect this profile before removing it."));
    if (!profile.available && profile.unavailable_reason) container.append(element("p", "field-hint", profile.unavailable_reason));
    updateStatus();
  }

  function updateStatus() {
    const profile = profileByID(appState.selectedID);
    if (!profile) return;
    const status = document.querySelector("#detail-status");
    const connect = container.querySelector('[data-detail-action="connect"]');
    const remove = container.querySelector('[data-detail-action="remove"]');
    const protocolDetails = container.querySelector("#protocol-details");
    const isActive = active(profile);
    const authority = hasFreshAuthority();
    if (status) {
      status.dataset.state = isActive ? "active" : profile.available ? "neutral" : "warning";
      status.textContent = !authority
        ? "Status authority unavailable · refresh status before changing this profile"
        : isActive ? "Connected · this is the current tunnel" : profile.available ? "Inactive · ready to connect" : "Inactive · protocol unavailable";
    }
    if (connect) {
      connect.hidden = isActive;
      connect.disabled = !authority || !profile.available || transitionBusy() || profile.capabilities?.connect === false;
      const switching = appState.status?.connected;
      const action = `${switching ? "Switch" : "Connect"} to ${profile.display_name}`;
      connect.textContent = action;
      connect.setAttribute("aria-label", action);
    }
    if (remove) remove.disabled = !authority || isActive || transitionBusy() || profile.capabilities?.remove === false;
    if (protocolDetails) {
      protocolDetails.replaceChildren();
      if (isActive) {
        const protocolStatus = appState.status?.protocol_status;
        if (protocolStatus?.state === "observation_unavailable") {
          addDefinition(protocolDetails, "Protocol observation", "Unavailable");
        } else if (profile.protocol === "wireguard") {
          const peers = protocolStatus?.peers || [];
          peers.forEach((peer, index) => {
            const label = peers.length > 1 ? `Peer ${index + 1}` : "Peer";
            addDefinition(protocolDetails, `${label} endpoint`, peer.endpoint || "Unavailable");
            addDefinition(protocolDetails, `${label} latest handshake`, formatHandshake(peer.latest_handshake));
          });
          if (!peers.length) addDefinition(protocolDetails, "Peer status", "No peer status observed");
        } else {
          addDefinition(protocolDetails, "Process state", protocolStatus?.state === "active" ? "Active" : "Observed");
        }
      }
      protocolDetails.hidden = !isActive;
    }
  }

  function openEdit(profile, opener) {
    editOpener = opener;
    editError.hidden = true;
    editName.value = profile.display_name;
    editGroup.value = profile.group;
    editLocation.value = profile.location || "";
    editDialog.dataset.profileId = profile.id;
    editDialog.showModal();
    editTitle.textContent = `Edit metadata: ${profile.display_name}`;
    editTitle.focus();
  }

  async function requestRemoval(profile, opener) {
    const confirmed = await confirm({
      title: `Remove ${profile.display_name}?`,
      message: "Tunnelfolio will remove this inactive profile from the managed library. It cannot recover the file afterward; secure erasure is not promised.",
      action: "Remove profile",
      opener,
    });
    if (!confirmed) return;
    const oldProfiles = [...appState.profiles];
    const oldIndex = oldProfiles.findIndex(candidate => candidate.id === profile.id);
    try {
      await api.removeProfile(profile.id);
      removeProfileState(profile.id);
      const replacement = appState.profiles[Math.min(oldIndex, appState.profiles.length - 1)] || null;
      appState.selectedID = replacement?.id || "";
      render(replacement);
      onRemoved(profile, replacement);
    } catch (error) {
      render(profile);
      container.querySelector('[data-detail-action="remove"]')?.focus();
      onError(error, { focus: true });
    }
  }

  editForm.addEventListener("submit", async event => {
    event.preventDefault();
    const id = editDialog.dataset.profileId;
    const prior = profileByID(id);
    if (!prior) return;
    editError.hidden = true;
    const submit = editForm.querySelector('button[type="submit"]');
    submit.disabled = true;
    try {
      const patch = {
        display_name: editName.value,
        group: editGroup.value,
        location: editLocation.value || null,
      };
      const profile = await api.updateMetadata(id, patch);
      replaceProfile(profile);
      editDialog.close("saved");
      render(profile);
      onChanged();
      container.querySelector('[data-detail-action="edit"]')?.focus();
    } catch (error) {
      editError.textContent = error.message;
      editError.hidden = false;
      editError.focus();
    } finally {
      submit.disabled = false;
    }
  });
  document.querySelector("#edit-close").addEventListener("click", () => editDialog.close("cancel"));
  editDialog.addEventListener("close", () => {
    if (editDialog.returnValue !== "saved") {
      const target = editOpener?.isConnected && !editOpener.disabled ? editOpener : document.querySelector("#detail-title");
      target?.focus();
    }
  });
  back.addEventListener("click", onReturn);

  return { render, updateStatus, empty, focusHeading: () => document.querySelector("#detail-title")?.focus() };
}
