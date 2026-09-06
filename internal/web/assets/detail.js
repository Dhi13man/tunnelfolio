"use strict";

import { api } from "./api.js";
import { appState, hasFreshAuthority, isReadOnly, profileByID, removeProfileState, replaceProfile } from "./state.js";
import { createProfileSymbol, updateProfileSymbol } from "./profile-symbol.js";

function element(name, className, text) {
  const node = document.createElement(name);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function addDefinition(list, term, value) {
  const item = element("div", "definition");
  item.append(element("dt", "", term), element("dd", "", value || "—"));
  list.append(item);
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

export function createDetailController({ connection, confirm, onChanged, onRemoved, onReturn, onError, savePreferences, visibleProfileIDs }) {
  const container = document.querySelector("#detail-content");
  const back = document.querySelector("#detail-back");
  const editDialog = document.querySelector("#edit-dialog");
  const editForm = document.querySelector("#edit-form");
  const editTitle = document.querySelector("#edit-title");
  const editError = document.querySelector("#edit-error");
  const editName = document.querySelector("#edit-name");
  const editEmoji = document.querySelector("#edit-emoji");
  const editGroup = document.querySelector("#edit-group");
  const editLocation = document.querySelector("#edit-location");
  const editSubmit = editForm.querySelector('button[type="submit"]');
  editForm.setAttribute("aria-describedby", "edit-error");
  let editOpener = null;
  let renderedID = "";
  let renderedMetadata = "";
  let mutationID = "";
  let editBusy = false;

  function empty(message = "Choose a profile to see its details and actions.") {
    renderedID = "";
    renderedMetadata = "";
    back.hidden = true;
    container.replaceChildren();
    const heading = element("h2", "", "No profile selected");
    heading.id = "detail-title";
    heading.tabIndex = -1;
    container.append(heading, element("p", "muted", message));
  }

  function actionError(message) {
    if (renderedID !== mutationID || document.querySelector("#main-content").dataset.screen !== "detail") {
      onError(new Error(message));
      return;
    }
    const error = container.querySelector("#detail-error");
    if (!error) return;
    error.textContent = message;
    error.hidden = false;
    error.focus();
  }

  function render(profile = profileByID(appState.selectedID)) {
    if (!profile) {
      empty(appState.selectedID ? "The selected profile is no longer in this library." : undefined);
      return;
    }
    const metadata = JSON.stringify([profile.display_name, profile.emoji, profile.protocol, profile.group, profile.location, profile.identifier, profile.original_filename, profile.imported_at]);
    if (renderedID === profile.id && renderedMetadata === metadata) {
      updateStatus();
      return;
    }
    const sameProfile = renderedID === profile.id;
    const focusedAction = sameProfile && container.contains(document.activeElement) ? document.activeElement.dataset.detailAction : "";
    const moreOpen = sameProfile && container.querySelector(".more-actions")?.open;
    const technicalOpen = sameProfile && container.querySelector(".technical-details")?.open;
    const priorError = sameProfile ? container.querySelector("#detail-error")?.textContent : "";
    renderedID = profile.id;
    renderedMetadata = metadata;
    back.hidden = false;
    container.replaceChildren();
    const heading = element("h2", "detail-title");
    heading.id = "detail-title";
    heading.tabIndex = -1;
    const symbol = createProfileSymbol();
    updateProfileSymbol(symbol, profile);
    heading.append(symbol);
    heading.append(element("span", "sr-only", "Profile details: "), document.createTextNode(profile.display_name));
    container.append(heading);

    const status = element("p", "detail-status", "");
    status.id = "detail-status";
    container.append(status);

    const primaryActions = element("div", "detail-primary-actions");
    const connect = element("button", "button button-primary", "Connect");
    connect.type = "button";
    connect.dataset.detailAction = "connect";
    connect.setAttribute("aria-describedby", "detail-restriction");
    connect.addEventListener("click", () => {
      const selected = profileByID(profile.id);
      if (selected && !connect.disabled) connection.connect(selected);
    });
    const currentLink = element("button", "button detail-current-link", "View host tunnel");
    currentLink.type = "button";
    currentLink.addEventListener("click", () => {
      const disconnect = document.querySelector("#disconnect");
      const target = !disconnect.hidden && !disconnect.disabled ? disconnect : document.querySelector("#current-title");
      target.focus();
    });
    primaryActions.append(connect, currentLink);
    container.append(primaryActions);

    const restriction = element("p", "field-hint detail-restriction", "");
    restriction.id = "detail-restriction";
    container.append(restriction);
    const error = element("p", "error-box detail-error", priorError || "");
    error.id = "detail-error";
    error.tabIndex = -1;
    error.hidden = !priorError;
    container.append(error);

    const definitions = element("dl", "profile-summary");
    addDefinition(definitions, "Protocol", profile.protocol === "wireguard" ? "WireGuard" : "OpenVPN");
    if (profile.group) addDefinition(definitions, "Group", profile.group);
    if (profile.location) addDefinition(definitions, "Location", profile.location);
    container.append(definitions);

    const technical = element("details", "technical-details");
    technical.open = Boolean(technicalOpen);
    technical.append(element("summary", "", "Technical details"));
    const technicalDefinitions = element("dl");
    addDefinition(technicalDefinitions, "Runtime identifier", profile.identifier);
    addDefinition(technicalDefinitions, "Original file", profile.original_filename);
    addDefinition(technicalDefinitions, "Imported", new Date(profile.imported_at).toLocaleString());
    technical.append(technicalDefinitions);
    const protocolDetails = element("dl");
    protocolDetails.id = "protocol-details";
    protocolDetails.setAttribute("aria-label", "Current protocol details");
    technical.append(protocolDetails);
    container.append(technical);

    const favorite = element("button", "button", "Favorite");
    favorite.type = "button";
    favorite.dataset.detailAction = "favorite";
    favorite.setAttribute("aria-describedby", "detail-restriction");
    favorite.addEventListener("click", async () => {
      const selected = profileByID(profile.id);
      if (!selected || mutationID || favorite.disabled) return;
      mutationID = selected.id;
      updateStatus();
      try {
        await savePreferences(latest => ({ favorites: selected.favorite ? latest.favorites.filter(id => id !== selected.id) : [...new Set([...latest.favorites, selected.id])] }));
        if (renderedID === selected.id) container.querySelector("#detail-error").hidden = true;
        onChanged();
        updateStatus();
      } catch (error) {
        actionError(`Could not update the favorite for ${selected.display_name}. ${error.message} Try the favorite action again when the host is available.`);
      } finally {
        mutationID = "";
        updateStatus();
      }
    });
    container.append(favorite);

    const more = element("details", "more-actions");
    more.open = Boolean(moreOpen);
    more.append(element("summary", "", "More actions"));
    const actions = element("div", "detail-actions");
    const edit = element("button", "button", "Edit metadata");
    edit.type = "button";
    edit.dataset.detailAction = "edit";
    edit.setAttribute("aria-describedby", "detail-restriction");
    edit.addEventListener("click", () => openEdit(profileByID(profile.id), edit));
    const remove = element("button", "button button-danger", "Remove profile");
    remove.type = "button";
    remove.dataset.detailAction = "remove";
    remove.setAttribute("aria-describedby", "detail-restriction");
    remove.addEventListener("click", () => requestRemoval(profileByID(profile.id), remove));
    actions.append(edit, remove);
    more.append(actions);
    container.append(more);
    updateStatus();
    if (focusedAction) container.querySelector(`[data-detail-action="${focusedAction}"]`)?.focus({ preventScroll: true });
  }

  function updateStatus() {
    const managed = profileByID(renderedID);
    const profile = managed || (appState.status?.profile?.id === renderedID ? appState.status.profile : null);
    if (!profile) return;
    const status = container.querySelector("#detail-status");
    const connect = container.querySelector('[data-detail-action="connect"]');
    const remove = container.querySelector('[data-detail-action="remove"]');
    const favorite = container.querySelector('[data-detail-action="favorite"]');
    const edit = container.querySelector('[data-detail-action="edit"]');
    const protocolDetails = container.querySelector("#protocol-details");
    const isActive = active(profile);
    const fresh = Boolean(appState.status) && !appState.statusStale && appState.status.observation_available !== false;
    const authority = hasFreshAuthority() && fresh;
    const busy = transitionBusy() || Boolean(mutationID);
    const conflict = appState.status?.lifecycle === "state_conflict";
    status.dataset.state = !fresh || conflict ? "warning" : "neutral";
    status.textContent = conflict ? "Host tunnel state conflict · review Host tunnel before making changes"
      : !fresh ? (isActive ? "Last known current profile · host observation unavailable" : "Host observation unavailable · current tunnel is unknown")
        : isActive ? "Current profile · connection evidence is shown in Host tunnel"
          : transitionBusy() ? "Inactive profile · host tunnel change in progress"
            : profile.available ? "Inactive profile" : "Inactive profile · protocol unavailable";
    const reasons = [];
    if (isReadOnly()) reasons.push("Read-only mode · profile changes are not permitted.");
    if (!managed) reasons.push("This current profile is not present in the loaded library; library actions are unavailable.");
    if (!fresh && !isReadOnly()) reasons.push("Refresh Host tunnel status before connecting or removing profiles.");
    if (isActive && !isReadOnly()) reasons.push("Disconnect this profile in Host tunnel before removing it.");
    if (!profile.available && profile.unavailable_reason) reasons.push(profile.unavailable_reason);
    if (!isReadOnly() && profile.capabilities?.connect === false && profile.available && !isActive) reasons.push("Connecting this profile is not permitted.");
    if (!isReadOnly() && (profile.capabilities?.favorite === false || profile.capabilities?.edit_metadata === false || profile.capabilities?.remove === false)) reasons.push("Some library actions are not permitted for this profile.");
    const restriction = container.querySelector("#detail-restriction");
    restriction.textContent = reasons.join(" ");
    restriction.hidden = !restriction.textContent;
    connect.hidden = Boolean(isActive);
    connect.disabled = !managed || !authority || conflict || !profile.available || busy || profile.capabilities?.connect === false;
    connect.textContent = `${appState.status?.connected ? "Switch" : "Connect"} to ${profile.display_name}`;
    container.querySelector(".detail-current-link").hidden = !isActive;
    remove.disabled = !managed || !authority || conflict || isActive || busy || profile.capabilities?.remove === false;
    favorite.disabled = !managed || isReadOnly() || Boolean(mutationID) || profile.capabilities?.favorite === false;
    favorite.textContent = profile.favorite ? "Remove favorite" : "Add favorite";
    favorite.setAttribute("aria-pressed", String(Boolean(profile.favorite)));
    edit.disabled = !managed || isReadOnly() || Boolean(mutationID) || profile.capabilities?.edit_metadata === false;
    container.setAttribute("aria-busy", String(mutationID === profile.id));
    if (editDialog.open) editSubmit.disabled = editBusy || isReadOnly() || profileByID(editDialog.dataset.profileId)?.capabilities?.edit_metadata === false;
    if (protocolDetails) {
      protocolDetails.replaceChildren();
      if (isActive) {
        const protocolStatus = appState.status?.protocol_status;
        if (!fresh) addDefinition(protocolDetails, "Observation", "Last known details; host status is unavailable");
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
    if (!profile || opener.disabled) return;
    editOpener = opener;
    editError.hidden = true;
    editName.value = profile.display_name;
    editEmoji.value = profile.emoji || "";
    editGroup.value = profile.group;
    editLocation.value = profile.location || "";
    editDialog.dataset.profileId = profile.id;
    editSubmit.disabled = false;
    editDialog.showModal();
    editTitle.textContent = `Edit metadata: ${profile.display_name}`;
    editTitle.focus();
  }

  async function requestRemoval(profile, opener) {
    if (!profile || mutationID || opener.disabled) return;
    const confirmed = await confirm({
      title: `Remove ${profile.display_name}?`,
      message: "Tunnelfolio will remove this inactive profile from the managed library. It cannot recover the file afterward; secure erasure is not promised.",
      action: "Remove profile",
      opener,
    });
    if (!confirmed || opener.disabled || !profileByID(profile.id)) return;
    const previousVisibleIDs = visibleProfileIDs();
    mutationID = profile.id;
    updateStatus();
    try {
      await api.removeProfile(profile.id);
      removeProfileState(profile.id);
      onRemoved(profile, previousVisibleIDs);
    } catch (error) {
      actionError(`Could not remove ${profile.display_name}. ${error.message} Reload this page to check whether it is still present before trying again.`);
    } finally {
      mutationID = "";
      updateStatus();
    }
  }

  editForm.addEventListener("submit", async event => {
    event.preventDefault();
    const id = editDialog.dataset.profileId;
    const prior = profileByID(id);
    if (editBusy || editSubmit.disabled) return;
    if (!prior) {
      editError.textContent = "This profile is no longer in the library. Your draft is preserved; close the editor to return to profiles.";
      editError.hidden = false;
      editError.focus();
      return;
    }
    editError.hidden = true;
    editBusy = true;
    editSubmit.disabled = true;
    document.querySelector("#edit-close").disabled = true;
    editForm.setAttribute("aria-busy", "true");
    try {
      const patch = { display_name: editName.value, emoji: editEmoji.value || null, group: editGroup.value, location: editLocation.value || null };
      const profile = await api.updateMetadata(id, patch);
      replaceProfile(profile);
      if (appState.status?.profile?.id === id) connection.render({ ...appState.status, profile });
      editDialog.close("saved");
      if (appState.selectedID === id) render(profile);
      onChanged();
      if (document.querySelector("#main-content").dataset.screen === "detail") container.querySelector('[data-detail-action="edit"]')?.focus();
      else onReturn();
    } catch (error) {
      editError.textContent = `Could not save profile metadata. ${error.message} Your draft is preserved; correct any reported fields and try saving again.`;
      editError.hidden = false;
      editError.focus();
    } finally {
      editBusy = false;
      editForm.setAttribute("aria-busy", "false");
      editSubmit.disabled = isReadOnly();
      document.querySelector("#edit-close").disabled = false;
    }
  });
  document.querySelector("#edit-close").addEventListener("click", () => { if (!editBusy) editDialog.close("cancel"); });
  editDialog.addEventListener("cancel", event => { if (editBusy) event.preventDefault(); });
  editDialog.addEventListener("close", () => {
    if (document.activeElement !== document.body && !editDialog.contains(document.activeElement)) return;
    if (document.querySelector("#main-content").dataset.screen !== "detail") {
      onReturn();
      return;
    }
    if (editDialog.returnValue !== "saved") {
      const target = editOpener?.isConnected && !editOpener.disabled ? editOpener : document.querySelector("#detail-title");
      target?.focus();
    }
  });
  back.addEventListener("click", onReturn);

  return { render, updateStatus, empty, focusHeading: options => document.querySelector("#detail-title")?.focus(options) };
}
