"use strict";

import { APIError, api } from "./api.js";
import { appState, isReadOnly } from "./state.js";

const panels = ["choose", "inspect", "review", "outcome"];
const steps = ["choose", "inspect", "review", "import"];

function field(labelText, id, value, maximum, optional = false) {
  const wrapper = document.createElement("div");
  wrapper.className = "field";
  const label = document.createElement("label");
  label.htmlFor = id;
  label.textContent = `${labelText}${optional ? " (optional)" : ""}`;
  const input = document.createElement("input");
  input.id = id;
  input.type = "text";
  input.maxLength = maximum;
  input.value = value || "";
  input.required = !optional;
  wrapper.append(label, input);
  return { wrapper, input };
}

const metadataLimits = {
  display_name: { label: "display name", runes: 120, bytes: 512, optional: false },
  group: { label: "Group", runes: 64, bytes: 256, optional: false },
  location: { label: "location", runes: 80, bytes: 320, optional: true },
};

function metadataError(value, limit) {
  if (!value && limit.optional) return "";
  if (!value) return `Enter a ${limit.label}.`;
  if (value.trim() !== value) return `${limit.label} cannot begin or end with whitespace.`;
  if (/\p{Cc}/u.test(value)) return `${limit.label} cannot contain control characters.`;
  if ([...value].length > limit.runes || new TextEncoder().encode(value).length > limit.bytes) {
    return `${limit.label} must be at most ${limit.runes} characters and ${limit.bytes} UTF-8 bytes.`;
  }
  return "";
}

function metadataServerMessage(detail) {
  const limit = metadataLimits[detail.field];
  const label = limit?.label || "metadata field";
  const messages = {
    required: `Enter a ${label}.`,
    surrounding_whitespace: `${label} cannot begin or end with whitespace.`,
    control_character: `${label} cannot contain control characters.`,
    invalid_utf8: `${label} must be valid UTF-8 text.`,
    length_limit: limit ? `${label} must be at most ${limit.runes} characters and ${limit.bytes} UTF-8 bytes.` : `${label} is too long.`,
  };
  return messages[detail.code] || `${label} is invalid.`;
}

function setButtonBusy(button, busy, settledLabel) {
  button.disabled = busy;
  button.textContent = busy ? `${settledLabel}…` : settledLabel;
  button.setAttribute("aria-busy", String(busy));
}

export function createImportController({ onLibraryChanged, reconcileImport, onFinish }) {
  const opener = document.querySelector("#import-open");
  const dialog = document.querySelector("#import-dialog");
  const title = document.querySelector("#import-title");
  const close = document.querySelector("#import-close");
  const fileInput = document.querySelector("#profile-files");
  const fileSelection = document.querySelector("#file-selection");
  const dropTarget = document.querySelector("#drop-target");
  const inspectButton = document.querySelector("#inspect-profiles");
  const cancelInspection = document.querySelector("#cancel-inspection");
  const inspectAgain = document.querySelector("#inspect-again");
  const commitButton = document.querySelector("#commit-import");
  const reviewList = document.querySelector("#import-review-list");
  const batchGroup = document.querySelector("#batch-group");
  const trust = document.querySelector("#trust-profiles");
  const errors = document.querySelector("#import-errors");
  const errorList = document.querySelector("#import-error-list");
  const outcomeTitle = document.querySelector("#import-outcome-title");
  const outcomeText = document.querySelector("#import-outcome-text");
  const finish = document.querySelector("#import-finish");
  const discardNotice = document.querySelector("#import-discard");
  const keepImport = document.querySelector("#keep-import");
  const discardImport = document.querySelector("#discard-import");
  const pageStatus = document.querySelector("#import-status");
  const pageStatusText = document.querySelector("#import-status-text");
  const importAnnouncer = document.querySelector("#import-announcer");
  let files = [];
  let overrides = {};
  let inspection = null;
  let metadataDraft = new Map();
  let controller = null;
  let phase = "choose";
  let committing = false;
  let settled = false;
  let returnTarget = opener;

  function setImportBusy(busy) {
    appState.importBusy = busy;
    opener.disabled = isReadOnly() || busy;
  }

  function showPanel(next, step = next) {
    phase = next;
    for (const name of panels) document.querySelector(`#import-${name}-panel`).hidden = name !== next;
    for (const name of steps) {
      const item = document.querySelector(`#import-step-${name}`);
      if (name === step) item.setAttribute("aria-current", "step");
      else item.removeAttribute("aria-current");
    }
  }

  function setPageStatus(message, focus = false, announce = false) {
    pageStatusText.textContent = message;
    pageStatus.hidden = false;
    if (announce) importAnnouncer.textContent = message;
    if (focus) pageStatus.focus();
  }

  function clearErrors() {
    errors.hidden = true;
    errorList.replaceChildren();
    for (const target of dialog.querySelectorAll('[aria-invalid="true"]')) {
      target.removeAttribute("aria-invalid");
      const generated = [...(target.getAttribute("aria-describedby") || "").split(/\s+/)].filter(id => id && !id.endsWith("-error"));
      if (generated.length) target.setAttribute("aria-describedby", generated.join(" "));
      else target.removeAttribute("aria-describedby");
    }
    for (const message of dialog.querySelectorAll('[data-generated-error="true"]')) message.remove();
  }

  function addError(message, targetID = "") {
    const item = document.createElement("li");
    if (targetID) {
      const link = document.createElement("a");
      link.href = `#${targetID}`;
      link.textContent = message;
      link.addEventListener("click", event => {
        event.preventDefault();
        const target = document.getElementById(targetID);
        const disclosure = target?.closest("details");
        if (target instanceof HTMLDetailsElement) target.open = true;
        if (disclosure) disclosure.open = true;
        target?.focus();
      });
      item.append(link);
      const target = document.getElementById(targetID);
      if (target instanceof HTMLInputElement || target instanceof HTMLSelectElement || (target instanceof HTMLElement && target.matches("summary"))) {
        const errorID = `${targetID}-error`;
        let fieldMessage = document.getElementById(errorID);
        if (fieldMessage) fieldMessage.textContent += ` ${message}`;
        else {
          fieldMessage = document.createElement("p");
          fieldMessage.id = errorID;
          fieldMessage.className = "field-error";
          fieldMessage.dataset.generatedError = "true";
          fieldMessage.textContent = message;
          target.insertAdjacentElement("afterend", fieldMessage);
        }
        target.setAttribute("aria-invalid", "true");
        const describedBy = new Set((target.getAttribute("aria-describedby") || "").split(/\s+/).filter(Boolean));
        describedBy.add(errorID);
        target.setAttribute("aria-describedby", [...describedBy].join(" "));
      }
    } else item.textContent = message;
    errorList.append(item);
    errors.hidden = false;
  }

  function focusErrors() {
    if (!errors.hidden) errors.focus();
  }

  function reset() {
    files = [];
    overrides = {};
    inspection = null;
    metadataDraft = new Map();
    controller = null;
    committing = false;
    settled = false;
    setImportBusy(false);
    fileInput.value = "";
    fileSelection.textContent = "No files selected · up to 100 files, 1 MiB each";
    batchGroup.value = "Unsorted";
    trust.checked = false;
    reviewList.replaceChildren();
    discardNotice.hidden = true;
    clearErrors();
    showPanel("choose");
  }

  function selectFiles(nextFiles) {
    files = [...nextFiles];
    inspection = null;
    settled = false;
    const total = files.reduce((sum, file) => sum + file.size, 0);
    fileSelection.textContent = files.length
      ? `${files.length} ${files.length === 1 ? "file" : "files"} selected · ${(total / 1048576).toFixed(1)} MiB total`
      : "No files selected · up to 100 files, 1 MiB each";
    clearErrors();
  }

  function localEnvelopeValid() {
    clearErrors();
    if (!files.length) addError("Choose at least one .ovpn or .conf file.", "profile-files");
    if (files.length > 100) addError("Choose no more than 100 files in one batch.", "profile-files");
    if (files.some(file => file.size > 1048576)) addError("Each profile must be no larger than 1 MiB.", "profile-files");
    if (files.reduce((sum, file) => sum + file.size, 0) > 32 * 1048576) addError("The complete request must be no larger than 32 MiB.", "profile-files");
    return errors.hidden;
  }

  function collectDraft() {
    for (let ordinal = 0; ordinal < files.length; ordinal += 1) {
      const name = document.querySelector(`#import-name-${ordinal}`);
      const group = document.querySelector(`#import-group-${ordinal}`);
      const location = document.querySelector(`#import-location-${ordinal}`);
      const protocol = document.querySelector(`#import-protocol-${ordinal}`);
      if (name && group && location) metadataDraft.set(ordinal, { display_name: name.value, group: group.value, location: location.value });
      if (protocol?.value) overrides[String(ordinal)] = protocol.value;
      else delete overrides[String(ordinal)];
    }
  }

  async function inspect() {
    if (!localEnvelopeValid()) {
      focusErrors();
      return;
    }
    collectDraft();
    clearErrors();
    showPanel("inspect");
    setImportBusy(true);
    controller = new AbortController();
    try {
      inspection = await api.inspect(files, overrides, controller.signal);
      renderReview();
      showPanel("review");
      document.querySelector("#import-review-title").focus?.();
    } catch (error) {
      if (error.name === "AbortError") {
        showPanel("choose");
        inspectButton.focus();
        document.querySelector("#status-announcer").textContent = "Profile inspection cancelled";
      } else {
        showPanel("choose");
        addError(error.message);
        focusErrors();
      }
    } finally {
      controller = null;
      setImportBusy(false);
    }
  }

  function renderReview() {
    reviewList.replaceChildren();
    clearErrors();
    const suggestions = new Map((inspection.suggestions || []).map(value => [value.ordinal, value]));
    for (const record of inspection.inspection_records || []) {
      const ordinal = record.ordinal;
      const suggestion = suggestions.get(ordinal) || { display_name: files[ordinal]?.name || `Profile ${ordinal + 1}`, group: "Unsorted", location: "" };
      const draft = metadataDraft.get(ordinal) || suggestion;
      metadataDraft.set(ordinal, { display_name: draft.display_name, group: draft.group, location: draft.location || "" });
      const details = document.createElement("details");
      details.className = "import-file";
      details.id = `import-file-${ordinal}`;
      details.open = (record.issues || []).length > 0 || !record.protocol;
      const summary = document.createElement("summary");
      summary.id = `import-file-summary-${ordinal}`;
      const disposition = record.disposition === "already_imported" ? "already in library" : record.protocol || "protocol needed";
      summary.textContent = `${ordinal + 1}. ${files[ordinal]?.name || "Profile"} · ${disposition}`;
      details.append(summary);
      const fields = document.createElement("div");
      fields.className = "import-file-fields";
      const nameField = field("Display name", `import-name-${ordinal}`, draft.display_name, 120);
      const groupField = field("Group", `import-group-${ordinal}`, draft.group, 64);
      const locationField = field("Location", `import-location-${ordinal}`, draft.location, 80, true);
      const protocolWrapper = document.createElement("div");
      protocolWrapper.className = "field";
      const protocolLabel = document.createElement("label");
      protocolLabel.htmlFor = `import-protocol-${ordinal}`;
      protocolLabel.textContent = "Protocol detection";
      const protocolSelect = document.createElement("select");
      protocolSelect.id = `import-protocol-${ordinal}`;
      for (const [value, label] of [["", `Automatic${record.protocol ? ` · ${record.protocol === "wireguard" ? "WireGuard" : "OpenVPN"}` : ""}`], ["openvpn", "OpenVPN"], ["wireguard", "WireGuard"]]) {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = label;
        protocolSelect.append(option);
      }
      protocolSelect.value = overrides[String(ordinal)] || "";
      protocolWrapper.append(protocolLabel, protocolSelect);
      fields.append(nameField.wrapper, groupField.wrapper, locationField.wrapper, protocolWrapper);
      details.append(fields);
      reviewList.append(details);
      if ((record.issues || []).length) {
        const issues = document.createElement("ul");
        issues.className = "policy-issues";
        for (const issue of record.issues) {
          const item = document.createElement("li");
          item.textContent = issue.message;
          issues.append(item);
          const target = issue.field === "protocol" ? protocolSelect.id : summary.id;
          addError(`${files[ordinal]?.name || `File ${ordinal + 1}`}: ${issue.message}`, target);
        }
        fields.append(issues);
      }
    }
    const count = inspection.inspection_records?.length || 0;
    commitButton.textContent = `Import ${count} ${count === 1 ? "profile" : "profiles"}`;
    commitButton.disabled = !inspection.commit_ready;
    if (!inspection.commit_ready && errors.hidden) addError("Correct the profile review and inspect the files again.");
  }

  function validateMetadata() {
    clearErrors();
    collectDraft();
    for (let ordinal = 0; ordinal < files.length; ordinal += 1) {
      const draft = metadataDraft.get(ordinal);
      for (const [fieldName, limit] of Object.entries(metadataLimits)) {
        const message = metadataError(draft?.[fieldName] || "", limit);
        if (message) addError(`${files[ordinal].name}: ${message}`, `import-${fieldName === "display_name" ? "name" : fieldName}-${ordinal}`);
      }
    }
    if (!trust.checked) addError("Confirm that you trust these profiles to change this host’s network configuration.", "trust-profiles");
    return errors.hidden;
  }

  function metadataDocument() {
    const document = {};
    for (const [ordinal, value] of metadataDraft.entries()) document[String(ordinal)] = value;
    return document;
  }

  async function lostResponse(error) {
    if (error instanceof APIError) return false;
    const newIDs = (inspection.inspection_records || []).filter(record => record.disposition === "new").map(record => record.id);
    if (!newIDs.length) {
      settleSuccess("These profiles were already present in the library. The lost response did not leave a new publication to resolve.");
      return true;
    }
    const present = await reconcileImport(newIDs);
    if (present === newIDs.length) {
      settleSuccess(`Imported ${newIDs.length} ${newIDs.length === 1 ? "profile" : "profiles"}. The library confirmed the result after the response was lost.`);
      return true;
    }
    if (present === 0) {
      addError("The import response was lost, but none of the proposed profiles is present. Review and retry the same batch.");
      showPanel("review");
      setImportBusy(false);
      focusErrors();
      return true;
    }
    setImportBusy(true);
    if (dialog.open) dialog.close("unknown");
    setPageStatus("The import response was lost and the library contains only part of the proposed batch. Do not retry. Inspect the host audit log before changing the library again.", true, true);
    return true;
  }

  function settleSuccess(message) {
    settled = true;
    setImportBusy(false);
    outcomeTitle.textContent = "Import complete";
    outcomeText.textContent = message;
    showPanel("outcome", "import");
    setPageStatus(message, !dialog.open, true);
    if (dialog.open) outcomeTitle.focus();
  }

  function finishCommitAttempt() {
    committing = false;
    setButtonBusy(commitButton, false, `Import ${files.length} ${files.length === 1 ? "profile" : "profiles"}`);
  }

  async function commit() {
    if (!inspection?.commit_ready || !validateMetadata()) {
      focusErrors();
      return;
    }
    committing = true;
    setImportBusy(true);
    clearErrors();
    showPanel("review", "import");
    setButtonBusy(commitButton, true, "Import profiles");
    setPageStatus(`Importing ${files.length} ${files.length === 1 ? "profile" : "profiles"}…`);
    let result;
    try {
      result = await api.commitImport({ files, overrides, inspection, metadata: metadataDocument() });
    } catch (error) {
      try {
        if (await lostResponse(error)) {
          finishCommitAttempt();
          return;
        }
      } catch (reconcileError) {
        setImportBusy(true);
        if (dialog.open) dialog.close("unknown");
        setPageStatus("The import response was lost and the library could not be reconciled. Do not retry until the host audit log is checked.", true, true);
        finishCommitAttempt();
        return;
      }
      showPanel("review");
      if (error instanceof APIError && error.code === "invalid_metadata" && error.details.length) {
        for (const detail of error.details) {
          const fieldName = detail.field === "display_name" ? "name" : detail.field;
          const target = Number.isInteger(detail.file) && ["name", "group", "location"].includes(fieldName)
            ? `import-${fieldName}-${detail.file}` : "";
          addError(`${files[detail.file]?.name || "Profile"}: ${metadataServerMessage(detail)}`, target);
        }
      } else addError(error.message);
      setImportBusy(false);
      if (dialog.open) focusErrors();
      else setPageStatus(`Import failed: ${error.message} Reopen the import to review and retry.`, true, true);
      finishCommitAttempt();
      return;
    }
    try {
      const imported = result.records.filter(record => record.result === "imported").length;
      const existing = result.records.length - imported;
      const parts = [];
      if (imported) parts.push(`imported ${imported}`);
      if (existing) parts.push(`${existing} already in the library`);
      try {
        await onLibraryChanged();
        settleSuccess(`${parts.join(" · ")}. No profile was connected.`);
      } catch (refreshError) {
        settleSuccess(`${parts.join(" · ")}. No profile was connected. The library refresh failed; reload the page before making another change.`);
      }
    } finally {
      finishCommitAttempt();
    }
  }

  function requestClose() {
    if (committing) {
      dialog.close("background");
      setPageStatus("Import continues in the background. Another import is blocked until it settles.", true);
      return;
    }
    if (files.length && !settled) {
      discardNotice.hidden = false;
      discardImport.focus();
      return;
    }
    dialog.close("close");
  }

  function open(source = opener) {
    if (isReadOnly() || appState.importBusy) return;
    if (source instanceof HTMLElement) returnTarget = source;
    if (!dialog.open) dialog.showModal();
    title.focus();
  }

  opener.addEventListener("click", event => open(event.currentTarget));
  close.addEventListener("click", requestClose);
  dialog.addEventListener("cancel", event => {
    event.preventDefault();
    requestClose();
  });
  dialog.addEventListener("close", () => {
    if (!committing && dialog.returnValue !== "background" && dialog.returnValue !== "unknown") {
      const focusTarget = dialog.returnValue === "finished"
        ? document.querySelector("#profiles-title")
        : returnTarget?.isConnected && !returnTarget.disabled ? returnTarget : document.querySelector("#main-content");
      focusTarget.focus();
      requestAnimationFrame(() => focusTarget.focus());
    }
  });
  fileInput.addEventListener("change", () => selectFiles(fileInput.files));
  for (const type of ["dragenter", "dragover"]) dropTarget.addEventListener(type, event => {
    event.preventDefault();
    dropTarget.dataset.dragging = "true";
  });
  for (const type of ["dragleave", "drop"]) dropTarget.addEventListener(type, event => {
    event.preventDefault();
    dropTarget.dataset.dragging = "false";
  });
  dropTarget.addEventListener("drop", event => selectFiles(event.dataTransfer.files));
  inspectButton.addEventListener("click", inspect);
  inspectAgain.addEventListener("click", inspect);
  cancelInspection.addEventListener("click", () => controller?.abort());
  commitButton.addEventListener("click", commit);
  batchGroup.addEventListener("input", () => {
    for (let ordinal = 0; ordinal < files.length; ordinal += 1) {
      const group = document.querySelector(`#import-group-${ordinal}`);
      if (group) group.value = batchGroup.value;
    }
  });
  keepImport.addEventListener("click", () => {
    discardNotice.hidden = true;
    close.focus();
  });
  discardImport.addEventListener("click", () => {
    reset();
    dialog.close("discard");
  });
  finish.addEventListener("click", () => {
    reset();
    onFinish();
    dialog.close("finished");
  });

  return { open, reset };
}
