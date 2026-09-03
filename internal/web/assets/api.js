"use strict";

export class APIError extends Error {
  constructor(status, body) {
    super(body?.error || `Request failed with status ${status}.`);
    this.name = "APIError";
    this.status = status;
    this.code = body?.code || "request_failed";
    this.details = Array.isArray(body?.details) ? body.details : [];
  }
}

async function request(path, options = {}, accepted = []) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: { Accept: "application/json", ...(options.headers || {}) },
  });
  let body = null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) body = await response.json();
  if (!response.ok && !accepted.includes(response.status)) throw new APIError(response.status, body);
  return body;
}

function json(method, body) {
  return {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

export const api = {
  health: () => request("/healthz"),
  profiles: () => request("/api/profiles"),
  profile: id => request(`/api/profiles/${encodeURIComponent(id)}`),
  preferences: () => request("/api/preferences"),
  status: () => request("/api/status", {}, [409, 503]),
  connect: profile => request("/api/connect", json("POST", { profile })),
  disconnect: () => request("/api/disconnect", { method: "POST" }),
  savePreferences: preferences => request("/api/preferences", json("PUT", preferences)),
  updateMetadata: (id, patch) => request(`/api/profiles/${encodeURIComponent(id)}`, json("PATCH", patch)),
  removeProfile: id => request(`/api/profiles/${encodeURIComponent(id)}`, { method: "DELETE" }),
  inspect: (files, overrides, signal) => {
    const form = new FormData();
    for (const file of files) form.append("files", file, file.name);
    if (Object.keys(overrides).length) form.append("protocol_overrides", JSON.stringify(overrides));
    return request("/api/imports/inspect", { method: "POST", body: form, signal });
  },
  commitImport: ({ files, overrides, inspection, metadata, signal }) => {
    const form = new FormData();
    for (const file of files) form.append("files", file, file.name);
    if (Object.keys(overrides).length) form.append("protocol_overrides", JSON.stringify(overrides));
    form.append("inspection_records", JSON.stringify(inspection.inspection_records));
    form.append("metadata", JSON.stringify(metadata));
    form.append("receipt", inspection.receipt);
    form.append("library_revision", String(inspection.library_revision));
    form.append("trust_profile_policy", "true");
    return request("/api/profiles/import", { method: "POST", body: form, signal });
  },
};
