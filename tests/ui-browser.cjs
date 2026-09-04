"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const AxeBuilder = require("@axe-core/playwright").default;
const { chromium, firefox } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const webRoot = path.join(root, "internal", "web");
const executablePath = process.env.CHROMIUM_PATH || "/usr/bin/chromium";
const browserName = process.env.BROWSER || "chromium";
const browserType = browserName === "firefox" ? firefox : chromium;
const artifactDir = process.env.UI_ARTIFACT_DIR ? path.resolve(process.env.UI_ARTIFACT_DIR) : "";
const artifactManifest = [];
let artifactSequence = 0;
if (!["chromium", "firefox"].includes(browserName)) throw new Error(`Unsupported BROWSER: ${browserName}`);
if (artifactDir) fs.mkdirSync(artifactDir, { recursive: true });
const hostileName = `<img src=x onerror="globalThis.injected=true"> ${"界".repeat(80)}`;
const fixtureTime = "2026-09-02T05:20:00.000Z";
const fixtureEpochSeconds = Math.floor(new Date(fixtureTime).getTime() / 1000);
let readOnly = false;
let profileFailure = false;
let profileGate = null;
let statusFailure = false;
let preferenceFailure = false;
let metadataFailure = false;
let removalFailure = false;
let inspectGate = null;
let inspectScenario = "ready";
let commitScenario = "ready";
let commitGate = null;
let lastInspectionRecords = [];
let inspectionSequence = 0;
let preferences = { favorites: [], recents: [], startup_mode: "manual" };
let status = {
  connected: true,
  lifecycle: "active",
  observation_available: true,
  observed_at: fixtureTime,
  profile: null,
  protocol_status: {
    state: "interface_active",
    received_bytes: 15360,
    sent_bytes: 4096,
    peers: [{ endpoint: "198.51.100.8:51820", latest_handshake: 0, received_bytes: 15360, sent_bytes: 4096 }],
  },
  protocols: {
    openvpn: { available: true },
    wireguard: { available: true },
  },
};
let profiles = [
  profile("tf_aaaaaaaaaaaaaaaaaaaaaaaaaa", "openvpn", hostileName, "Work", "Office", false),
  profile("tf_bbbbbbbbbbbbbbbbbbbbbbbbbb", "wireguard", "Japan", "Mullvad", "JP", true),
  profile("tf_cccccccccccccccccccccccccc", "wireguard", "Germany — Frankfurt relay with a deliberately long descriptive name", "Mullvad", "DE", false),
];
status.profile = profiles[1];

function profile(id, protocol, displayName, group, location, recent) {
  return {
    id,
    protocol,
    display_name: displayName,
    group,
    location,
    identifier: `tf${id.slice(3, 15)}`,
    original_filename: `${location.toLowerCase()}.${protocol === "wireguard" ? "conf" : "ovpn"}`,
    imported_at: fixtureTime,
    favorite: false,
    recent,
    available: true,
    capabilities: { connect: true, favorite: true, edit_metadata: true, remove: true },
  };
}

function stableID(index) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let value = index + 1;
  let encoded = "";
  while (value > 0) {
    encoded = alphabet[value % alphabet.length] + encoded;
    value = Math.floor(value / alphabet.length);
  }
  return `tf_${"a".repeat(26 - encoded.length)}${encoded}`;
}

function contrast(left, right) {
  const luminance = hex => {
    const channels = hex.match(/[0-9a-f]{2}/gi).map(value => Number.parseInt(value, 16) / 255);
    const linear = channels.map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
  };
  const values = [luminance(left), luminance(right)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

function deferred() {
  let resolve;
  const promise = new Promise(settle => { resolve = settle; });
  return { promise, resolve };
}

function json(response, statusCode, body) {
  response.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  response.end(JSON.stringify(body));
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", chunk => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

async function handleAPI(request, response, url) {
  if (url.pathname === "/healthz") return json(response, 200, { live: true, readiness: "ready", read_only: readOnly, protocols: status.protocols });
  if (url.pathname === "/api/status") {
    if (statusFailure) return json(response, 500, { code: "status_failed", error: "Tunnel state could not be observed." });
    const statusCode = status.lifecycle === "state_conflict" ? 409 : status.lifecycle === "observation_unavailable" ? 503 : 200;
    return json(response, statusCode, { ...status, observed_at: fixtureTime });
  }
  if (url.pathname === "/api/profiles" && request.method === "GET") {
    if (profileGate) await profileGate.promise;
    if (profileFailure) return json(response, 500, { code: "library_failed", error: "The profile library could not be loaded." });
    const visible = readOnly
      ? profiles.map(item => ({ ...item, capabilities: { connect: false, favorite: false, edit_metadata: false, remove: false } }))
      : profiles;
    return json(response, 200, visible);
  }
  if (url.pathname === "/api/preferences" && request.method === "GET") return json(response, 200, preferences);
  if (url.pathname === "/api/preferences" && request.method === "PUT") {
    if (preferenceFailure) return json(response, 500, { code: "preferences_failed", error: "Preferences could not be saved." });
    preferences = JSON.parse((await readBody(request)).toString("utf8"));
    profiles = profiles.map(item => ({ ...item, favorite: preferences.favorites.includes(item.id), recent: preferences.recents.includes(item.id) }));
    return json(response, 200, preferences);
  }
  if (url.pathname === "/api/connect" && request.method === "POST") {
    const body = JSON.parse((await readBody(request)).toString("utf8"));
    const selected = profiles.find(item => item.id === body.profile);
    if (selected?.display_name === hostileName) return json(response, 503, { code: "transition_failed", error: "The tunnel transition failed. The current state has been reconciled where possible." });
    status = { ...status, connected: true, lifecycle: "active", profile: selected, protocol_status: selected.protocol === "wireguard" ? status.protocol_status : { state: "active" } };
    preferences = { ...preferences, recents: [selected.id, ...preferences.recents.filter(id => id !== selected.id)].slice(0, 5) };
    profiles = profiles.map(item => ({ ...item, recent: preferences.recents.includes(item.id) }));
    return json(response, 200, { profile: selected.id, result: "connected" });
  }
  if (url.pathname === "/api/disconnect" && request.method === "POST") {
    status = { ...status, connected: false, lifecycle: "disconnected", profile: null, protocol_status: null };
    return json(response, 200, { result: "disconnected" });
  }
  if (url.pathname === "/api/imports/inspect" && request.method === "POST") {
    const body = (await readBody(request)).toString("latin1");
    if (inspectGate) await inspectGate.promise;
    inspectionSequence += 1;
    const count = Math.max(1, (body.match(/name="files"/g) || []).length);
    lastInspectionRecords = Array.from({ length: count }, (_, ordinal) => ({
      ordinal,
      id: stableID(1000 + inspectionSequence * 100 + ordinal),
      protocol: inspectScenario === "ambiguous" && ordinal === 0 ? null : ordinal % 2 ? "wireguard" : "openvpn",
      identifier: `tf${"d".repeat(9)}${String(ordinal).padStart(3, "2")}`,
      disposition: inspectScenario === "duplicate" ? "already_imported" : "new",
      issues: inspectScenario === "ambiguous" && ordinal === 0
        ? [{ field: "protocol", code: "protocol_ambiguous", message: "Choose OpenVPN or WireGuard, then inspect the file again." }]
        : inspectScenario === "policy" && ordinal === 0
          ? [{ code: "executable_hook", message: "This file uses PostUp. Tunnelfolio does not import executable hooks." }]
          : [],
    }));
    return json(response, 200, {
      library_revision: 4,
      inspection_records: lastInspectionRecords,
      suggestions: Array.from({ length: count }, (_, ordinal) => ({ ordinal, display_name: count === 1 ? "Imported office" : `Imported profile ${ordinal + 1}`, group: "Unsorted", location: "" })),
      receipt: "test-receipt",
      expires_at: new Date((fixtureEpochSeconds + 3600) * 1000).toISOString(),
      commit_ready: !["ambiguous", "policy"].includes(inspectScenario),
    });
  }
  if (url.pathname === "/api/profiles/import" && request.method === "POST") {
    await readBody(request);
    if (commitScenario === "known-failure") return json(response, 422, { code: "import_rejected", error: "The reviewed import is no longer valid." });
    if (commitScenario === "metadata-failure") return json(response, 422, { code: "invalid_metadata", error: "Profile metadata is invalid.", details: [{ file: 0, field: "group", code: "length_limit" }] });
    if (commitScenario === "delayed") await commitGate.promise;
    const importedProfiles = lastInspectionRecords
      .filter(record => record.disposition === "new")
      .map(record => profile(record.id, record.protocol || "openvpn", lastInspectionRecords.length === 1 ? "Imported office" : `Imported profile ${record.ordinal + 1}`, "Unsorted", "", false));
    if (commitScenario === "lost-partial" && importedProfiles[0] && !profiles.some(item => item.id === importedProfiles[0].id)) profiles.push(importedProfiles[0]);
    if (commitScenario === "lost-none" || commitScenario === "lost-partial") {
      request.socket.destroy();
      return;
    }
    for (const imported of importedProfiles) if (!profiles.some(item => item.id === imported.id)) profiles.push(imported);
    const records = lastInspectionRecords.map(record => ({ ordinal: record.ordinal, result: record.disposition === "new" ? "imported" : "already_imported", profile: profiles.find(item => item.id === record.id) }));
    if (commitScenario === "refresh-failure") profileFailure = true;
    return json(response, 200, { records, replayed: false, library_revision: 5 });
  }
  const match = url.pathname.match(/^\/api\/profiles\/([^/]+)$/);
  if (match && request.method === "PATCH") {
    if (metadataFailure) return json(response, 500, { code: "metadata_failed", error: "Profile metadata could not be saved." });
    const id = decodeURIComponent(match[1]);
    const patch = JSON.parse((await readBody(request)).toString("utf8"));
    const index = profiles.findIndex(item => item.id === id);
    profiles[index] = { ...profiles[index], display_name: patch.display_name, group: patch.group, location: patch.location || "" };
    return json(response, 200, profiles[index]);
  }
  if (match && request.method === "DELETE") {
    if (removalFailure) return json(response, 500, { code: "remove_failed", error: "The profile could not be removed." });
    const id = decodeURIComponent(match[1]);
    const removed = profiles.find(item => item.id === id);
    profiles = profiles.filter(item => item.id !== id);
    return json(response, 200, { result: "removed", profile: removed, cleanup_pending: false });
  }
  return json(response, 404, { code: "not_found", error: "Not found" });
}

function createServer() {
  return http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, "http://127.0.0.1");
      if (url.pathname.startsWith("/api/") || url.pathname === "/healthz") return await handleAPI(request, response, url);
      if (url.pathname === "/test-spacing.css") {
        response.writeHead(200, { "Content-Type": "text/css; charset=utf-8" });
        return response.end("* { line-height: 1.5 !important; letter-spacing: .12em !important; word-spacing: .16em !important; } p { margin-block-end: 2em !important; }");
      }
      const file = url.pathname === "/" ? path.join(webRoot, "index.html") : path.join(webRoot, "assets", path.basename(url.pathname));
      if (!fs.existsSync(file)) {
        response.writeHead(404);
        return response.end();
      }
      const contentType = file.endsWith(".css") ? "text/css; charset=utf-8" : file.endsWith(".js") ? "text/javascript; charset=utf-8" : "text/html; charset=utf-8";
      response.writeHead(200, {
        "Content-Type": contentType,
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
      });
      response.end(fs.readFileSync(file));
    } catch (error) {
      json(response, 500, { code: "test_server_error", error: error.message });
    }
  });
}

async function scan(page, state) {
  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  assert.deepEqual(result.violations, [], `${state}: ${result.violations.map(item => `${item.id} (${item.nodes.length})`).join(", ")}`);
  const openDialog = page.locator("dialog[open]");
  if (await openDialog.count()) {
    const dialogTree = await openDialog.first().ariaSnapshot();
    assert.match(dialogTree, /dialog|heading/, `${state}: active dialog accessibility tree lost its role or heading`);
  } else {
    const currentTree = await page.locator("#current-tunnel").ariaSnapshot();
    assert.match(currentTree, /heading "Current tunnel"/, `${state}: current-tunnel accessibility tree lost its static heading`);
  }
  if (artifactDir) {
    artifactSequence += 1;
    const slug = state.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    const filename = `${String(artifactSequence).padStart(2, "0")}-${slug}.png`;
    const viewport = page.viewportSize();
    const media = await page.evaluate(() => ({
      forced_colors: matchMedia("(forced-colors: active)").matches,
      reduced_motion: matchMedia("(prefers-reduced-motion: reduce)").matches,
    }));
    await page.screenshot({ path: path.join(artifactDir, filename), fullPage: true });
    artifactManifest.push({ state, file: filename, viewport, ...media });
  }
}

async function assertNoHorizontalOverflow(page, state) {
  const hiddenRecipes = await page.locator(".sr-only").evaluateAll(nodes => nodes.map(node => {
    const style = getComputedStyle(node);
    return { position: style.position, width: node.getBoundingClientRect().width, height: node.getBoundingClientRect().height, overflow: style.overflow, clipPath: style.clipPath, whiteSpace: style.whiteSpace };
  }));
  assert.ok(hiddenRecipes.length > 0, `${state}: no visually hidden status nodes were present`);
  for (const recipe of hiddenRecipes) {
    assert.ok(recipe.position === "absolute" && recipe.width <= 1 && recipe.height <= 1 && recipe.overflow === "hidden" && recipe.clipPath !== "none" && recipe.whiteSpace === "nowrap", `${state}: incomplete visually hidden recipe ${JSON.stringify(recipe)}`);
  }
  const dimensions = await page.evaluate(() => ({
    width: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth,
    offenders: [...document.querySelectorAll("body *")]
      .filter(node => !node.matches(".sr-only"))
      .map(node => ({ selector: `${node.tagName.toLowerCase()}#${node.id}.${node.className}`, left: node.getBoundingClientRect().left, right: node.getBoundingClientRect().right, scroll: node.scrollWidth, width: node.clientWidth }))
      .filter(node => node.right > document.documentElement.clientWidth + 1 || node.left < -1 || node.scroll > node.width + 1)
      .slice(0, 10),
  }));
  assert.ok(dimensions.scroll <= dimensions.width + 1, `${state}: horizontal overflow ${dimensions.scroll} > ${dimensions.width}; ${JSON.stringify(dimensions.offenders)}`);
  assert.deepEqual(dimensions.offenders, [], `${state}: clipped or horizontally overflowing descendants: ${JSON.stringify(dimensions.offenders)}`);
}

async function assertHeaderContract(page, narrowLayout) {
  const geometry = await page.evaluate(() => {
    const box = selector => {
      const node = document.querySelector(selector);
      const rect = node.getBoundingClientRect();
      return { top: rect.top, bottom: rect.bottom, left: rect.left, right: rect.right, width: rect.width, height: rect.height };
    };
    const textLines = node => {
      const range = document.createRange();
      range.selectNodeContents(node);
      return [...range.getClientRects()].filter(rect => rect.width > 0 && rect.height > 0).length;
    };
    return {
      brand: box(".brand-block"),
      title: box(".brand-block h1"),
      current: box(".current-tunnel-link"),
      actions: box(".header-actions"),
      currentDisplay: getComputedStyle(document.querySelector(".current-tunnel-link")).display,
      titleLines: textLines(document.querySelector(".brand-block h1")),
      currentLines: textLines(document.querySelector(".current-tunnel-link")),
      actionBoxes: [...document.querySelectorAll(".header-actions .button")].map(node => {
        const rect = node.getBoundingClientRect();
        return { top: rect.top, bottom: rect.bottom, height: rect.height };
      }),
      actionLines: [...document.querySelectorAll(".header-actions .button span")].map(node => ({ text: node.textContent.trim(), lines: textLines(node) })),
    };
  });
  assert.equal(geometry.currentDisplay === "none", !narrowLayout, `Current tunnel link cascade is wrong for ${narrowLayout ? "narrow" : "wide"} layout`);
  assert.equal(geometry.titleLines, 1, "Tunnelfolio wrapped in the header");
  assert.deepEqual(geometry.actionLines, [{ text: "Import profiles", lines: 1 }, { text: "Settings", lines: 1 }], "header action labels wrapped or changed");
  if (narrowLayout) {
    assert.equal(geometry.currentLines, 1, "Current tunnel wrapped in the narrow header");
    assert.ok(geometry.current.width > 0 && geometry.current.height >= 44, "narrow Current tunnel link is not visibly operable");
    assert.ok(geometry.actions.top >= Math.max(geometry.brand.bottom, geometry.current.bottom) - 1, "narrow header actions are not on the deliberate second row");
    assert.ok(Math.abs(geometry.actionBoxes[0].top - geometry.actionBoxes[1].top) <= 1, "Import and Settings split across extra narrow-header rows");
    assert.ok(geometry.actions.height <= Math.max(...geometry.actionBoxes.map(box => box.height)) + 1, "narrow action row contains an unintended wrap");
  }
}

async function assertSimplifiedWorkspace(page) {
  const structure = await page.evaluate(() => {
    const folio = document.querySelector("#main-content");
    const library = document.querySelector("#library-screen").getBoundingClientRect();
    const detail = document.querySelector("#detail-screen").getBoundingClientRect();
    return {
      legacyIndexCount: document.querySelectorAll(".folio-index").length,
      display: getComputedStyle(folio).display,
      libraryRight: library.right,
      detailLeft: detail.left,
      viewsInFilters: document.querySelector("#profile-filters #view-filter") !== null,
      groupInFilters: document.querySelector("#profile-filters #group-filter") !== null,
      openVPNInSettings: document.querySelector("#settings-dialog #openvpn-availability") !== null,
      wireGuardInSettings: document.querySelector("#settings-dialog #wireguard-availability") !== null,
    };
  });
  assert.equal(structure.legacyIndexCount, 0, "the retired index pane is still rendered");
  assert.equal(structure.display, "grid", "wide workspace is not a two-pane grid");
  assert.ok(Math.abs(structure.libraryRight - structure.detailLeft) <= 1, "wide library and detail panes do not meet");
  assert.equal(structure.viewsInFilters, true, "profile views did not move into the library filters");
  assert.equal(structure.groupInFilters, true, "group filtering did not move into the library filters");
  assert.equal(structure.openVPNInSettings, true, "OpenVPN availability did not move into Settings");
  assert.equal(structure.wireGuardInSettings, true, "WireGuard availability did not move into Settings");
}

async function tabTo(page, selector, { reverse = false, limit = 40 } = {}) {
  for (let count = 0; count < limit; count += 1) {
    await page.keyboard.press(reverse ? "Shift+Tab" : "Tab");
    if (await page.evaluate(value => document.activeElement?.matches(value) === true, selector)) return;
  }
  throw new Error(`Sequential keyboard navigation did not reach ${selector}`);
}

async function refreshTo(page, expected) {
  await page.locator("#status-refresh").click();
  await page.waitForFunction(value => document.querySelector("#current-state")?.textContent === value, expected);
}

async function waitImportOutcome(page) {
  await page.waitForFunction(() => {
    const panel = document.querySelector("#import-outcome-panel");
    return panel && !panel.hidden && document.querySelector("#import-outcome-text")?.textContent.trim();
  });
}

(async () => {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const launchOptions = browserName === "chromium"
    ? { executablePath, headless: true, args: ["--no-sandbox"], timeout: 30000 }
    : { headless: true, timeout: 30000 };
  const browser = await browserType.launch(launchOptions);
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: "reduce" });
    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    page.setDefaultNavigationTimeout(15000);
    await page.clock.setFixedTime(fixtureTime);
    profileGate = deferred();
    await page.goto(origin, { waitUntil: "domcontentloaded" });
    await scan(page, "initial library loading");
    profileGate.resolve();
    profileGate = null;
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "3 profiles");

    assert.equal(await page.locator(".profile-row-button").count(), 3, "each profile must render as one row button");
    assert.equal(await page.locator("img").count(), 0, "profile metadata created an image element");
    assert.equal(await page.evaluate(() => globalThis.injected), undefined, "profile metadata executed script");
    assert.match(await page.locator(".profile-name").first().textContent(), /^<img src=x/, "hostile metadata was not rendered literally");
    assert.equal(await page.locator("#location-filter option").count(), 4, "location filter was not derived from profile metadata");
    const tokens = await page.evaluate(() => {
      const style = getComputedStyle(document.documentElement);
      return Object.fromEntries(["surface-page", "surface-panel", "surface-raised", "border-control", "text-primary", "text-secondary", "action-fill", "action-ink", "state-active", "state-warning", "state-danger"].map(name => [name, style.getPropertyValue(`--${name}`).trim()]));
    });
    for (const fill of ["action-fill", "state-active", "state-warning", "state-danger"]) assert.ok(contrast(tokens[fill], tokens["action-ink"]) >= 4.5, `${fill} does not support normal-size action text`);
    for (const ink of ["text-primary", "text-secondary"]) assert.ok(contrast(tokens[ink], tokens["surface-panel"]) >= 4.5, `${ink} does not meet text contrast`);
    for (const surface of ["surface-page", "surface-panel", "surface-raised"]) assert.ok(contrast(tokens["border-control"], tokens[surface]) >= 3, `border-control does not meet non-text contrast on ${surface}`);
    await assertHeaderContract(page, false);
    await assertSimplifiedWorkspace(page);
    await scan(page, "ready populated library");
    await page.evaluate(() => document.activeElement?.blur());
    await tabTo(page, ".skip-link");
    await tabTo(page, "#import-open");
    await tabTo(page, "#settings-open", { limit: 120 });
    await tabTo(page, "#import-open", { reverse: true });

    await page.locator("#profile-search").fill("tfbbbbbbbbbbbb");
    assert.equal(await page.locator(".profile-row-button").count(), 1, "runtime identifiers must be searchable");
    await page.locator("#profile-search").fill("no profile can match this");
    assert.equal(await page.locator("#filtered-empty").isVisible(), true);
    await scan(page, "filtered-zero recovery");
    await page.locator("#clear-filters").focus();
    await page.keyboard.press("Enter");
    assert.equal(await page.locator(".profile-row-button").count(), 3);

    const japan = page.locator('[data-profile-id="tf_bbbbbbbbbbbbbbbbbbbbbbbbbb"]');
    await tabTo(page, '[data-profile-id="tf_bbbbbbbbbbbbbbbbbbbbbbbbbb"]');
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.activeElement?.id === "detail-title");
    assert.match(await page.locator("#detail-title").textContent(), /Japan/);
    assert.match(await japan.locator(".profile-state").textContent(), /Selected · Connected/);
    assert.equal(await page.locator(".profile-summary .definition").count(), 3, "primary profile summary contains technical metadata");
    assert.equal(await page.locator(".technical-details").getAttribute("open"), null, "technical details are expanded by default");
    assert.match(await page.locator(".technical-details").textContent(), /Runtime identifier.*Original file.*Imported/s);
    assert.match(await page.locator("#protocol-details").textContent(), /198\.51\.100\.8:51820/);
    assert.match(await page.locator("#protocol-details").textContent(), /No handshake observed/);
    await page.locator("#detail-back").focus();
    await page.locator("#status-refresh").click();
    assert.equal(await page.evaluate(() => document.activeElement?.id), "status-refresh", "status polling replaced unrelated focused controls");
    await scan(page, "selected connected detail");

    await tabTo(page, '[data-detail-action="edit"]');
    await page.keyboard.press("Enter");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "edit-title");
    await scan(page, "metadata dialog");
    await page.keyboard.press("Escape");
    assert.equal(await page.evaluate(() => document.activeElement?.dataset?.detailAction), "edit");

    await tabTo(page, "#settings-open", { reverse: true, limit: 120 });
    await page.keyboard.press("Enter");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "settings-title");
    await scan(page, "manual startup settings");
    preferenceFailure = true;
    await tabTo(page, 'input[name="startup-mode"]:checked');
    await page.keyboard.press("ArrowDown");
    assert.equal(await page.evaluate(() => document.activeElement?.value), "restore");
    await tabTo(page, "#save-settings");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.activeElement?.id === "settings-error");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "settings-error");
    await scan(page, "settings save failure");
    preferenceFailure = false;
    await tabTo(page, "#save-settings");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => !document.querySelector("#settings-dialog")?.open);
    assert.equal(await page.evaluate(() => document.activeElement?.id), "settings-open");

    await page.locator("#status-pause").click();
    assert.equal(await page.locator("#status-pause").getAttribute("aria-pressed"), "true");
    assert.equal(await page.locator("#status-pause").textContent(), "Pause status updates");
    assert.match(await page.locator("#current-observed").textContent(), /Updates paused/);
    await scan(page, "paused status polling");
    await page.locator("#status-refresh").click();
    assert.match(await page.locator("#current-observed").textContent(), /Updates paused/);
    await page.locator("#status-pause").click();
    assert.equal(await page.locator("#status-pause").getAttribute("aria-pressed"), "false");
    await scan(page, "active status polling");

    await tabTo(page, '[data-profile-id="tf_cccccccccccccccccccccccccc"]');
    await page.keyboard.press("Enter");
    assert.match(await page.locator('[data-profile-id="tf_cccccccccccccccccccccccccc"] .profile-state').textContent(), /Selected/);
    assert.doesNotMatch(await page.locator('[data-profile-id="tf_cccccccccccccccccccccccccc"] .profile-state').textContent(), /Connected/);
    assert.match(await page.locator('[data-profile-id="tf_bbbbbbbbbbbbbbbbbbbbbbbbbb"] .profile-state').textContent(), /Connected/);
    assert.doesNotMatch(await page.locator('[data-profile-id="tf_bbbbbbbbbbbbbbbbbbbbbbbbbb"] .profile-state').textContent(), /Selected/);
    await scan(page, "inactive profile detail");
    await tabTo(page, '[data-detail-action="connect"]');
    assert.match(await page.locator('[data-detail-action="connect"]').textContent(), /Germany/);
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.activeElement?.id === "current-title"
      && document.querySelector("#current-title")?.textContent.includes("Germany")
      && document.querySelector("#current-tunnel")?.getAttribute("aria-busy") === "false"
      && document.querySelector("#current-state")?.textContent.startsWith("WireGuard interface active"));
    assert.equal(preferences.recents[0], "tf_cccccccccccccccccccccccccc", "server recents did not record the successful connection");
    await page.locator('input[name="profile-view"][value="recent"]').check();
    assert.equal(await page.locator('[data-profile-id="tf_cccccccccccccccccccccccccc"]').count(), 1, "connected profile did not enter the Recent view");
    await page.locator('input[name="profile-view"][value="all"]').check();
    await page.locator('[data-profile-id="tf_cccccccccccccccccccccccccc"]').click();
    await page.locator('[data-detail-action="favorite"]').click();
    assert.equal(preferences.recents[0], "tf_cccccccccccccccccccccccccc", "favorite save erased the server's recent history");

    await tabTo(page, "#import-open", { reverse: true, limit: 120 });
    await page.keyboard.press("Enter");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "import-title");
    await scan(page, "import choose dialog");
    await tabTo(page, "#profile-files");
    await tabTo(page, "#import-close", { reverse: true });
    await tabTo(page, "#profile-files");
    await page.locator("#profile-files").setInputFiles({ name: "office.ovpn", mimeType: "application/octet-stream", buffer: Buffer.from("client\ndev tun\nremote 198.51.100.1 1194\n") });
    await tabTo(page, "#inspect-profiles");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => !document.querySelector("#import-review-panel")?.hidden);
    assert.equal(await page.locator(".import-file").count(), 1);
    await scan(page, "import review dialog");
    await tabTo(page, "#trust-profiles");
    await page.keyboard.press("Space");
    await tabTo(page, "#commit-import");
    await page.keyboard.press("Enter");
    await waitImportOutcome(page);
    await scan(page, "import outcome dialog");
    await tabTo(page, "#import-finish");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "4 profiles");
    await page.waitForFunction(() => document.activeElement?.id === "profiles-title");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "profiles-title", "import completion did not return focus to the library");

    await page.locator('[data-profile-id="tf_aaaaaaaaaaaaaaaaaaaaaaaaaa"]').click();
    await page.locator('[data-detail-action="connect"]').click();
    await page.waitForFunction(() => !document.querySelector("#page-error")?.hidden);
    assert.equal(await page.evaluate(() => document.activeElement?.id), "page-error-title");
    await scan(page, "persistent operation error");
    await page.locator("#page-error-dismiss").click();
    assert.equal(await page.evaluate(() => document.activeElement?.id), "current-title", "failed connection did not settle focus on current tunnel status");

    status = { ...status, connected: false, lifecycle: "switching", profile: profiles[2], protocol_status: null };
    await refreshTo(page, "Switching tunnel");
    assert.equal(await page.locator("#current-state").textContent(), "Switching tunnel");
    assert.equal(await page.locator("#current-tunnel").getAttribute("aria-busy"), "true");
    await scan(page, "switching lifecycle");
    status = { ...status, connected: false, lifecycle: "failed", profile: null, error: "The desired profile could not be restored." };
    await refreshTo(page, "The desired profile could not be restored.");
    assert.equal(await page.locator("#current-state").textContent(), "The desired profile could not be restored.");
    await scan(page, "failed lifecycle");
    status = { ...status, connected: false, lifecycle: "state_conflict", observation_available: false, can_disconnect: true, profile: null, protocol_status: null, error: "Two managed tunnels were observed." };
    await refreshTo(page, "Two managed tunnels were observed.");
    assert.equal(await page.locator("#current-state").textContent(), "Two managed tunnels were observed.");
    assert.equal(await page.locator("#current-tunnel").getAttribute("data-state"), "danger");
    assert.equal(await page.locator("#disconnect").isVisible(), true, "recoverable managed conflict hid Disconnect");
    assert.equal(await page.locator("#disconnect").isDisabled(), false, "recoverable managed conflict disabled Disconnect");
    await scan(page, "managed-state conflict");
    status = { ...status, connected: false, lifecycle: "observation_unavailable", observation_available: false, can_disconnect: false, profile: null, protocol_status: null, error: "Tunnel state could not be observed." };
    await refreshTo(page, "Tunnel state could not be observed.");
    assert.match(await page.locator("#current-observed").textContent(), /last known status/);
    assert.equal(await page.locator("#disconnect").isVisible(), false);
    await scan(page, "status observation unavailable");
    status = { ...status, connected: true, lifecycle: "active", observation_available: true, profile: profiles[1], protocol_status: { state: "interface_active", received_bytes: 15360, sent_bytes: 4096, peers: [{ endpoint: "198.51.100.8:51820", latest_handshake: 0, received_bytes: 15360, sent_bytes: 4096 }] }, protocols: { openvpn: { available: false, reason: "openvpn was not found" }, wireguard: { available: true } } };
    profiles[0] = { ...profiles[0], available: false, unavailable_reason: "OpenVPN is unavailable on this host." };
    await page.reload({ waitUntil: "networkidle" });
    await page.waitForFunction(() => document.querySelector("#current-state")?.textContent === "WireGuard interface active · no handshake observed");
    assert.match(await page.locator("#current-state").textContent(), /no handshake observed/);
    assert.match(await page.locator("#openvpn-availability").textContent(), /unavailable|not found/);
    await scan(page, "active WireGuard without handshake");
    await page.locator('[data-profile-id="tf_aaaaaaaaaaaaaaaaaaaaaaaaaa"]').click();
    assert.equal(await page.locator('[data-detail-action="connect"]').isDisabled(), true);
    assert.match(await page.locator("#detail-content").textContent(), /OpenVPN is unavailable/);
    await scan(page, "protocol-degraded unavailable detail");
    profiles[0] = { ...profiles[0], available: true, unavailable_reason: "" };
    statusFailure = true;
    await page.locator('[data-profile-id="tf_cccccccccccccccccccccccccc"]').click();
    await page.locator("#status-refresh").click();
    await page.waitForFunction(() => document.querySelector("#current-observed")?.textContent.includes("last known status"));
    assert.match(await page.locator("#current-observed").textContent(), /last known status/);
    assert.match(await page.locator("#status-announcer").textContent(), /unavailable/);
    assert.equal(await page.locator('[data-detail-action="connect"]').isDisabled(), true, "stale state left Connect enabled");
    assert.equal(await page.locator('[data-detail-action="remove"]').isDisabled(), true, "stale state left removal enabled");
    assert.equal(await page.locator("#disconnect").isDisabled(), true, "stale state left Disconnect enabled");
    await scan(page, "stale last-known tunnel status");
    await page.locator("#page-error-dismiss").click();
    statusFailure = false;
    status.protocols.openvpn = { available: true };
    await page.locator("#status-refresh").click();
    await page.waitForFunction(() => document.querySelector("#status-announcer")?.textContent === "Tunnel status observation restored");
    assert.equal(await page.locator("#status-announcer").textContent(), "Tunnel status observation restored");

    for (const lifecycle of ["restoring", "starting", "disconnecting"]) {
      status = { ...status, connected: false, lifecycle, observation_available: true, profile: lifecycle === "disconnecting" ? null : profiles[1], protocol_status: null, error: "" };
      const expected = lifecycle === "restoring" ? "Restoring tunnel" : lifecycle === "starting" ? "Starting tunnel" : "Disconnecting tunnel";
      await refreshTo(page, expected);
      assert.equal(await page.locator("#current-state").textContent(), expected);
      await scan(page, `${lifecycle} lifecycle`);
    }
    status = { ...status, connected: true, lifecycle: "active", profile: profiles[0], protocol_status: { state: "active" } };
    await refreshTo(page, "OpenVPN active");
    assert.equal(await page.locator("#current-state").textContent(), "OpenVPN active");
    await scan(page, "active OpenVPN");
    status = { ...status, connected: false, lifecycle: "disconnected", profile: null, protocol_status: null };
    await refreshTo(page, "No managed tunnel is active.");
    assert.equal(await page.locator("#current-state").textContent(), "No managed tunnel is active.");
    await scan(page, "disconnected tunnel");
    status = { ...status, connected: true, lifecycle: "active", profile: profiles[1], protocol_status: { state: "interface_active", received_bytes: 15360, sent_bytes: 4096, peers: [{ endpoint: "198.51.100.8:51820", latest_handshake: fixtureEpochSeconds, received_bytes: 15360, sent_bytes: 4096 }] } };
    await refreshTo(page, "WireGuard interface active · handshake observed");
    assert.match(await page.locator("#current-state").textContent(), /handshake observed/);
    await scan(page, "active WireGuard with handshake");
    await page.locator('[data-profile-id="tf_bbbbbbbbbbbbbbbbbbbbbbbbbb"]').click();
    assert.match(await page.locator("#protocol-details").textContent(), /198\.51\.100\.8:51820/);
    status = { ...status, protocol_status: { state: "observation_unavailable" }, error: "Protocol status could not be observed." };
    await refreshTo(page, "WireGuard interface active · protocol observation unavailable");
    assert.doesNotMatch(await page.locator("#current-state").textContent(), /no handshake observed/);
    assert.match(await page.locator("#protocol-details").textContent(), /Protocol observationUnavailable/);
    status = { ...status, protocol_status: { state: "interface_active", received_bytes: 15360, sent_bytes: 4096, peers: [{ endpoint: "198.51.100.8:51820", latest_handshake: fixtureEpochSeconds, received_bytes: 15360, sent_bytes: 4096 }] }, error: "" };

    await page.setViewportSize({ width: 320, height: 800 });
    await assertHeaderContract(page, true);
    await page.locator('.profile-row-button[data-profile-id="tf_bbbbbbbbbbbbbbbbbbbbbbbbbb"]').click();
    assert.equal(await page.locator("#detail-screen").isVisible(), true);
    await page.goBack();
    await page.waitForFunction(() => document.querySelector("#main-content")?.dataset.screen === "library");
    assert.equal(await page.evaluate(() => document.activeElement?.dataset?.profileId), "tf_bbbbbbbbbbbbbbbbbbbbbbbbbb", "browser Back did not restore the selected row");
    await assertNoHorizontalOverflow(page, "320 CSS-pixel reflow and 400% zoom equivalent");
    await page.setViewportSize({ width: 640, height: 800 });
    await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
    await assertNoHorizontalOverflow(page, "200% text resize");
    await page.addStyleTag({ url: `${origin}/test-spacing.css` });
    await assertNoHorizontalOverflow(page, "WCAG text spacing override");

    await page.evaluate(() => { document.documentElement.style.fontSize = ""; });
    await page.setViewportSize({ width: 320, height: 800 });
    await page.emulateMedia({ forcedColors: "active", reducedMotion: "reduce" });
    await scan(page, "forced colors narrow library");
    const targets = await page.locator("button:visible, select:visible, input[type=search]:visible, input[type=text]:visible, input[type=file]:visible, a.inline-skip:visible, .error-summary a:visible, summary:visible, label:has(input[type=radio]):visible, label:has(input[type=checkbox]):visible").evaluateAll(nodes => nodes.map(node => ({ id: node.id, width: node.getBoundingClientRect().width, height: node.getBoundingClientRect().height })));
    for (const target of targets) assert.ok(target.width >= 44 && target.height >= 44, `${target.id || "control"} is smaller than the 44px target policy`);

    await page.emulateMedia({ forcedColors: "none", reducedMotion: "reduce" });
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.locator('[data-profile-id="tf_bbbbbbbbbbbbbbbbbbbbbbbbbb"]').click();
    assert.equal(await page.locator('[data-detail-action="remove"]').isDisabled(), true, "the active profile could be removed");
    await scan(page, "active profile removal blocked");
    await page.locator('[data-profile-id="tf_cccccccccccccccccccccccccc"]').click();
    metadataFailure = true;
    await tabTo(page, '[data-detail-action="edit"]');
    await page.keyboard.press("Enter");
    await tabTo(page, "#edit-name");
    await page.keyboard.press("ControlOrMeta+A");
    await page.keyboard.type("Frankfurt");
    await tabTo(page, '#edit-form button[type="submit"]');
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.activeElement?.id === "edit-error");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "edit-error");
    await scan(page, "metadata save failure");
    metadataFailure = false;
    await tabTo(page, "#edit-close", { reverse: true });
    await page.keyboard.press("Enter");
    assert.equal(await page.evaluate(() => document.activeElement?.dataset?.detailAction), "edit");

    await tabTo(page, '[data-detail-action="remove"]');
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.querySelector("#confirm-dialog")?.open
      && document.querySelector("#confirm-title")?.textContent.includes("Germany"));
    assert.match(await page.locator("#confirm-title").textContent(), /Germany/);
    await scan(page, "removal confirmation");
    await tabTo(page, "#confirm-cancel");
    await page.keyboard.press("Enter");
    assert.equal(await page.evaluate(() => document.activeElement?.dataset?.detailAction), "remove");
    removalFailure = true;
    await page.keyboard.press("Enter");
    await tabTo(page, "#confirm-action");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.activeElement?.id === "page-error-title");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "page-error-title");
    assert.equal(await page.locator('.profile-row-button[data-profile-id="tf_cccccccccccccccccccccccccc"]').count(), 1);
    await scan(page, "removal failure");
    await tabTo(page, "#page-error-dismiss");
    await page.keyboard.press("Enter");
    removalFailure = false;
    await tabTo(page, '[data-detail-action="remove"]');
    await page.keyboard.press("Enter");
    await tabTo(page, "#confirm-action");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "3 profiles");
    assert.equal(await page.locator('.profile-row-button[data-profile-id="tf_cccccccccccccccccccccccccc"]').count(), 0);
    assert.match(await page.evaluate(() => document.activeElement?.dataset?.profileId || ""), /^tf_/, "removal did not focus the next surviving row");
    await scan(page, "removal success settlement");

    await page.locator('[data-detail-action="favorite"]').click();
    await page.locator("#settings-open").click();
    await page.locator("#clear-favorites").click();
    await scan(page, "clear favorites confirmation");
    await page.locator("#confirm-action").click();
    await page.waitForFunction(() => document.querySelector("#status-announcer")?.textContent === "Favorites cleared");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "clear-recents");
    await page.locator("#clear-recents").click();
    await scan(page, "clear recents confirmation");
    await page.locator("#confirm-action").click();
    await page.waitForFunction(() => document.querySelector("#status-announcer")?.textContent === "Recent profiles cleared");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "settings-title");
    await scan(page, "stored-view clear settlement");
    await page.locator("#settings-close").click();

    readOnly = true;
    await page.evaluate(() => { document.documentElement.style.fontSize = ""; });
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.reload({ waitUntil: "networkidle" });
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "3 profiles");
    assert.equal(await page.locator("#import-open").isDisabled(), true);
    await page.locator(".profile-row-button").first().click();
    assert.equal(await page.locator('[data-detail-action="connect"]').isDisabled(), true);
    assert.equal(await page.locator('[data-detail-action="favorite"]').isDisabled(), true);
    assert.equal(await page.locator('[data-detail-action="edit"]').isDisabled(), true);
    assert.equal(await page.locator('[data-detail-action="remove"]').isDisabled(), true);
    assert.equal(await page.locator("#disconnect").isDisabled(), true);
    assert.match(await page.locator("#read-only-notice").textContent(), /Read-only mode.*changes are disabled/);
    assert.equal(await page.locator("#read-only-notice").isVisible(), true);
    await scan(page, "read-only library");

    readOnly = false;
    profiles = [
      profile("tf_aaaaaaaaaaaaaaaaaaaaaaaaaa", "openvpn", "Office gateway", "Work", "London", false),
      profile("tf_bbbbbbbbbbbbbbbbbbbbbbbbbb", "wireguard", "Japan", "Mullvad", "JP", true),
      profile("tf_cccccccccccccccccccccccccc", "wireguard", "Germany — Frankfurt", "Mullvad", "DE", false),
    ];
    preferences = { favorites: [profiles[1].id], recents: [profiles[1].id], startup_mode: "restore" };
    status = { ...status, connected: true, lifecycle: "active", observation_available: true, profile: profiles[1], protocol_status: { state: "interface_active", received_bytes: 15360, sent_bytes: 4096, peers: [{ endpoint: "198.51.100.8:51820", latest_handshake: fixtureEpochSeconds, received_bytes: 15360, sent_bytes: 4096 }] } };
    await page.reload({ waitUntil: "networkidle" });
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "3 profiles");
    await page.locator('[data-profile-id="tf_cccccccccccccccccccccccccc"]').click();
    await page.emulateMedia({ forcedColors: "none", reducedMotion: "reduce" });
    if (artifactDir) await page.screenshot({ path: path.join(artifactDir, "folio-desk.png"), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    if (artifactDir) await page.screenshot({ path: path.join(artifactDir, "folio-desk-narrow.png"), fullPage: true });

    for (const viewport of [{ width: 320, height: 568 }, { width: 375, height: 667 }, { width: 568, height: 320 }, { width: 768, height: 720 }, { width: 1119, height: 720 }, { width: 1120, height: 720 }, { width: 1121, height: 720 }, { width: 1440, height: 900 }]) {
      await page.setViewportSize(viewport);
      await assertNoHorizontalOverflow(page, `${viewport.width}x${viewport.height} viewport`);
      await scan(page, `${viewport.width}x${viewport.height} responsive probe`);
    }
    await page.setViewportSize({ width: 568, height: 256 });
    await page.evaluate(() => document.activeElement?.blur());
    await tabTo(page, "#settings-open", { limit: 120 });
    await page.keyboard.press("Enter");
    await tabTo(page, 'input[name="startup-mode"]:checked');
    if (await page.evaluate(() => document.activeElement?.value !== "restore")) await page.keyboard.press("ArrowDown");
    const keyboardFocus = await page.locator('input[name="startup-mode"][value="restore"]').boundingBox();
    assert.ok(keyboardFocus && keyboardFocus.y >= 0 && keyboardFocus.y + keyboardFocus.height <= 256, "focused setting was obscured in the 256px-height viewport proxy");
    await scan(page, "restore startup settings");
    await scan(page, "256px-height viewport proxy (not an actual software-keyboard session)");
    await page.keyboard.press("Escape");

    profileFailure = true;
    await page.reload({ waitUntil: "networkidle" });
    assert.equal(await page.locator("#library-error").isVisible(), true);
    assert.equal(await page.locator("#result-count").textContent(), "Library unavailable");
    assert.match(await page.locator("#page-error-announcer").textContent(), /could not be loaded/);
    await scan(page, "library load failure");
    profileFailure = false;
    await page.locator("#library-retry").click();
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "3 profiles");

    profiles = Array.from({ length: 50 }, (_, index) => profile(stableID(index), index % 2 ? "wireguard" : "openvpn", `Profile ${String(index + 1).padStart(3, "0")}`, `Group ${String(index + 1).padStart(3, "0")}`, index % 2 ? "JP" : "DE", index > 44));
    status = { ...status, connected: true, lifecycle: "active", profile: profiles[24], protocol_status: { state: "interface_active", received_bytes: 1, sent_bytes: 2, peers: [] } };
    preferences = { favorites: [profiles[0].id, profiles[24].id, profiles[49].id], recents: profiles.slice(45).map(item => item.id), startup_mode: "manual" };
    await page.setViewportSize({ width: 375, height: 667 });
    await page.reload({ waitUntil: "networkidle" });
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "50 profiles");
    assert.equal(await page.locator(".profile-row-button").count(), 50);
    assert.equal(await page.locator("#group-filter").count(), 1, "Group filtering must remain one native control");
    await page.locator("#profile-search").focus();
    await page.keyboard.type("Profile 050");
    assert.equal(await page.locator(".profile-row-button").count(), 1, "native keyboard filtering did not isolate the expected profile");
    await tabTo(page, ".profile-row-button");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.querySelector("#main-content")?.dataset.screen === "detail");
    await page.keyboard.press("Shift+Tab");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "detail-back");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.querySelector("#main-content")?.dataset.screen === "library");
    assert.equal(await page.evaluate(() => document.activeElement?.dataset?.profileId), profiles[49].id);
    await page.keyboard.press("Shift+Tab");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "skip-profile-list", "narrow keyboard path did not reach Skip profile list from the selected row");
    assert.deepEqual(await page.evaluate(() => history.state), { screen: "library" });
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.querySelector("#main-content")?.dataset.screen === "detail" && document.activeElement?.id === "detail-title");
    assert.deepEqual(await page.evaluate(() => history.state), { screen: "detail", profile: profiles[49].id });
    assert.match(await page.locator("#detail-title").textContent(), /Profile 050/);
    await page.keyboard.press("Shift+Tab");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "detail-back");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.querySelector("#main-content")?.dataset.screen === "library" && document.activeElement?.dataset?.profileId);
    await assertNoHorizontalOverflow(page, "50-profile narrow fixture");
    await scan(page, "50-profile narrow list detail skip and return");

    profiles = Array.from({ length: 100 }, (_, index) => profile(stableID(index), index % 2 ? "wireguard" : "openvpn", `Profile ${String(index + 1).padStart(3, "0")}`, `Group ${String(index + 1).padStart(3, "0")}`, index % 2 ? "JP" : "DE", index > 94));
    status = { ...status, connected: true, lifecycle: "active", profile: profiles[49], protocol_status: { state: "interface_active", received_bytes: 1, sent_bytes: 2, peers: [] } };
    preferences = { favorites: [profiles[0].id, profiles[49].id, profiles[99].id], recents: profiles.slice(95).map(item => item.id), startup_mode: "manual" };
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.reload({ waitUntil: "networkidle" });
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "100 profiles");
    assert.equal(await page.locator(".profile-row-button").count(), 100);
    assert.equal(await page.locator("#group-filter option").count(), 101);
    for (const index of [0, 49, 99]) {
      const row = page.locator(".profile-row-button").nth(index);
      await row.scrollIntoViewIfNeeded();
      const before = await page.evaluate(() => ({ window: window.scrollY, library: document.querySelector("#library-screen").scrollTop }));
      await row.click();
      assert.equal(await page.evaluate(() => document.activeElement?.id), "detail-title", `row ${index + 1} did not focus detail`);
      await page.locator("#detail-back").click();
      const after = await page.evaluate(() => ({ window: window.scrollY, library: document.querySelector("#library-screen").scrollTop, focused: document.activeElement?.dataset?.profileId }));
      assert.equal(after.focused, profiles[index].id, `row ${index + 1} was not refocused on return`);
      assert.ok(Math.abs(after.window - before.window) <= 1 && Math.abs(after.library - before.library) <= 1, `row ${index + 1} lost its exact scroll position: ${JSON.stringify({ before, after })}`);
    }
    await page.setViewportSize({ width: 320, height: 568 });
    for (const index of [0, 49, 99]) {
      for (const returnMethod of ["Back control", "browser Back"]) {
        const row = page.locator(".profile-row-button").nth(index);
        await row.scrollIntoViewIfNeeded();
        await row.focus();
        const before = await page.evaluate(() => ({ window: window.scrollY, library: document.querySelector("#library-screen").scrollTop }));
        await page.keyboard.press("Enter");
        await page.waitForFunction(() => document.querySelector("#main-content")?.dataset.screen === "detail");
        if (returnMethod === "Back control") await page.locator("#detail-back").click();
        else await page.goBack();
        await page.waitForFunction(() => document.querySelector("#main-content")?.dataset.screen === "library");
        await page.waitForFunction(expected => {
          const library = document.querySelector("#library-screen").scrollTop;
          return Math.abs(window.scrollY - expected.window) <= 1 && Math.abs(library - expected.library) <= 1;
        }, before).catch(async () => {
          const current = await page.evaluate(() => ({ window: window.scrollY, library: document.querySelector("#library-screen").scrollTop, focused: document.activeElement?.dataset?.profileId }));
          assert.fail(`${returnMethod} did not restore narrow row ${index + 1} scroll: ${JSON.stringify({ before, current })}`);
        });
        const after = await page.evaluate(() => ({ window: window.scrollY, library: document.querySelector("#library-screen").scrollTop, focused: document.activeElement?.dataset?.profileId }));
        assert.equal(after.focused, profiles[index].id, `${returnMethod} did not refocus narrow row ${index + 1}`);
        assert.ok(Math.abs(after.window - before.window) <= 1 && Math.abs(after.library - before.library) <= 1, `${returnMethod} lost narrow row ${index + 1} scroll: ${JSON.stringify({ before, after })}`);
      }
    }
    await scan(page, "100-profile narrow library and detail return");

    profiles = [];
    preferences = { favorites: [], recents: [], startup_mode: "manual" };
    status = { ...status, connected: false, lifecycle: "disconnected", profile: null, protocol_status: null };
    readOnly = false;
    await page.reload({ waitUntil: "networkidle" });
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "0 profiles");
    await scan(page, "first-use empty library");
    await page.locator("#empty-import").click();
    await page.locator("#import-close").click();
    assert.equal(await page.evaluate(() => document.activeElement?.id), "empty-import", "first-use import did not return focus to its opener");
    await page.locator("#import-open").click();
    const hundredFiles = Array.from({ length: 100 }, (_, index) => ({ name: `profile-${String(index + 1).padStart(3, "0")}.ovpn`, mimeType: "application/octet-stream", buffer: Buffer.from("client\ndev tun\nremote 198.51.100.1 1194\n") }));
    await page.locator("#profile-files").setInputFiles(hundredFiles);
    await page.locator("#inspect-profiles").click();
    await page.waitForFunction(() => document.querySelectorAll(".import-file").length === 100);
    assert.match(await page.locator(".import-file").nth(0).textContent(), /profile-001/);
    assert.match(await page.locator(".import-file").nth(49).textContent(), /profile-050/);
    assert.match(await page.locator(".import-file").nth(99).textContent(), /profile-100/);
    await scan(page, "100-file import review");
    await page.locator("#import-close").click();
    await scan(page, "100-file discard confirmation");
    await page.locator("#discard-import").click();

    await page.locator("#import-open").click();
    await page.locator("#profile-files").setInputFiles({ name: "cancel.ovpn", mimeType: "application/octet-stream", buffer: Buffer.from("client\ndev tun\nremote 198.51.100.1 1194\n") });
    inspectGate = deferred();
    await page.locator("#inspect-profiles").click();
    assert.equal(await page.locator("#import-inspect-panel").isVisible(), true);
    await scan(page, "import inspection in progress");
    await page.locator("#cancel-inspection").click();
    inspectGate.resolve();
    inspectGate = null;
    await page.waitForFunction(() => !document.querySelector("#import-choose-panel")?.hidden);
    assert.equal(await page.evaluate(() => document.activeElement?.id), "inspect-profiles");
    assert.match(await page.locator("#status-announcer").textContent(), /cancelled/);
    await scan(page, "inspection cancelled settlement");
    await page.locator("#import-close").click();
    await page.locator("#discard-import").click();

    inspectScenario = "ambiguous";
    await page.locator("#import-open").click();
    await page.locator("#profile-files").setInputFiles({ name: "ambiguous.conf", mimeType: "application/octet-stream", buffer: Buffer.from("unrecognized=true\n") });
    await page.locator("#inspect-profiles").click();
    await page.waitForFunction(() => !document.querySelector("#import-review-panel")?.hidden);
    assert.equal(await page.locator(".import-file").first().getAttribute("open"), "");
    assert.equal(await page.locator("#commit-import").isDisabled(), true);
    assert.equal(await page.locator("#import-protocol-0").getAttribute("aria-invalid"), "true");
    assert.match(await page.locator("#import-protocol-0").getAttribute("aria-describedby"), /import-protocol-0-error/);
    await scan(page, "ambiguous protocol review");
    await page.locator("#import-close").click();
    await page.locator("#discard-import").click();

    inspectScenario = "policy";
    await page.locator("#import-open").click();
    await page.locator("#profile-files").setInputFiles({ name: "hook.conf", mimeType: "application/octet-stream", buffer: Buffer.from("[Interface]\nPostUp = run-me\n") });
    await page.locator("#inspect-profiles").click();
    await page.waitForFunction(() => !document.querySelector("#import-review-panel")?.hidden);
    assert.match(await page.locator("#import-errors").textContent(), /does not import executable hooks/);
    assert.equal(await page.locator(".import-file").first().getAttribute("open"), "");
    assert.equal(await page.locator("#import-file-summary-0").getAttribute("aria-invalid"), "true");
    assert.match(await page.locator("#import-file-summary-0").getAttribute("aria-describedby"), /import-file-summary-0-error/);
    await scan(page, "policy-rejected import review");
    await page.locator("#import-close").click();
    await page.locator("#discard-import").click();

    inspectScenario = "duplicate";
    await page.locator("#import-open").click();
    await page.locator("#profile-files").setInputFiles({ name: "duplicate.ovpn", mimeType: "application/octet-stream", buffer: Buffer.from("client\ndev tun\nremote 198.51.100.1 1194\n") });
    await page.locator("#inspect-profiles").click();
    await page.waitForFunction(() => !document.querySelector("#import-review-panel")?.hidden);
    assert.match(await page.locator(".import-file").textContent(), /already in library/);
    await scan(page, "duplicate import review");
    await page.locator("#trust-profiles").check();
    await page.locator("#commit-import").click();
    await waitImportOutcome(page);
    assert.match(await page.locator("#import-outcome-text").textContent(), /already in the library/);
    await scan(page, "duplicate import outcome");
    await page.locator("#import-finish").click();

    inspectScenario = "ready";
    await page.locator("#import-open").click();
    await page.locator("#profile-files").setInputFiles({ name: "retry.ovpn", mimeType: "application/octet-stream", buffer: Buffer.from("client\ndev tun\nremote 198.51.100.2 1194\n") });
    await page.locator("#inspect-profiles").click();
    await page.waitForFunction(() => !document.querySelector("#import-review-panel")?.hidden);
    await tabTo(page, "#import-file-summary-0");
    await page.keyboard.press("Enter");
    await tabTo(page, "#import-group-0");
    await page.keyboard.type(" Work ");
    await tabTo(page, "#trust-profiles");
    await page.keyboard.press("Space");
    await tabTo(page, "#commit-import");
    await page.keyboard.press("Enter");
    assert.equal(await page.locator("#import-group-0").getAttribute("aria-invalid"), "true");
    assert.match(await page.locator("#import-group-0").getAttribute("aria-describedby"), /import-group-0-error/);
    await tabTo(page, '#import-errors a[href="#import-group-0"]');
    await page.keyboard.press("Enter");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "import-group-0");
    await page.keyboard.press("ControlOrMeta+A");
    await page.keyboard.type("Work");
    commitScenario = "known-failure";
    await tabTo(page, "#commit-import");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => !document.querySelector("#import-errors")?.hidden);
    assert.match(await page.locator("#import-errors").textContent(), /no longer valid/);
    assert.equal(await page.locator("#import-open").isDisabled(), false, "known import failure left imports locked");
    await scan(page, "recoverable import commit failure");
    commitScenario = "metadata-failure";
    await page.waitForFunction(() => !document.querySelector("#commit-import")?.disabled);
    await tabTo(page, "#commit-import");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.querySelector("#import-group-0")?.getAttribute("aria-invalid") === "true");
    assert.match(await page.locator("#import-errors").textContent(), /at most 64 characters and 256 UTF-8 bytes/);
    await tabTo(page, '#import-errors a[href="#import-group-0"]');
    await page.keyboard.press("Enter");
    assert.equal(await page.evaluate(() => document.activeElement?.id), "import-group-0");
    commitScenario = "ready";
    await page.waitForFunction(() => !document.querySelector("#commit-import")?.disabled);
    await tabTo(page, "#commit-import");
    await page.keyboard.press("Enter");
    await waitImportOutcome(page);
    await page.locator("#import-finish").click();

    profiles.push(
      profile(stableID(6000), "openvpn", "Filtered alpha", "Disappearance fixture", "A", false),
      profile(stableID(6001), "wireguard", "Filtered beta", "Disappearance fixture", "B", false),
    );
    await page.reload({ waitUntil: "networkidle" });
    await page.waitForFunction(() => document.querySelectorAll(".profile-row-button").length >= 3);
    await page.locator("#profile-search").fill("Disappearance fixture");
    const filteredIDs = await page.locator(".profile-row-button").evaluateAll(nodes => nodes.map(node => node.dataset.profileId));
    assert.ok(filteredIDs.length >= 2, "disappearance fixture did not expose two filtered rows");
    const [vanishedID, expectedReplacementID] = filteredIDs;
    await page.locator(`[data-profile-id="${vanishedID}"]`).click();
    profiles = profiles.filter(item => item.id !== vanishedID);
    await page.locator("#import-open").click();
    await page.locator("#profile-files").setInputFiles({ name: "refresh.ovpn", mimeType: "application/octet-stream", buffer: Buffer.from("client\ndev tun\nremote 198.51.100.9 1194\n") });
    await page.locator("#inspect-profiles").click();
    await page.waitForFunction(() => !document.querySelector("#import-review-panel")?.hidden);
    await page.locator("#trust-profiles").check();
    commitScenario = "refresh-failure";
    await page.locator("#commit-import").click();
    await waitImportOutcome(page);
    assert.match(await page.locator("#import-outcome-text").textContent(), /library refresh failed/i);
    assert.doesNotMatch(await page.locator("#import-outcome-text").textContent(), /retry/i);
    profileFailure = false;
    commitScenario = "ready";
    await page.locator("#import-finish").click();
    await page.locator("#library-retry").click();
    await page.waitForFunction(id => !document.querySelector(`[data-profile-id="${CSS.escape(id)}"]`), vanishedID);
    await page.waitForFunction(id => document.activeElement?.dataset?.profileId === id, expectedReplacementID);
    assert.equal(await page.evaluate(() => document.activeElement?.dataset?.profileId || ""), expectedReplacementID, "externally disappeared selection did not settle on the next filtered row");
    await scan(page, "selected profile disappearance settlement");

    profiles = [];
    preferences = { favorites: [], recents: [], startup_mode: "manual" };
    await page.reload({ waitUntil: "networkidle" });
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "0 profiles");
    await page.locator("#import-open").click();
    await page.locator("#profile-files").setInputFiles({ name: "background.ovpn", mimeType: "application/octet-stream", buffer: Buffer.from("client\ndev tun\nremote 198.51.100.3 1194\n") });
    await page.locator("#inspect-profiles").click();
    await page.waitForFunction(() => !document.querySelector("#import-review-panel")?.hidden);
    await page.locator("#trust-profiles").check();
    commitScenario = "delayed";
    commitGate = deferred();
    const settledAnnouncement = await page.locator("#import-announcer").textContent();
    await page.locator("#commit-import").click();
    assert.match(await page.locator("#import-status-text").textContent(), /Importing/);
    assert.equal(await page.locator("#import-announcer").textContent(), settledAnnouncement, "transient import progress was announced as settlement");
    await scan(page, "import commit in progress");
    await page.locator("#import-close").click();
    assert.equal(await page.locator("#import-dialog").isVisible(), false);
    assert.equal(await page.locator("#import-open").isDisabled(), true);
    assert.match(await page.locator("#import-status-text").textContent(), /continues in the background/);
    assert.equal(await page.locator("#import-status").getAttribute("role"), null);
    assert.equal(await page.locator("#import-announcer").textContent(), settledAnnouncement, "background progress was announced before settlement");
    await scan(page, "background import in progress");
    commitGate.resolve();
    commitGate = null;
    await page.waitForFunction(() => document.querySelector("#import-status-text")?.textContent.includes("imported 1"));
    assert.match(await page.locator("#import-announcer").textContent(), /imported 1/);
    assert.equal(await page.locator("#import-open").isDisabled(), false);
    await scan(page, "background import success settlement");
    commitScenario = "ready";
    await page.locator("#import-open").click();
    await page.locator("#import-finish").click();

    if (browserName === "chromium") {
      const touchContext = await browser.newContext({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true, reducedMotion: "reduce" });
      const touchPage = await touchContext.newPage();
      touchPage.setDefaultTimeout(15000);
      touchPage.setDefaultNavigationTimeout(15000);
      await touchPage.clock.setFixedTime(fixtureTime);
      await touchPage.goto(origin, { waitUntil: "networkidle" });
      await touchPage.waitForFunction(() => document.querySelector(".profile-row-button"));
      await touchPage.locator(".profile-row-button").first().tap();
      await touchPage.waitForFunction(() => document.querySelector("#main-content")?.dataset.screen === "detail");
      assert.equal(await touchPage.locator("#detail-screen").isVisible(), true);
      await scan(touchPage, "touch list-to-detail flow");
      await touchPage.locator("#settings-open").tap();
      await scan(touchPage, "touch settings flow");
      await touchPage.locator("#settings-close").tap();
      await touchPage.locator("#import-open").tap();
      await touchPage.locator("#profile-files").setInputFiles({ name: "touch.ovpn", mimeType: "application/octet-stream", buffer: Buffer.from("client\ndev tun\nremote 198.51.100.10 1194\n") });
      await touchPage.locator("#inspect-profiles").tap();
      await touchPage.waitForFunction(() => !document.querySelector("#import-review-panel")?.hidden);
      await scan(touchPage, "touch import review flow");
      await touchPage.locator("#import-close").tap();
      await touchPage.locator("#discard-import").tap();
      await touchContext.close();
    }

    profiles = [];
    await page.reload({ waitUntil: "networkidle" });
    await page.locator("#import-open").click();
    await page.locator("#profile-files").setInputFiles({ name: "lost.ovpn", mimeType: "application/octet-stream", buffer: Buffer.from("client\ndev tun\nremote 198.51.100.4 1194\n") });
    await page.locator("#inspect-profiles").click();
    await page.waitForFunction(() => !document.querySelector("#import-review-panel")?.hidden);
    await page.locator("#trust-profiles").check();
    commitScenario = "lost-none";
    await page.locator("#commit-import").click();
    await page.waitForFunction(() => !document.querySelector("#import-errors")?.hidden);
    assert.match(await page.locator("#import-errors").textContent(), /none of the proposed profiles is present/);
    assert.equal(await page.locator("#import-open").isDisabled(), false, "all-absent reconciliation did not permit retry");
    await scan(page, "unknown import outcome reconciled absent");
    await page.locator("#import-close").click();
    await page.locator("#discard-import").click();

    await page.locator("#import-open").click();
    await page.locator("#profile-files").setInputFiles([
      { name: "partial-a.ovpn", mimeType: "application/octet-stream", buffer: Buffer.from("client\ndev tun\nremote 198.51.100.5 1194\n") },
      { name: "partial-b.conf", mimeType: "application/octet-stream", buffer: Buffer.from("[Interface]\nPrivateKey = redacted-test-value\n") },
    ]);
    await page.locator("#inspect-profiles").click();
    await page.waitForFunction(() => document.querySelectorAll(".import-file").length === 2);
    await page.locator("#trust-profiles").check();
    commitScenario = "lost-partial";
    await page.locator("#commit-import").click();
    await page.waitForFunction(() => document.querySelector("#import-status-text")?.textContent.includes("only part"));
    assert.equal(await page.locator("#import-dialog").isVisible(), false);
    assert.equal(await page.evaluate(() => document.activeElement?.id), "import-status", "uncertain import did not focus its page-level settlement after closing the dialog");
    assert.equal(await page.locator("#import-open").isDisabled(), true, "partial publication uncertainty did not fail closed");
    await scan(page, "partial import reconciliation failure");
    console.log(`${browserName} UI behavior and accessibility checks passed`);
  } finally {
    if (artifactDir) fs.writeFileSync(path.join(artifactDir, "manifest.json"), `${JSON.stringify({
      candidate_commit: process.env.CANDIDATE_COMMIT || "unbound-local-run",
      browser: browserName,
      public_screenshot_candidate: fs.existsSync(path.join(artifactDir, "folio-desk.png")) ? "folio-desk.png" : null,
      states: artifactManifest,
    }, null, 2)}\n`);
    await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
