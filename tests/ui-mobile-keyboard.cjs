"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { chromium } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const webRoot = path.join(root, "internal", "web");
const artifactDir = path.resolve(process.env.UI_ARTIFACT_DIR || path.join(root, "test-artifacts", "ui", "android"));
const candidateCommit = process.env.CANDIDATE_COMMIT || "";
const fixtureTime = "2026-09-02T05:20:00.000Z";
const profile = {
  id: "tf_bbbbbbbbbbbbbbbbbbbbbbbbbb",
  protocol: "wireguard",
  display_name: "Japan",
  group: "Mullvad",
  location: "JP",
  identifier: "tfbbbbbbbbbbbb",
  original_filename: "jp.conf",
  imported_at: fixtureTime,
  favorite: true,
  recent: true,
  available: true,
  capabilities: { connect: true, favorite: true, edit_metadata: true, remove: true },
};

fs.mkdirSync(artifactDir, { recursive: true });
assert.match(candidateCommit, /^[0-9a-f]{40}$/, "CANDIDATE_COMMIT must bind mobile evidence to an exact commit");
const gitHead = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
assert.equal(gitHead, candidateCommit, "mobile evidence checkout does not match CANDIDATE_COMMIT");

function adb(...args) {
  return execFileSync("adb", args, { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 }).trim();
}

function captureDeviceScreenshot(file) {
  fs.writeFileSync(file, execFileSync("adb", ["exec-out", "screencap", "-p"], { maxBuffer: 16 * 1024 * 1024 }));
}

function dumpWindowHierarchy() {
  const devicePath = "/sdcard/tunnelfolio-window.xml";
  adb("shell", "uiautomator", "dump", devicePath);
  return adb("shell", "cat", devicePath);
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function json(response, statusCode, body) {
  response.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  response.end(JSON.stringify(body));
}

function createServer() {
  return http.createServer((request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    if (url.pathname === "/healthz") return json(response, 200, {
      live: true,
      readiness: "ready",
      read_only: false,
      protocols: { openvpn: { available: true }, wireguard: { available: true } },
    });
    if (url.pathname === "/api/preferences") return json(response, 200, {
      favorites: [profile.id],
      recents: [profile.id],
      startup_mode: "restore",
    });
    if (url.pathname === "/api/profiles") return json(response, 200, [profile]);
    if (url.pathname === "/api/status") return json(response, 200, {
      connected: true,
      lifecycle: "active",
      observation_available: true,
      observed_at: fixtureTime,
      profile,
      protocol_status: {
        state: "interface_active",
        received_bytes: 15360,
        sent_bytes: 4096,
        peers: [{ endpoint: "198.51.100.8:51820", latest_handshake: 0, received_bytes: 15360, sent_bytes: 4096 }],
      },
      protocols: { openvpn: { available: true }, wireguard: { available: true } },
    });

    const relative = url.pathname === "/"
      ? "index.html"
      : url.pathname.startsWith("/assets/") ? path.join("assets", path.basename(url.pathname)) : "";
    const file = relative ? path.join(webRoot, relative) : "";
    if (!file || !fs.existsSync(file)) {
      response.writeHead(404);
      return response.end();
    }
    const contentType = file.endsWith(".css") ? "text/css; charset=utf-8" : file.endsWith(".js") ? "text/javascript; charset=utf-8" : "text/html; charset=utf-8";
    response.writeHead(200, {
      "Content-Type": contentType,
      "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    });
    response.end(fs.readFileSync(file));
  });
}

const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function waitForCDP() {
  adb("forward", "tcp:9222", "localabstract:chrome_devtools_remote");
  const deadline = Date.now() + 120000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch("http://127.0.0.1:9222/json/version");
      if (response.ok) return;
    } catch (error) {
      lastError = error;
    }
    await delay(1000);
  }
  throw new Error(`Android Chrome did not expose CDP: ${lastError?.message || "timeout"}`);
}

function imeEvidence() {
  const dump = adb("shell", "dumpsys", "input_method");
  const lines = dump.split("\n").filter(line => /mInputShown|mIsInputViewShown|mImeWindowVis|showRequested|requestedVisibleTypes|curMethodId/i.test(line));
  const visible = lines.some(line => /mInputShown=true|mIsInputViewShown=true|mImeWindowVis=0x[1-9a-f]|showRequested=true|requestedVisibleTypes=.*ime/i.test(line));
  return { visible, lines };
}

async function waitForOpenIME(page, baselineHeight) {
  const deadline = Date.now() + 20000;
  let last = { visible: false, lines: [] };
  while (Date.now() < deadline) {
    last = imeEvidence();
    const viewportShrank = await page.evaluate(baseline => window.visualViewport && window.visualViewport.height < baseline - 100, baselineHeight);
    if (last.visible && viewportShrank) return last;
    await delay(500);
  }
  throw new Error(`Android software keyboard did not become visibly open: ${last.lines.join(" | ")}`);
}

async function tapFocusedInputWithADB(page, selector) {
  const focusedNode = dumpWindowHierarchy()
    .match(/<node\b[^>]*>/g)
    ?.find(node => /class="android\.widget\.EditText"/.test(node) && /focused="true"/.test(node));
  const bounds = focusedNode?.match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
  const point = bounds
    ? {
      x: Math.round((Number(bounds[1]) + Number(bounds[3])) / 2),
      y: Math.round((Number(bounds[2]) + Number(bounds[4])) / 2),
      source: "UI hierarchy",
    }
    : await page.locator(selector).evaluate(node => {
      const rect = node.getBoundingClientRect();
      const contentTop = Math.max(0, (screen.availHeight - innerHeight) * devicePixelRatio);
      return {
        x: Math.round((rect.left + rect.width / 2) * devicePixelRatio),
        y: Math.round(contentTop + (rect.top + rect.height / 2) * devicePixelRatio),
        source: "browser geometry",
        metrics: {
          screen_height: screen.height,
          available_height: screen.availHeight,
          inner_height: innerHeight,
          device_pixel_ratio: devicePixelRatio,
          content_top: contentTop,
          input_rect: { top: rect.top, left: rect.left, width: rect.width, height: rect.height },
        },
      };
    });
  console.log(`Tapping focused Android input at ${point.x},${point.y} from ${point.source}${point.metrics ? `: ${JSON.stringify(point.metrics)}` : ""}`);
  adb("shell", "input", "tap", String(point.x), String(point.y));
}

async function tapFocusedInputWithCDP(page, selector) {
  const point = await page.locator(selector).evaluate(node => {
    const rect = node.getBoundingClientRect();
    return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
  });
  const session = await page.context().newCDPSession(page);
  try {
    await session.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [point] });
    await session.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  } finally {
    await session.detach();
  }
}

(async () => {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "0.0.0.0", resolve);
  });
  const port = server.address().port;
  adb("reverse", `tcp:${port}`, `tcp:${port}`);
  const origin = `http://127.0.0.1:${port}`;
  let browser;
  try {
    adb("shell", "settings", "put", "secure", "show_ime_with_hard_keyboard", "1");
    assert.equal(adb("shell", "settings", "get", "secure", "show_ime_with_hard_keyboard"), "1", "Android did not retain the software-keyboard setting");
    adb("shell", "am", "force-stop", "com.android.chrome");
    adb(
      "shell", "am", "start", "-W",
      "-a", "android.intent.action.VIEW",
      "-d", `${origin}/healthz`,
      "-p", "com.android.chrome",
      "--ez", "com.android.chrome.firstrun.SKIP_FIRST_RUN_EXPERIENCE", "true",
    );
    await waitForCDP();
    browser = await chromium.connectOverCDP("http://127.0.0.1:9222");
    const context = browser.contexts()[0];
    assert.ok(context, "Android Chrome CDP connection did not expose a browser context");
    const page = context.pages()[0];
    assert.ok(page, "Android Chrome CDP connection did not expose a page");
    page.setDefaultTimeout(20000);
    const response = await page.goto(origin, { waitUntil: "commit", timeout: 60000 });
    assert.equal(response?.status(), 200, "Android Chrome did not receive the app document");
    await page.waitForFunction(
      () => document.querySelector("#result-count")?.textContent === "1 profile",
      undefined,
      { timeout: 60000 },
    );
    await page.locator(".profile-row-button").click();
    await page.waitForFunction(() => document.querySelector("#main-content")?.dataset.screen === "detail");
    await page.locator('[data-detail-action="edit"]').click();
    await page.waitForFunction(() => document.querySelector("#edit-dialog")?.open);

    const input = page.locator("#edit-location");
    await input.scrollIntoViewIfNeeded();
    const baseline = await page.evaluate(() => ({
      innerHeight,
      visualHeight: window.visualViewport?.height || innerHeight,
      active: document.activeElement?.id || "",
    }));
    await tapFocusedInputWithCDP(page, "#edit-location");
    await delay(500);
    if (!(await page.evaluate(() => document.activeElement?.id === "edit-location"))) await tapFocusedInputWithADB(page, "#edit-location");
    let ime = imeEvidence();
    if (!ime.visible) await tapFocusedInputWithADB(page, "#edit-location");
    ime = await waitForOpenIME(page, baseline.visualHeight);
    await page.waitForFunction(() => document.activeElement?.id === "edit-location");
    await delay(500);

    const observed = await page.locator("#edit-location").evaluate(node => {
      const rect = node.getBoundingClientRect();
      const viewport = window.visualViewport;
      return {
        active_element: document.activeElement?.id || "",
        rect: { top: rect.top, right: rect.right, bottom: rect.bottom, left: rect.left, width: rect.width, height: rect.height },
        visual_viewport: viewport ? { offset_top: viewport.offsetTop, offset_left: viewport.offsetLeft, width: viewport.width, height: viewport.height, scale: viewport.scale } : null,
        inner_height: innerHeight,
        device_pixel_ratio: devicePixelRatio,
        user_agent: navigator.userAgent,
      };
    });
    assert.equal(observed.active_element, "edit-location", "software keyboard session lost focus from Location");
    assert.ok(observed.visual_viewport, "Android Chrome did not expose VisualViewport geometry");
    const visibleTop = observed.visual_viewport.offset_top;
    const visibleBottom = visibleTop + observed.visual_viewport.height;
    assert.ok(observed.visual_viewport.height < baseline.visualHeight - 100, "visual viewport did not shrink for the open software keyboard");
    assert.ok(observed.rect.top >= visibleTop - 1, "focused Location field is obscured above the visual viewport");
    assert.ok(observed.rect.bottom <= visibleBottom + 1, "focused Location field is obscured by the software keyboard");

    const deviceScreenshot = path.join(artifactDir, "android-software-keyboard.png");
    const webScreenshot = path.join(artifactDir, "android-web-viewport.png");
    const inputEvidence = path.join(artifactDir, "input-method-evidence.txt");
    captureDeviceScreenshot(deviceScreenshot);
    await page.screenshot({ path: webScreenshot });
    fs.writeFileSync(inputEvidence, `${ime.lines.join("\n")}\n`);
    const receipt = {
      candidate_commit: candidateCommit,
      git_head: gitHead,
      evidence: "Android Emulator Chrome session with Android software keyboard visibly open",
      avd_name: process.env.ANDROID_AVD_NAME || "",
      system_image: process.env.ANDROID_SYSTEM_IMAGE || "",
      android_api_level: adb("shell", "getprop", "ro.build.version.sdk"),
      android_release: adb("shell", "getprop", "ro.build.version.release"),
      android_build_fingerprint: adb("shell", "getprop", "ro.build.fingerprint"),
      device_model: adb("shell", "getprop", "ro.product.model"),
      chrome_package: adb("shell", "dumpsys", "package", "com.android.chrome").split("\n").find(line => line.trim().startsWith("versionName="))?.trim() || "unknown",
      input_method_visible: ime.visible,
      baseline,
      observed,
      assertions: {
        exact_candidate_checkout: true,
        software_keyboard_visible_in_android_state: true,
        visual_viewport_shrank: true,
        focused_control_inside_visual_viewport: true,
      },
      artifacts: {
        "android-software-keyboard.png": `sha256:${sha256(deviceScreenshot)}`,
        "android-web-viewport.png": `sha256:${sha256(webScreenshot)}`,
        "input-method-evidence.txt": `sha256:${sha256(inputEvidence)}`,
      },
    };
    fs.writeFileSync(path.join(artifactDir, "manifest.json"), `${JSON.stringify(receipt, null, 2)}\n`);
    console.log("Android Emulator software-keyboard focus-obscuration check passed");
  } catch (error) {
    console.error(error);
    try {
      captureDeviceScreenshot(path.join(artifactDir, "android-failure.png"));
      fs.writeFileSync(path.join(artifactDir, "input-method-dump.txt"), `${adb("shell", "dumpsys", "input_method")}\n`);
      fs.writeFileSync(path.join(artifactDir, "window-hierarchy.xml"), `${dumpWindowHierarchy()}\n`);
    } catch (screenshotError) {
      console.error(`Could not capture complete Android failure evidence: ${screenshotError.message}`);
    }
    throw error;
  } finally {
    if (browser) await browser.close();
    adb("shell", "am", "force-stop", "com.android.chrome");
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(() => {
  process.exitCode = 1;
});
