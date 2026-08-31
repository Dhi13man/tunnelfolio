"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { chromium } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const executablePath = process.env.CHROMIUM_PATH || "/usr/bin/chromium";
const proxyToken = "tunnelfolio-test-proxy-token-value";

if (process.getuid?.() !== 0) {
  throw new Error("browser/server boundary test must run as root to exercise the production ownership contract");
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(error => error ? reject(error) : resolve(port));
    });
  });
}

function privateDirectory(directory) {
  fs.mkdirSync(directory, { mode: 0o700 });
}

function privateFile(file, contents) {
  fs.writeFileSync(file, contents, { mode: 0o600 });
}

(async () => {
  const temporaryBase = process.env.TUNNELFOLIO_TEST_TMPDIR || "/run";
  const temporary = fs.mkdtempSync(path.join(temporaryBase, "tunnelfolio-browser-"));
  const profiles = path.join(temporary, "profiles");
  const state = path.join(temporary, "state");
  const token = path.join(temporary, "proxy-token");
  for (const directory of [
    profiles,
    path.join(profiles, "openvpn"),
    path.join(profiles, "openvpn", "generic"),
    path.join(profiles, "wireguard"),
    path.join(profiles, "wireguard", "generic"),
    state,
  ]) privateDirectory(directory);
  privateFile(path.join(profiles, "openvpn", "generic", "office.ovpn"), "client\n");
  privateFile(path.join(profiles, "wireguard", "generic", "home.conf"), "[Interface]\n");
  privateFile(token, `${proxyToken}\n`);

  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  const child = spawn(path.join(root, "tunnelfolio"), [
    "--listen", `127.0.0.1:${port}`,
    "--profiles-dir", profiles,
    "--state-dir", state,
    "--trusted-proxy",
    "--proxy-token-file", token,
    "--read-only",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let diagnostics = "";
  child.stderr.on("data", chunk => { diagnostics = (diagnostics + chunk).slice(-8192); });
  let browser;
  try {
    browser = await chromium.launch({ executablePath, headless: true, args: ["--no-sandbox"] });
    const context = await browser.newContext({ extraHTTPHeaders: {
      "X-Tunnelfolio-Proxy-Token": proxyToken,
      "X-Forwarded-Proto": "https",
      "X-Forwarded-Host": "vpn.example.test",
      "X-Remote-User": "browser-ci",
    } });
    const page = await context.newPage();
    let ready = false;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      try {
        const health = await fetch(`${origin}/healthz`, { headers: {
          "X-Tunnelfolio-Proxy-Token": proxyToken,
          "X-Forwarded-Proto": "https",
          "X-Forwarded-Host": "vpn.example.test",
          "X-Remote-User": "browser-ci",
        } });
        if (!health.ok) throw new Error(`health status ${health.status}`);
        ready = true;
        break;
      } catch (error) {
        if (attempt === 19) throw error;
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    assert.equal(ready, true);
    const response = await page.goto(origin, { waitUntil: "commit", timeout: 10000 });
    assert.equal(response.status(), 200);
    assert.match(response.headers()["content-security-policy"], /script-src 'self'/);
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "2 profiles");
    assert.equal(await page.locator(".profile-card").count(), 2);
    assert.equal(await page.locator('[data-focus-key^="connect:"]').count(), 2);

    for (const asset of ["app.css", "app.js"]) {
      const assetResponse = await page.request.get(`${origin}/assets/${asset}`);
      assert.equal(assetResponse.status(), 200);
      assert.match(assetResponse.headers()["content-type"], asset.endsWith("css") ? /text\/css/ : /javascript/);
    }
    const unauthorized = await fetch(`${origin}/healthz`);
    assert.equal(unauthorized.status, 401);
    const mutation = await page.evaluate(async () => {
      const result = await fetch("/api/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profile: "wireguard/generic/home" }),
      });
      return { status: result.status, body: await result.json() };
    });
    assert.equal(mutation.status, 403);
    assert.equal(mutation.body.code, "read_only");
    console.log("browser/server boundary checks passed");
  } catch (error) {
    error.message += `\nserver diagnostics:\n${diagnostics}`;
    throw error;
  } finally {
    if (browser) await browser.close();
    if (child.exitCode === null && child.signalCode === null) {
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          child.kill("SIGKILL");
          reject(new Error("browser smoke-test server did not stop within 2 seconds"));
        }, 2000);
        child.once("exit", () => {
          clearTimeout(timeout);
          resolve();
        });
        child.kill("SIGTERM");
      });
    }
    fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
