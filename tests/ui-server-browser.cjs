"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { chromium } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const executablePath = process.env.CHROMIUM_PATH || "/usr/bin/chromium";
const proxyToken = "tunnelfolio-test-proxy-token-value";

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
  const temporaryBase = process.env.TUNNELFOLIO_TEST_TMPDIR || (process.geteuid() === 0 ? os.homedir() : os.tmpdir());
  const temporary = fs.mkdtempSync(path.join(temporaryBase, "tunnelfolio-browser-"));
  const state = path.join(temporary, "state");
  const token = path.join(temporary, "proxy-token");
  privateDirectory(state);
  privateFile(token, `${proxyToken}\n`);

  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  const child = spawn(path.join(root, "tunnelfolio"), [
    "--listen", `127.0.0.1:${port}`,
    "--state-dir", state,
    "--trusted-proxy",
    "--proxy-token-file", token,
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let diagnostics = "";
  child.stderr.on("data", chunk => { diagnostics = (diagnostics + chunk).slice(-8192); });
  let browser;
  try {
    browser = await chromium.launch({ executablePath, headless: true, args: ["--no-sandbox"], timeout: 30000 });
    const context = await browser.newContext({ extraHTTPHeaders: {
      "X-Tunnelfolio-Proxy-Token": proxyToken,
      "X-Forwarded-Proto": "https",
      "X-Forwarded-Host": "vpn.example.test",
      "X-Remote-User": "browser-ci",
    } });
    await context.route("**/*", async route => {
      const headers = await route.request().allHeaders();
      const response = await route.fetch({ headers: {
        ...headers,
        origin: "https://vpn.example.test",
      } });
      await route.fulfill({ response });
    });
    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    page.setDefaultNavigationTimeout(15000);
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
        // test-audit: allow=FIXED_SLEEP reason="bounded readiness polling still requires a successful authenticated health response" owner="Dhi13man" expires=2027-09-02
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    assert.equal(ready, true);
    const response = await page.goto(origin, { waitUntil: "commit", timeout: 10000 });
    assert.equal(response.status(), 200);
    assert.match(response.headers()["content-security-policy"], /script-src 'self'/);
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "0 profiles");
    assert.equal(await page.locator(".profile-row-button").count(), 0);
    assert.equal(await page.locator("#library-empty").isVisible(), true);
    assert.equal(await page.locator("#import-open").isDisabled(), false);

    for (const asset of ["app.css", "api.js", "app.js", "connection.js", "detail.js", "import.js", "library.js", "state.js"]) {
      const assetResponse = await page.request.get(`${origin}/assets/${asset}`);
      assert.equal(assetResponse.status(), 200);
      assert.match(assetResponse.headers()["content-type"], asset.endsWith("css") ? /text\/css/ : /javascript/);
    }
    const unauthorized = await fetch(`${origin}/healthz`);
    assert.equal(unauthorized.status, 401);
    await page.locator("#empty-import").click();
    await page.locator("#profile-files").setInputFiles({
      name: "office.ovpn",
      mimeType: "application/octet-stream",
      buffer: Buffer.from("client\ndev tun\nproto udp\nremote vpn.example.test 1194\nnobind\n<ca>\nsynthetic-ca\n</ca>\n"),
    });
    await page.locator("#inspect-profiles").click();
    await page.waitForFunction(() =>
      !document.querySelector("#import-review-panel")?.hidden ||
      !document.querySelector("#import-errors")?.hidden
    );
    assert.equal(
      await page.locator("#import-errors").isHidden(),
      true,
      `profile inspection failed: ${await page.locator("#import-error-list").textContent()}`,
    );
    await page.locator("#import-file-summary-0").click();
    await page.locator("#import-name-0").fill("Office gateway");
    await page.locator("#import-group-0").fill("Work");
    await page.locator("#import-location-0").fill("London");
    await page.locator("#trust-profiles").check();
    await page.locator("#commit-import").click();
    await page.waitForFunction(() => !document.querySelector("#import-outcome-panel")?.hidden);
    assert.match(await page.locator("#import-outcome-text").textContent(), /imported 1/);
    await page.locator("#import-finish").click();
    await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "1 profile");
    assert.match(await page.locator(".profile-row-button").textContent(), /Office gateway/);

    await page.locator(".profile-row-button").click();
    await page.locator('[data-detail-action="edit"]').click();
    await page.locator("#edit-name").fill("Office primary");
    await page.locator("#edit-location").fill("Manchester");
    await page.locator('#edit-form button[type="submit"]').click();
    await page.waitForFunction(() => document.querySelector(".profile-row-button")?.textContent.includes("Office primary"));
    assert.match(await page.locator("#detail-content").textContent(), /Manchester/);

    await page.locator('[data-detail-action="remove"]').click();
    const removalResponsePromise = page.waitForResponse(response =>
      response.request().method() === "DELETE" &&
      new URL(response.url()).pathname.startsWith("/api/profiles/")
    );
    await page.locator("#confirm-action").click();
    const removalResponse = await removalResponsePromise;
    assert.equal(
      removalResponse.status(),
      200,
      `profile removal failed: ${await removalResponse.text()}`,
    );
    await page.waitForFunction(() =>
      document.querySelector("#result-count")?.textContent === "0 profiles" ||
      !document.querySelector("#page-error")?.hidden
    );
    assert.equal(
      await page.locator("#page-error").isHidden(),
      true,
      `profile removal failed: ${await page.locator("#page-error-text").textContent()}`,
    );
    assert.equal(await page.locator(".profile-row-button").count(), 0);
    console.log("mutable browser/server boundary checks passed");
  } catch (error) {
    error.message += `\nserver diagnostics:\n${diagnostics}`;
    throw error;
  } finally {
    if (browser) await browser.close();
    if (child.exitCode === null && child.signalCode === null) {
      await new Promise((resolve, reject) => {
        // test-audit: allow=FIXED_SLEEP reason="shutdown timeout is a failure bound and success still requires the child exit event" owner="Dhi13man" expires=2027-09-02
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
