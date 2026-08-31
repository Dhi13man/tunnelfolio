"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const executablePath = process.env.CHROMIUM_PATH || "/usr/bin/chromium";

function contrast(left, right) {
  const channel = value => {
    value /= 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  };
  const luminance = color => {
    const values = color.match(/\d+/g).slice(0, 3).map(Number).map(channel);
    return 0.2126 * values[0] + 0.7152 * values[1] + 0.0722 * values[2];
  };
  const [bright, dark] = [luminance(left), luminance(right)].sort((a, b) => b - a);
  return (bright + 0.05) / (dark + 0.05);
}

(async () => {
  const browser = await chromium.launch({ executablePath, headless: true, args: ["--no-sandbox"] });
  try {
    const context = await browser.newContext({ reducedMotion: "reduce" });
    const page = await context.newPage();
  let status = { connected: false, lifecycle: "disconnected", capabilities: {} };
  const hostileName = `<img src=x onerror="globalThis.injected=true"> ${"界".repeat(180)}`;
  const profiles = [
    { id: "openvpn/generic/office", backend: "openvpn", provider: "generic", name: hostileName, available: true, capabilities: {} },
    { id: "wireguard/mullvad/mullvad_de", backend: "wireguard", provider: "mullvad", name: "Germany", country_name: "Germany", flag: "🇩🇪", available: true, capabilities: { transfer_stats: true } },
  ];

  await page.route("**/api/**", async route => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (pathname === "/api/profiles") return route.fulfill({ json: profiles });
    if (pathname === "/api/preferences") {
      if (request.method() === "PUT") return route.fulfill({ json: JSON.parse(request.postData()) });
      return route.fulfill({ json: { favorites: [], recents: [] } });
    }
    if (pathname === "/api/status") return route.fulfill({ json: status });
    if (pathname === "/api/connect") {
      await new Promise(resolve => setTimeout(resolve, 400));
      const profile = profiles.find(candidate => candidate.id === JSON.parse(request.postData()).profile);
      status = { connected: true, lifecycle: "connected", profile, capabilities: profile.capabilities };
      return route.fulfill({ json: { message: "Connected", profile: profile.id } });
    }
    if (pathname === "/api/disconnect") {
			await new Promise(resolve => setTimeout(resolve, 400));
      status = { connected: false, lifecycle: "disconnected", capabilities: {} };
      return route.fulfill({ json: { message: "Disconnected" } });
    }
    return route.fulfill({ status: 404, json: {} });
  });

  let html = fs.readFileSync(path.join(root, "templates/index.html"), "utf8");
  html = html.replace(/<link rel="stylesheet"[^>]+>/, "").replace(/<script src="[^"]+" defer><\/script>/, "");
  html = html.replace("<head>", '<head><base href="http://tunnelfolio.test/">');
  await page.setContent(html);
  await page.addStyleTag({ path: path.join(root, "templates/app.css") });
  await page.addScriptTag({ path: path.join(root, "templates/app.js") });
  await page.waitForFunction(() => document.querySelector("#result-count")?.textContent === "2 profiles");

  assert.equal(await page.locator("img").count(), 0, "profile metadata created executable markup");
  assert.equal(await page.evaluate(() => globalThis.injected), undefined, "profile metadata executed script");
  assert.match(await page.locator(".profile-name").first().textContent(), /^<img src=x/, "hostile text was not rendered literally");

  const connect = page.locator('[data-focus-key="connect:wireguard/mullvad/mullvad_de"]');
  assert.equal(await connect.getAttribute("aria-label"), "Connect to Germany");
  await connect.focus();
  await page.evaluate(() => refreshStatus());
  assert.equal(await page.evaluate(() => document.activeElement?.dataset?.focusKey), "connect:wireguard/mullvad/mullvad_de", "polling destroyed keyboard focus");

  await connect.click();
  await page.waitForFunction(() => document.querySelector("#status-announcer")?.textContent.includes("Connecting to Germany"));
  assert.equal(await page.evaluate(() => document.activeElement?.id), "connection-title", "connect initiation lost focus");
  await page.waitForFunction(() => document.querySelector("#connection-title")?.textContent === "Germany");
	assert.equal(await page.evaluate(() => document.activeElement?.id), "connection-title", "connect completion refresh lost focus");
	assert.equal(await page.locator("#status-announcer").textContent(), "Connected to Germany");

  const disconnect = page.locator("#connection-actions button");
  await disconnect.click();
	await page.waitForFunction(() => document.querySelector("#status-announcer")?.textContent === "Disconnecting VPN");
  assert.equal(await page.evaluate(() => document.activeElement?.id), "connection-title", "disconnect initiation lost focus");
  await page.waitForFunction(() => document.querySelector("#connection-title")?.textContent === "Disconnected");
	assert.equal(await page.evaluate(() => document.activeElement?.id), "connection-title", "disconnect completion refresh lost focus");
	assert.equal(await page.locator("#status-announcer").textContent(), "VPN disconnected");

  await page.locator("#settings-open").click();
  assert.equal(await page.evaluate(() => document.activeElement?.id), "settings-title");
  await page.keyboard.press("Escape");
  assert.equal(await page.evaluate(() => document.activeElement?.id), "settings-open");

  await page.evaluate(() => showError("Persistent test error"));
  await page.locator("#error-dismiss").focus();
  await page.locator("#error-dismiss").click();
  assert.equal(await page.evaluate(() => document.activeElement?.id), "connection-title", "dismissing an error lost focus");

  const colors = await page.locator("#profile-search").evaluate(element => {
    const style = getComputedStyle(element);
    return { border: style.borderTopColor, background: style.backgroundColor, animation: getComputedStyle(document.querySelector(".connection-orb")).animationDuration };
  });
  assert.ok(contrast(colors.border, colors.background) >= 3, `control boundary contrast was ${contrast(colors.border, colors.background).toFixed(2)}:1`);
  await page.evaluate(() => { document.querySelector("#connection").dataset.lifecycle = "connecting"; });
  assert.equal(await page.locator(".connection-orb").evaluate(element => getComputedStyle(element).animationDuration), "1e-06s", "reduced-motion override did not apply");

    console.log("browser UI checks passed");
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
