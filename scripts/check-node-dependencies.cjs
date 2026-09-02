"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");

const manifest = JSON.parse(fs.readFileSync("package.json", "utf8"));
const lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
const allowed = new Set(fs.readFileSync(".github/license-policy.txt", "utf8")
  .split(/\r?\n/)
  .map(line => line.trim())
  .filter(line => line && !line.startsWith("#")));

assert.equal(manifest.private, true, "Node package must remain private");
assert.deepEqual(manifest.dependencies || {}, {}, "runtime Node dependencies are not allowed");
assert.deepEqual(lock.packages[""].devDependencies, manifest.devDependencies, "package.json and lockfile devDependencies differ");

for (const [path, dependency] of Object.entries(lock.packages)) {
  if (path === "") continue;
  assert.equal(dependency.dev, true, `${path} is not development-only`);
  assert.ok(allowed.has(dependency.license), `${path} uses unapproved license ${dependency.license}`);
  assert.match(dependency.version || "", /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/, `${path} has an invalid version`);
  assert.match(dependency.resolved || "", /^https:\/\/registry\.npmjs\.org\//, `${path} is not registry-bound`);
  assert.match(dependency.integrity || "", /^sha512-/, `${path} is not SHA-512 integrity-bound`);
}

console.log("Node dependency lock and license policy passed");
