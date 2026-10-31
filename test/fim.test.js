import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { sha256Hex, normalisePath, createManifest, validateManifest, compareManifests, severity, hashDiff, formatBytes } from "../src/fim.js";
import { DEMO_FILES, ATTACK } from "../src/demo-site.js";

const manifestFrom = async (files) =>
  createManifest(await Promise.all(Object.entries(files).map(async ([p, c]) => ({ path: p, size: new TextEncoder().encode(c).length, sha256: await sha256Hex(c) }))), { created: "2026-10-31T00:00:00Z" });

test("sha256Hex matches the standard test vectors", async () => {
  assert.equal(await sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(await sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("a one-character change flips about half of the hash (avalanche effect)", async () => {
  const a = await sha256Hex("define('DB_USER', 'site');"), b = await sha256Hex("define('DB_USER', 'sitf');");
  const diff = hashDiff(a, b).length;
  assert.ok(diff > 40, `expected most hex characters to differ, got ${diff}/64`);
});

test("normalisePath handles Windows paths, ./ and folder roots", () => {
  assert.equal(normalisePath("site\\css\\site.css"), "site/css/site.css");
  assert.equal(normalisePath("./index.html"), "index.html");
  assert.equal(normalisePath("site/css/site.css", { stripRoot: true }), "css/site.css");
  assert.equal(normalisePath("index.html", { stripRoot: true }), "index.html");
});

test("validateManifest accepts a good baseline and explains bad ones", async () => {
  validateManifest(await manifestFrom(DEMO_FILES));
  assert.throws(() => validateManifest(null), /JSON object/);
  assert.throws(() => validateManifest({ tool: "other" }), /wasn't created/);
  assert.throws(() => validateManifest({ tool: "file-integrity", version: 1, algorithm: "sha256", files: { a: { sha256: "xyz" } } }), /invalid SHA-256/);
});

test("an untouched site compares clean", async () => {
  const m = await manifestFrom(DEMO_FILES);
  const r = compareManifests(m, m);
  assert.equal(r.clean, true);
  assert.equal(r.unchanged.length, Object.keys(DEMO_FILES).length);
});

test("the simulated attack is fully detected with sensible severities", async () => {
  const r = compareManifests(await manifestFrom(DEMO_FILES), await manifestFrom(ATTACK.apply(DEMO_FILES)));
  assert.equal(r.clean, false);
  assert.deepEqual(r.modified.map((x) => [x.path, x.severity]), [[".htaccess", "high"], ["config.php", "high"]]);
  assert.deepEqual(r.added.map((x) => [x.path, x.severity]), [["uploads/avatar.php", "critical"]]);
  assert.deepEqual(r.removed.map((x) => [x.path, x.severity]), [["robots.txt", "medium"]]);
});

test("severity rules", () => {
  assert.equal(severity("uploads/shell.php", "added"), "critical");
  assert.equal(severity("wp-config.php", "modified"), "high");
  assert.equal(severity("lib/new-tool.sh", "added"), "high");
  assert.equal(severity("css/site.css", "modified"), "low");
  assert.equal(severity("index.html", "unchanged"), "none");
});

test("hashes match the Python CLI's baseline for the same files (shared format)", async () => {
  const dir = path.join(import.meta.dirname, "fixtures", "sample-site");
  const py = validateManifest(JSON.parse(fs.readFileSync(path.join(import.meta.dirname, "fixtures", "sample-site.baseline.json"), "utf8")));
  for (const [rel, info] of Object.entries(py.files)) {
    const bytes = fs.readFileSync(path.join(dir, rel));
    assert.equal(await sha256Hex(new Uint8Array(bytes)), info.sha256, rel);
    assert.equal(bytes.length, info.size, rel);
  }
  assert.equal(Object.keys(py.files).length, Object.keys(DEMO_FILES).length);
});

test("formatBytes", () => {
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(2048), "2.0 KB");
});
