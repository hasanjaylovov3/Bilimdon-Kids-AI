const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const htmlPath = path.join(__dirname, "..", "public", "index.html");
const html = fs.readFileSync(htmlPath, "utf8");
const match = html.match(/<script>([\s\S]*?)<\/script>/i);
if (!match) {
  console.error("Inline application script was not found in public/index.html");
  process.exit(1);
}

const tempPath = path.join(os.tmpdir(), "bilimdon-kids-client-check.js");
try {
  fs.writeFileSync(tempPath, match[1], "utf8");
  const result = spawnSync(process.execPath, ["--check", tempPath], { stdio: "inherit" });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} finally {
  fs.rmSync(tempPath, { force: true });
}
