import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
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
