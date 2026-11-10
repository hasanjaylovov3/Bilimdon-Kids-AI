import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const html = fs.readFileSync(path.join(root, "public/index.html"), "utf8");
const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
if (!scripts.length) {
  console.error("No inline scripts found in public/index.html");
  process.exit(1);
}

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "bilimdon-client-check-"));
let failed = false;
try {
  for (let index = 0; index < scripts.length; index++) {
    const [, attributes, source] = scripts[index];
    if (/\bsrc\s*=/.test(attributes) || !source.trim()) continue;
    const type = attributes.match(/\btype\s*=\s*["']([^"']+)["']/i)?.[1]?.toLowerCase() || "text/javascript";
    if (!["text/javascript", "application/javascript", "module", "text/babel", "application/babel"].includes(type)) continue;
    const isJsx = type.includes("babel") || /<\/?[A-Z][A-Za-z0-9.]*(?:\s|\/?>)/.test(source);
    const tempFile = path.join(tempDir, "inline-" + index + "." + (isJsx ? "jsx" : type === "module" ? "mjs" : "js"));
    fs.writeFileSync(tempFile, source, "utf8");
    const result = isJsx
      ? spawnSync("npx", ["--yes", "esbuild@0.25.0", tempFile, "--loader=jsx", "--outfile=" + tempFile + ".js", "--log-level=warning"], { cwd: root, stdio: "inherit" })
      : spawnSync(process.execPath, ["--check", tempFile], { cwd: root, stdio: "inherit" });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      console.error("Inline script #" + (index + 1) + " failed syntax validation.");
      failed = true;
    } else {
      console.log("Inline script #" + (index + 1) + ": syntax OK (" + (isJsx ? "JSX" : type) + ")");
    }
  }
} finally {
  fs.rmSync(tempDir, { recursive: true, force: true });
}
if (failed) process.exit(1);
