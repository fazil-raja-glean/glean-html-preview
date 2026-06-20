import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const targets = {
  local: {
    database: "PREVIEW_DB",
    flags: ["--local"],
  },
  dev: {
    database: "html-sharing-metadata-dev",
    flags: ["--remote"],
  },
  prod: {
    database: "html-sharing-metadata-prod",
    flags: ["--remote"],
  },
};

const targetName = process.argv[2];
const target = targets[targetName];

if (!target) {
  console.error("Usage: node scripts/apply-d1-schema.mjs <local|dev|prod>");
  process.exit(1);
}

const schema = readFileSync(new URL("../schema.sql", import.meta.url), "utf8");
const localConfig = new URL("../wrangler.local.toml", import.meta.url);
if (!existsSync(localConfig)) {
  console.error("Missing wrangler.local.toml. Run `npm run config:init:local`, fill in real deployment values, then retry.");
  process.exit(1);
}

const args = [
  "wrangler",
  "d1",
  "execute",
  target.database,
  "--config",
  "wrangler.local.toml",
  ...target.flags,
  "--command",
  schema,
];

const result = spawnSync("npx", args, {
  stdio: "inherit",
  shell: false,
});

process.exit(result.status ?? 1);
