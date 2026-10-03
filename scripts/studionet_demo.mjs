// Live Redactor screening on GenLayer Studionet.
//
// The publisher commits a URL and a hash; the document itself never touches the chain.
// A keeper runs the scan, validators fetch the document themselves, check it against the
// commitment, and agree on locators (category, start, length) plus a redaction hash.
//
//   node scripts/studionet_demo.mjs <contract> [--base <raw url prefix>]
//
// The demo documents are synthetic fixtures in demo/, served over https so validators can
// fetch them. A real publisher would host the document somewhere private instead.

import { execSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL, fileURLToPath } from "node:url";
import path from "node:path";

const jsRoot =
  process.env.GENLAYER_JS ||
  path.join(execSync("npm root -g").toString().trim(), "genlayer", "node_modules", "genlayer-js");
const gl = await import(pathToFileURL(path.join(jsRoot, "dist", "index.js")).href);
const { studionet } = await import(pathToFileURL(path.join(jsRoot, "dist", "chains", "index.js")).href);

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONTRACT = process.argv[2];
if (!CONTRACT) throw new Error("usage: node scripts/studionet_demo.mjs <contract> [--base <url>]");
const baseIdx = process.argv.indexOf("--base");
const BASE = baseIdx > 0 ? process.argv[baseIdx + 1] : "https://raw.githubusercontent.com/Baster221/redactor/master/demo";
const RPC = "https://studio.genlayer.com/api";
const EXPLORER = "https://explorer-studio.genlayer.com";
const FEE = 10n ** 17n;            // 0.1 GEN, must match the deployed scan fee
const WINDOW = 900;

const plain = (v) => JSON.parse(JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x instanceof Map ? Object.fromEntries(x) : x)));
const show = (v) => JSON.stringify(plain(v), null, 2);
const field = (o, k) => (o instanceof Map ? o.get(k) : o?.[k]);
const normalize = (t) => t.replace(/\s+/g, " ").trim();
const hashOf = (t) => "0x" + createHash("sha256").update(normalize(t), "utf8").digest("hex");

async function rpc(method, params) {
  const res = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

function account(label) {
  const acc = gl.createAccount(gl.generatePrivateKey());
  console.log(`${label.padEnd(10)} ${acc.address}`);
  return { acc, client: gl.createClient({ chain: studionet, account: acc }) };
}

const publisher = account("publisher");
const keeper = account("keeper");
for (const a of [publisher, keeper]) {
  const tx = await rpc("sim_fundAccount", [a.acc.address, 1000000000000000000]);
  await a.client.waitForTransactionReceipt({ hash: tx, status: "FINALIZED", interval: 3000, retries: 60 });
}

const txs = [];
async function send(a, fn, args, label, value = 0n) {
  const hash = await a.client.writeContract({ address: CONTRACT, functionName: fn, args, value });
  const r = await a.client.waitForTransactionReceipt({ hash, status: "ACCEPTED", interval: 5000, retries: 240 });
  const votes = r?.consensus_data?.votes ? Object.values(r.consensus_data.votes) : undefined;
  const exec = r?.consensus_data?.leader_receipt?.[0]?.execution_result ?? "";
  console.log(`  ${label.padEnd(24)} ${hash} ${r.result_name ?? ""} ${exec} ${votes ? JSON.stringify(votes) : ""}`);
  txs.push([label, hash, exec]);
  return { r, exec };
}
const read = (fn, args = []) => publisher.client.readContract({ address: CONTRACT, functionName: fn, args });

const POLICY = "no personal data, payment details or credentials may appear in published notes";
const DOCS = [
  { key: "A", title: "Release notes", file: "release-notes.txt" },
  { key: "B", title: "Support handover", file: "support-handover.txt" },
  { key: "C", title: "Incident notes", file: "incident-notes.txt" },
];

console.log("contract", CONTRACT, "\n");
const ids = {};
for (const d of DOCS) {
  const text = readFileSync(path.join(ROOT, "demo", d.file), "utf8");
  d.text = normalize(text);
  d.hash = hashOf(text);
  d.url = `${BASE}/${d.file}`;
  console.log(`\nDocument ${d.key}: ${d.title}\n  url  ${d.url}\n  hash ${d.hash}`);
  await send(publisher, "submit", [d.title, POLICY, d.url, d.hash, WINDOW], `submit ${d.key}`, FEE);
  ids[d.key] = Number(field(await read("get_accounting"), "documents"));
  console.log("  stored on-chain:", show(await read("get_document", [ids[d.key]])));
}

for (const d of DOCS) {
  console.log(`\nScanning ${d.key} (${d.title})`);
  const { exec } = await send(keeper, "scan", [ids[d.key]], `scan ${d.key}`);
  const doc = await read("get_document", [ids[d.key]]);
  console.log("  ->", show({
    status: field(doc, "status"),
    reason: field(doc, "reason"),
    categories: field(doc, "categories"),
    findings: (field(doc, "findings") || []).map((f) => (f instanceof Map ? Object.fromEntries(f) : f)),
    redacted_hash: field(doc, "redacted_hash"),
  }));
  if (exec === "SUCCESS" && field(doc, "status") !== "PENDING") {
    const local = await read("verify_locally", [ids[d.key], d.text]);
    console.log("  publisher side:", show({
      hash_matches: field(local, "hash_matches"),
      redaction_matches: field(local, "redaction_matches"),
      redacted: field(local, "redacted"),
    }));
  }
}

console.log("\ncertificates:");
for (const d of DOCS) console.log(`  ${d.key}:`, show(await read("is_cleared", [d.hash])));
console.log("\nkeeper credit:", String(await read("get_credit", [keeper.acc.address])));
console.log("accounting:", show(await read("get_accounting")));
console.log("\nexplorer:");
console.log(`  contract ${EXPLORER}/address/${CONTRACT}`);
for (const [label, hash, exec] of txs) console.log(`  ${label.padEnd(24)} ${exec.padEnd(8)} ${EXPLORER}/tx/${hash}`);
