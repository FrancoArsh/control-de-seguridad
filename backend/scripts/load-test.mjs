import { performance } from "node:perf_hooks";

const args = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const [key, value = "true"] = process.argv[index].split("=", 2);
  args.set(key.replace(/^--/, ""), value);
}

const baseUrl = args.get("url") || "http://127.0.0.1:3000";
const pathname = args.get("path") || "/health";
const requests = Math.max(1, Number(args.get("requests") || 100));
const concurrency = Math.max(1, Math.min(Number(args.get("concurrency") || 10), requests));
const durations = [];
let issued = 0;
let completed = 0;
let failed = 0;

async function worker() {
  while (true) {
    const current = issued++;
    if (current >= requests) return;
    const started = performance.now();
    try {
      const response = await fetch(`${baseUrl}${pathname}`);
      if (!response.ok) failed += 1;
      else completed += 1;
    } catch (_) {
      failed += 1;
    } finally {
      durations.push(performance.now() - started);
    }
  }
}

const startedAt = performance.now();
await Promise.all(Array.from({ length: concurrency }, worker));
durations.sort((a, b) => a - b);
const percentile = (value) => durations[Math.min(durations.length - 1, Math.floor(durations.length * value))] || 0;

console.log(JSON.stringify({
  url: `${baseUrl}${pathname}`,
  requests,
  concurrency,
  completed,
  failed,
  durationMs: Math.round(performance.now() - startedAt),
  latencyMs: {
    p50: Number(percentile(0.5).toFixed(2)),
    p95: Number(percentile(0.95).toFixed(2)),
    max: Number((durations.at(-1) || 0).toFixed(2))
  }
}, null, 2));

process.exitCode = failed > 0 ? 1 : 0;
