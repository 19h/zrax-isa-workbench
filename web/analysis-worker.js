import init, { WorkbenchEngine, hilbert_indices, classifier_version } from '../pkg/isa_classifier.js';
import { WORKBENCH_PROTOCOL } from './protocol.js';

const files = new Map();
const latest = new Map();
const queued = [];
const interactive = new Map();
let queueHead = 0;
let ready = false;
let running = false;
let resident = null;
let startupError = null;
// Yield between chunks without imposing nested-timer delays on every tile.
// Only one job is active, so there is at most one pending yield continuation.
const yieldChannel = new MessageChannel();
let resumeYield = null;
yieldChannel.port1.onmessage = () => { const resume = resumeYield; resumeYield = null; resume?.(); };
const yieldTask = () => new Promise(resolve => { resumeYield = resolve; yieldChannel.port2.postMessage(0); });
const send = (message, transfer = []) => postMessage(message, transfer);

function releaseResident() {
  resident?.engine.free();
  resident = null;
}

async function engineFor(id) {
  if (resident?.id === id) return resident.engine;
  releaseResident();
  const entry = files.get(id);
  if (!entry) throw new Error('File was removed.');
  // Browser/WASM allocations must remain below the wasm32 address-space limit.
  if (entry.file.size > 1024 ** 3) throw new Error('Resident analysis supports files up to 1 GiB.');
  const buffer = await entry.file.arrayBuffer();
  if (!files.has(id)) throw new Error('File was removed.');
  const engine = new WorkbenchEngine(new Uint8Array(buffer));
  resident = { id, engine };
  return engine;
}

function current(job) {
  return files.has(job.id) && (!job.request || latest.get(job.type) === job.request);
}

async function run(job) {
  if (!current(job)) return;
  if (job.type === 'classify') send({ type: 'status', id: job.id, status: 'analyzing' });
  if (job.type === 'map' || job.type === 'detail') send({ type: 'operation-status', operation: job.type,
    id: job.id, request: job.request, phase: resident?.id === job.id ? 'computing' : 'reading file' });
  const engine = await engineFor(job.id);
  if (!current(job)) return;
  if (job.type === 'classify') {
    const start = performance.now();
    let payload = null, error = '';
    try {
      payload = JSON.parse(engine.classification());
      if (payload.error) { error = String(payload.error); payload = null; }
    } catch (e) { error = String(e.message || e); }
    const elapsed = performance.now() - start;
    // A failed architecture classification still gets entropy and hex analysis.
    const profile = engine.profile(1024);
    const mean = profile.reduce((sum, h) => sum + h, 0) / profile.length;
    if (current(job)) send({ type: 'result', id: job.id, payload, error, elapsed, mean, profile }, [profile.buffer]);
  } else if (job.type === 'map' || job.type === 'detail') {
    if (![job.worldSide, job.scale, job.x, job.y, job.width, job.height].every(Number.isInteger)
      || job.width < 1 || job.height < 1 || job.width * job.height > 65536) {
      throw new Error('Map protocol mismatch. Reload the page to load matching workbench assets.');
    }
    const count = job.width * job.height;
    send({ type: 'operation-status', operation: job.type, id: job.id, request: job.request, phase: 'computing' });
    for (let from = 0; from < count; from += 512) {
      if (!current(job)) return;
      const cells = engine.spatial_cells(job.worldSide, job.scale, job.x, job.y, job.width, job.height,
        from, Math.min(512, count - from), job.linear);
      if (cells.length !== Math.min(512, count - from) * 6) throw new Error('Spatial kernel rejected the requested map bounds.');
      send({ type: 'map-tile', operation: job.type, id: job.id, request: job.request, from, count, cells }, [cells.buffer]);
      await yieldTask();
    }
    if (current(job)) send({ type: 'map-done', operation: job.type, id: job.id, request: job.request });
  } else if (job.type === 'probe') {
    const stats = JSON.parse(engine.inspect(job.start, job.length));
    const bytes = engine.bytes(job.offset, 32);
    send({ type: 'probe', id: job.id, request: job.request, offset: job.offset, stats, bytes }, [bytes.buffer]);
  } else if (job.type === 'hex' || job.type === 'selection') {
    const bytes = engine.bytes(job.start, job.length);
    const stats = job.type === 'selection' ? JSON.parse(engine.inspect(job.start, job.length)) : null;
    send({ type: job.type, id: job.id, request: job.request, start: job.start, bytes, stats }, [bytes.buffer]);
  }
}

async function pump() {
  if (!ready || running) return;
  running = true;
  try {
    while (interactive.size || queueHead < queued.length) {
      let job;
      if (interactive.size) { const [type, next] = interactive.entries().next().value; interactive.delete(type); job = next; }
      else job = queued[queueHead++];
      try { await run(job); }
      catch (e) {
        if (current(job)) send({ type: job.type === 'classify' ? 'result' : 'error', id: job.id,
          request: job.request, operation: job.type, error: String(e.message || e), payload: null });
      }
      await yieldTask();
    }
  } finally { running = false; if (queueHead === queued.length) { queued.length = 0; queueHead = 0; } }
}

self.addEventListener('message', ({ data }) => {
  if (data.type === 'add') {
    for (const entry of data.files) {
      files.set(entry.id, entry);
      if (startupError) send({ type: 'result', id: entry.id, payload: null, error: startupError });
      else queued.push({ type: 'classify', id: entry.id });
    }
  } else if (data.type === 'cancel') {
    for (const type of data.operations) { latest.delete(type); interactive.delete(type); }
  } else if (data.type === 'remove' || data.type === 'clear') {
    const ids = data.type === 'clear' ? [...files.keys()] : [data.id];
    for (const id of ids) files.delete(id);
    for (const [type, job] of interactive) if (!files.has(job.id)) interactive.delete(type);
    if (data.type === 'clear') { queued.length = 0; queueHead = 0; }
    // An active job can be between tiles or awaiting a file read. It checks
    // membership before the next engine access; freeing here is therefore safe.
    if (resident && !files.has(resident.id)) releaseResident();
  } else {
    latest.set(data.type, data.request);
    // One pending job per operation; replacement and classification dequeue
    // are O(1), including large batches and continuous viewport gestures.
    interactive.set(data.type, data);
  }
  pump();
});

try {
  await init();
  const probe = new WorkbenchEngine(new Uint8Array(0));
  try { if (probe.spatial_cells(2, 1, 0, 0, 1, 1, 0, 1, false).length !== 6) throw new Error('Unexpected spatial kernel result.'); }
  catch (e) { throw new Error(`Workbench/WASM build mismatch: ${e.message || e}. Rebuild and reload the page.`); }
  finally { probe.free(); }
  const layouts = [2, 4, 8, 16, 32, 64, 128, 256].map(side => ({ side, indices: hilbert_indices(side) }));
  ready = true;
  send({ type: 'ready', protocol: WORKBENCH_PROTOCOL, version: classifier_version(), layouts }, layouts.map(x => x.indices.buffer));
  pump();
} catch (e) {
  startupError = `Failed to load classifier: ${e.message || e}`;
  send({ type: 'boot-error', error: startupError });
  for (const id of files.keys()) send({ type: 'result', id, payload: null, error: startupError });
  queued.length = 0; queueHead = 0; interactive.clear();
}
