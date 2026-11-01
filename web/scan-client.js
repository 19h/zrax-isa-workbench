// Main-thread side of the scan worker: one worker shared by the strings and
// certificates views, request numbering, and a stall watchdog. A regular
// expression with catastrophic backtracking blocks the worker inside a
// single test, so it sends nothing at all. While a query is pending, every
// worker message re-arms the watchdog; after STALL_MS of silence the worker
// is replaced and subscribers are told why. A busy but working worker keeps
// sending scan progress and query progress.
import { SCAN_PROTOCOL } from './protocol.js';

const STALL_MS = 4000;

export class ScanClient {
  constructor() {
    this.listeners = new Set();
    this.nextRequest = 1;
    this.encodingIds = [];
    this.tagIds = [];
    this.error = '';
    this.start();
  }

  start() {
    this.ready = false;
    this.queue = [];
    this.watched = null;
    clearTimeout(this.stallTimer);
    this.worker = new Worker(new URL('./scan-worker.js', import.meta.url), { type: 'module' });
    this.worker.addEventListener('message', ({ data }) => this.receive(data));
    this.worker.addEventListener('error', event => {
      this.error = `Scan worker failed: ${event.message || 'unknown error'}`;
      this.emit({ type: 'boot-error', error: this.error });
    });
  }

  receive(data) {
    if (data.type === 'ready') {
      if (data.protocol !== SCAN_PROTOCOL) {
        this.error = 'Scan worker build mismatch. Reload the page to load matching assets.';
        this.worker.terminate();
        this.emit({ type: 'boot-error', error: this.error });
        return;
      }
      this.ready = true;
      this.encodingIds = data.encodingIds;
      this.tagIds = data.tagIds;
      for (const message of this.queue.splice(0)) this.worker.postMessage(message);
    }
    if (this.watched) {
      const answered = data.request === this.watched.request && data.type !== 'strings-query-progress';
      if (answered) this.unwatch();
      else this.watch(this.watched);
    }
    this.emit(data);
  }

  emit(data) {
    for (const listener of this.listeners) listener(data);
  }

  /** Subscribe to every worker message; returns an unsubscribe function. */
  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Send a request; returns its request number. */
  post(message) {
    const request = this.nextRequest++;
    const full = { ...message, request };
    if (this.ready) this.worker.postMessage(full);
    else this.queue.push(full);
    if (message.type === 'strings-query') this.watch(full);
    return request;
  }

  /** Release a file's scans in the worker. */
  forget(id) {
    const message = { type: 'forget', id };
    if (this.ready) this.worker.postMessage(message);
    else this.queue.push(message);
  }

  watch(job) {
    this.watched = job;
    clearTimeout(this.stallTimer);
    this.stallTimer = setTimeout(() => this.stalled(job), STALL_MS);
  }

  unwatch() {
    this.watched = null;
    clearTimeout(this.stallTimer);
  }

  stalled(job) {
    if (this.watched !== job) return;
    // A query waiting for the worker to boot has not started yet.
    if (!this.ready) {
      this.watch(job);
      return;
    }
    this.worker.terminate();
    this.start();
    this.emit({
      type: 'restarted',
      id: job.id,
      request: job.request,
      query: job.query,
      reason: `The search stopped responding for ${STALL_MS / 1000} s and was cancelled; simplify the regular expression`,
    });
  }
}
