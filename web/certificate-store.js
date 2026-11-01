// Certificate reports of the open files, shared by the certificates tab and
// the all-files certificates view. Scans run in the scan worker. A scan the
// user is waiting for starts at once; scans for the all-files view queue and
// run at most MAX_BACKGROUND_SCANS at a time, so opening that view over many
// files does not read every file at once.

// Scans in flight before queued scans wait. Each holds a window of up to
// 6 MiB while it reads.
const MAX_BACKGROUND_SCANS = 2;

export function createCertificateStore(scanner) {
  const files = new Map();
  const queue = [];
  const running = new Set();
  const listeners = new Set();

  const notify = id => {
    for (const listener of listeners) listener(id);
  };

  function fileState(entry) {
    let state = files.get(entry.id);
    if (!state) {
      state = { entry, request: 0, report: null, error: '', scanned: 0, queued: false, urgent: false };
      files.set(entry.id, state);
    }
    return state;
  }

  function start(state) {
    state.queued = false;
    state.report = null;
    state.error = '';
    state.request = scanner.post({ type: 'certificates', id: state.entry.id, file: state.entry.file });
    running.add(state.entry.id);
  }

  function enqueue(state) {
    if (state.queued) return;
    state.queued = true;
    queue.push(state.entry.id);
  }

  function pump() {
    while (running.size < MAX_BACKGROUND_SCANS && queue.length) {
      const state = files.get(queue.shift());
      if (state?.queued) start(state);
    }
  }

  function settle(id) {
    running.delete(id);
    pump();
  }

  /** Release the worker's scan of a file that is still in flight. */
  function release(id) {
    if (running.delete(id)) scanner.forget(id);
  }

  scanner.subscribe(data => {
    if (data.type === 'boot-error' || data.type === 'restarted') {
      // The worker was replaced, so scans without a report are lost. Rescan
      // the ones that were running or queued; the rest rescan when asked.
      const lost = [];
      for (const state of files.values()) {
        if (state.report) continue;
        if (running.has(state.entry.id) || state.queued) lost.push(state);
        state.request = 0;
        state.queued = false;
      }
      running.clear();
      queue.length = 0;
      for (const state of lost) {
        if (state.urgent) start(state);
        else enqueue(state);
      }
      pump();
      return;
    }
    const state = files.get(data.id);
    if (!state || data.request !== state.request) return;
    if (data.type === 'certificates-progress') {
      state.scanned = data.scanned;
    } else if (data.type === 'certificates') {
      state.report = data.report;
      settle(data.id);
    } else if (data.type === 'error' && data.operation === 'certificates') {
      state.error = data.error;
      settle(data.id);
    } else {
      return;
    }
    notify(data.id);
  });

  return {
    /** Scan state of a file: `{ report, error, scanned }`, or undefined before any request. */
    get(id) {
      return files.get(id);
    },
    /**
     * Scan `entry` once. An urgent scan starts now; others queue behind the
     * running scans.
     */
    scan(entry, urgent = false) {
      const state = fileState(entry);
      if (state.request) return;
      if (urgent) {
        state.urgent = true;
        start(state);
        return;
      }
      enqueue(state);
      pump();
    },
    /** Call `listener(id)` whenever a file's scan state changes. */
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    forget(id) {
      release(id);
      files.delete(id);
      pump();
      notify(id);
    },
    clear() {
      for (const id of [...running]) release(id);
      files.clear();
      queue.length = 0;
      notify(null);
    },
  };
}
