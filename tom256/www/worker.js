/*
// synchronously, using the browser, import out shim JS scripts
importScripts('zkp-wasm/tom256.js');

// Wait for the main thread to send us the shared module/memory. Once we've got
// it, initialize it all with the `wasm_bindgen` global we imported via
// `importScripts`.
//
// After our first message all subsequent messages are an entry point to run,
// so we just do that.
self.onmessage = event => {
  let initialised = wasm_bindgen(...event.data).catch(err => {
    // Propagate to main `onerror`:
    setTimeout(() => {
      throw err;
    });
    // Rethrow to keep promise rejected and prevent execution of further commands:
    throw err;
  });

  self.onmessage = async event => {
    // This will queue further commands up until the module is fully initialised:
    await initialised;
    wasm_bindgen.child_entry_point(event.data);
  };
};
*/

import * as Comlink from 'comlink';

// Wrap wasm-bindgen exports (the `generate` function) to add time measurement.
function wrapExports({ generateExpProof }) {
  return ({ input }) => {
    const start = performance.now();
    const proof = generateExpProof(input);
    const time = performance.now() - start;
    return {
      // Little perf boost to transfer data to the main thread w/o copying.
      proof: Comlink.transfer(proof, [proof.buffer]),
      time
    };
  };
}

async function initHandlers() {
    (async () => {
      const multiThread = await import(
        './zkp-wasm/tom256.js'
      );
      await multiThread.default();
      await multiThread.initThreadPool(navigator.hardwareConcurrency);
      return wrapExports(multiThread);
    })()
  ]);

  return Comlink.proxy({
    multiThread
  });
}

Comlink.expose({
  handlers: initHandlers()
});
