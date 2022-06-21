const button = document.getElementById('render');
const text = document.getElementById('text');
const concurrency = document.getElementById('concurrency');
const concurrencyAmt = document.getElementById('concurrency-amt');
const timing = document.getElementById('timing');
const timingVal = document.getElementById('timing-val');

button.disabled = true;
concurrency.disabled = true;

function loadWasm() {
  wasm_bindgen('./zkp-wasm/tom256_bg.wasm')
    .then(run)
    .catch(console.error);
}

loadWasm();

const { generateExpInput, generateExpProof, WorkerPool} = wasm_bindgen;

function run() {
  // use max num of threads
  pool = new WorkerPool(navigator.hardwareConcurrency);
  // Configure various buttons and such.
  button.onclick = function() {
    button.disabled = true;
    console.time('render');
    let zkpInput = JSON.parse(text.value);
    process(zkpInput);
  };
  button.innerText = 'Render!';
  button.disabled = false;

  concurrency.oninput = function() {
    concurrencyAmt.innerText = 'Concurrency: ' + concurrency.value;
  };
  concurrency.min = 1;
  concurrency.step = 1;
  concurrency.max = navigator.hardwareConcurrency;
  concurrency.value = concurrency.max;
  concurrency.oninput();
  concurrency.disabled = false;
}

let rendering = null;
let start = null;
let interval = null;
let pool = null;

class State {
  constructor(wasm) {
    this.start = performance.now();
    this.wasm = wasm;
    this.running = true;
    this.counter = 1;

    this.interval = setInterval(() => this.updateTimer(true), 100);

    wasm
      .then(data => {
        this.updateTimer(false);
        console.log(data);
        this.stop();
      })
      .catch(console.error);
  }

  updateTimer(updateImage) {
    const dur = performance.now() - this.start;
    timingVal.innerText = `${dur}ms`;
    this.counter += 1;
  }

  stop() {
    if (!this.running)
      return;
    console.timeEnd('render');
    this.running = false;
    this.wasm = null;
    clearInterval(this.interval);
    button.disabled = false;
  }
}

function process(zkpInput) {
  if (rendering) {
    rendering.stop();
    rendering = null;
  }
  console.log("BELLO");
  let expInput; 
  try {
    expInput = generateExpInput(zkpInput.input);
  } catch(error) {
    console.error(error);
  }
  rendering = new State(generateExpProof(expInput, pool, concurrency.value));
}
