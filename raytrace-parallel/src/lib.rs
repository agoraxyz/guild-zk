use futures_channel::oneshot;
use js_sys::{Promise, Uint8ClampedArray, WebAssembly};
use rayon::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

macro_rules! console_log {
    ($($t:tt)*) => (crate::log(&format_args!($($t)*).to_string()))
}

mod pool;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn logv(x: &JsValue);
}

#[wasm_bindgen(js_name = "renderScene")]
pub fn render_scene(
    scene: JsValue,
    concurrency: usize,
    pool: &pool::WorkerPool,
) -> Result<js_sys::Promise, JsValue> {
    let scene: raytracer::scene::Scene = scene
        .into_serde()
        .map_err(|e| JsValue::from(e.to_string()))?;
    let height = scene.height;
    let width = scene.width;

    // Allocate the pixel data which our threads will be writing into.
    let pixels = (width * height) as usize;
    let mut rgb_data = vec![0; 4 * pixels];
    let base = rgb_data.as_ptr() as usize;
    let len = rgb_data.len();

    // Configure a rayon thread pool which will pull web workers from
    // `pool`.
    let thread_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(concurrency)
        .spawn_handler(|thread| Ok(pool.run(|| thread.run()).unwrap()))
        .build()
        .unwrap();

    // And now execute the render! The entire render happens on our worker
    // threads so we don't lock up the main thread, so we ship off a thread
    // which actually does the whole rayon business. When our returned
    // future is resolved we can pull out the final version of the image.
    let (tx, rx) = oneshot::channel();
    pool.run(move || {
        thread_pool.install(|| {
            rgb_data
                .par_chunks_mut(4)
                .enumerate()
                .for_each(|(i, chunk)| {
                    let i = i as u32;
                    let x = i % width;
                    let y = i / width;
                    let ray = raytracer::Ray::create_prime(x, y, &scene);
                    let result = raytracer::cast_ray(&scene, &ray, 0).to_rgba();
                    chunk[0] = result.data[0];
                    chunk[1] = result.data[1];
                    chunk[2] = result.data[2];
                    chunk[3] = result.data[3];
                });
        });
        drop(tx.send(rgb_data));
    })?;

    let done = async move {
        match rx.await {
            Ok(_data) => Ok(JsValue::from(15_u32)),
            Err(_) => Err(JsValue::undefined()),
        }
    };

    Ok(wasm_bindgen_futures::future_to_promise(done))
}
