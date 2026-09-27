#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Val};

pub const STORE_MEMORY_LIMIT_BYTES: usize = 16 * 1024 * 1024;
const STORE_TABLE_ELEMENT_LIMIT: usize = 10_000;
const STORE_INSTANCE_LIMIT: usize = 1;
const STORE_TABLE_LIMIT: usize = 1;
const STORE_LINEAR_MEMORY_LIMIT: usize = 1;

pub fn fuel_engine() -> Engine {
    let mut config: Config = Config::new();
    config.consume_fuel(true);
    Engine::new(&config).expect("wasmtime engine with fuel metering")
}

pub struct Bounded {
    pub store: Store<StoreLimits>,
    pub instance: wasmtime::Instance,
    fuel: u64,
}

impl Bounded {
    pub fn instantiate(engine: &Engine, bytes: &[u8], fuel: u64) -> Self {
        let module: Module = Module::new(engine, bytes).expect("module compiles");
        let limits: StoreLimits = StoreLimitsBuilder::new()
            .memory_size(STORE_MEMORY_LIMIT_BYTES)
            .table_elements(STORE_TABLE_ELEMENT_LIMIT)
            .instances(STORE_INSTANCE_LIMIT)
            .tables(STORE_TABLE_LIMIT)
            .memories(STORE_LINEAR_MEMORY_LIMIT)
            .build();
        let mut store: Store<StoreLimits> = Store::new(engine, limits);
        store.limiter(|limits: &mut StoreLimits| limits);
        store
            .set_fuel(fuel)
            .expect("the engine meters fuel, so the store accepts a budget");
        let mut linker: Linker<StoreLimits> = Linker::new(engine);
        linker
            .define_unknown_imports_as_traps(&module)
            .expect("every import resolves to a trapping stub, never to a host function");
        let instance: wasmtime::Instance = linker
            .instantiate(&mut store, &module)
            .expect("module instantiates within the store limits");
        Self {
            store,
            instance,
            fuel,
        }
    }

    pub fn call(&mut self, export: &str, args: &[Val], result: Val) -> Option<Val> {
        let func: wasmtime::Func = self.instance.get_func(&mut self.store, export)?;
        self.store
            .set_fuel(self.fuel)
            .expect("the engine meters fuel, so the store accepts a budget");
        let mut results: [Val; 1] = [result];
        func.call(&mut self.store, args, &mut results).ok()?;
        let [value]: [Val; 1] = results;
        Some(value)
    }
}
