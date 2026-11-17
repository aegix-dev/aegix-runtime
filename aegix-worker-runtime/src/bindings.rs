use wasmtime::component::*;

bindgen!({
    world: "automation-node",
    path: "../wit/aegix.wit",
    imports: {
        default: async,
    },
    exports: {
        default: async,
    }
});
