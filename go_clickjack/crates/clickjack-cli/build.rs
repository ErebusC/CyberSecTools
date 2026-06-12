// Creates an empty wasm-pkg directory next to this crate's Cargo.toml so that
// rust-embed compiles before wasm-pack has been run. Populate the directory by
// running `just build-wasm` before building this crate in earnest.
fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by cargo for every build script");
    let wasm_pkg = std::path::Path::new(&manifest).join("wasm-pkg");
    if !wasm_pkg.exists() {
        std::fs::create_dir(&wasm_pkg).expect("failed to create placeholder wasm-pkg directory");
    }
    println!("cargo:rerun-if-changed=wasm-pkg");
}
