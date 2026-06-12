use rust_embed::RustEmbed;

/// Embeds the shared static files (CSS, fonts) from the project root static/ directory.
#[derive(RustEmbed)]
#[folder = "../../static/"]
pub struct StaticAssets;

/// Embeds the compiled WASM frontend from the crate-local wasm-pkg/ directory.
///
/// Populate this directory by running `just build-wasm` before building the CLI.
/// The directory is created empty by build.rs so compilation succeeds beforehand.
#[derive(RustEmbed)]
#[folder = "wasm-pkg/"]
pub struct WasmAssets;
