# ClickJacker

A clickjacking proof-of-concept tool written in Rust with a WebAssembly frontend. Loads a target site in an iframe with a fake credential overlay and draggable decoy elements for UI redressing tests. Supports optional collaborator exfiltration.

Built by Daniel Roberts.

## Architecture

Three-crate Rust workspace:

| Crate | Role |
|---|---|
| `clickjack-core` | Shared types: `Config`, `LogoSource`, `DecoyTemplate` |
| `clickjack-wasm` | WebAssembly frontend — DOM wiring, overlays, drag/resize, history |
| `clickjack-cli` | Axum HTTP server — serves the UI and embedded WASM bundle |

## Features

- Loads any target URL in an iframe
- Phishing overlay: fake credential form POSTs captured credentials to a collaborator address
- Draggable, resizable decoy overlay for UI redressing tests
- Decoy templates: Fake button, Survey prompt, Security check, Flash reward, Custom HTML
- Adjustable decoy opacity slider
- Fullscreen mode — hides controls (Escape or button to exit)
- Session URL history panel
- Optional nav logo via `--logo` or auto-detected from a file alongside the binary
- Configurable port and browser auto-open suppression

## Prerequisites

- Rust toolchain (stable)
- `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`
- `wasm-pack`: `cargo install wasm-pack`
- `just`: `cargo install just`

## Building

Build the WASM frontend and CLI binary in one step:

```
just build
```

The compiled binary is placed at `target/release/clickjack`.

### Separate steps

```
just build-wasm   # compile WASM with wasm-pack (must run before build-cli)
just build-cli    # compile the CLI binary
```

> The WASM bundle must be compiled before the CLI. Running `just build-cli` alone will produce a binary where the frontend does not function. Always run `just build-wasm` first, or use `just build` to do both in the correct order.

### Development build (unoptimised, includes debug info)

```
just dev
```

Compiles an unoptimised WASM bundle and runs the server via `cargo run`.

## Usage

```
clickjack [OPTIONS] [target_url] [collab_url]
```

| Argument / Flag | Description |
|---|---|
| `target_url` | URL to load in the iframe. Defaults to `https://economist.com` |
| `collab_url` | Address to POST captured credentials to |
| `--logo <url\|path>` | URL or local file path to display in the nav bar |
| `--port <N>` | Port to listen on (default: `9999`) |
| `--no-open` | Do not open a browser window automatically |

Once running, open `http://localhost:9999` in your browser (or the configured port). The browser is opened automatically unless `--no-open` is passed.

## Workflow

1. Enter a target URL in the **Web page to clickjack** field and press **Submit** or Enter — the iframe loads the target.
2. **Phishing overlay**: enter a collaborator address and click **Phish** to inject a fake credential form over the iframe. Submitted credentials are POSTed to the collaborator address. Click **Remove Overlay** to dismiss.
3. **Decoy overlay**: choose a template from the dropdown and click **Clickjack** to place a draggable, resizable decoy element over the iframe. Use the opacity slider to adjust visibility. Click **Remove Decoy** to dismiss.
   - *Fake button* — a styled "Click to Continue" button
   - *Survey prompt* — a survey invitation card
   - *Security check* — a red security-verification warning
   - *Flash reward* — an orange congratulatory reward banner
   - *Custom* — enter arbitrary HTML in the input field that appears
4. Click **Fullscreen** to hide the controls panel. Press **Escape** or the exit button to restore them.

## Logo auto-detection

If `--logo` is not passed, the server scans the directory containing the binary for `logo.svg`, `logo.png`, `logo.jpg`, `logo.jpeg`, or `logo.gif` and serves the first match automatically.

## Notes

- The tool sets `X-Frame-Options: Deny` on its own responses so it cannot itself be framed.
- The WASM bundle is embedded into the CLI binary at compile time via `rust-embed`. The `build.rs` script creates an empty `wasm-pkg/` directory so the CLI crate compiles without the bundle, but the UI will not function until the WASM artifacts are present — always run `just build-wasm` first.
