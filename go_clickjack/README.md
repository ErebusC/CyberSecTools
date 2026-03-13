# ClickJacker

A clickjacking proof-of-concept tool written in Go. Loads a target website inside an iframe and overlays a fake login form to demonstrate that the target is vulnerable to clickjacking attacks. Supports an optional collaborator address to capture submitted credentials.

Built by Daniel Roberts. Enhanced with AI assistance to improve functionality.

## Features

- Loads any target URL in an iframe
- Frame status indicator showing whether the target was successfully framed or blocked
- Overlay a fake credential capture form over the framed site
- Forwards captured credentials to a collaborator server (e.g. Burp Collaborator)
- Optional logo display in the nav bar via `--logo`
- Session history panel tracking URLs loaded during the session
- Auto-detects a logo file alongside the binary if one is present

## Usage

```
clickjack [--logo <url|path>] [target_url] [collaborator_url]
```

**Arguments:**

| Argument | Description |
|---|---|
| `target_url` | The URL to load in the iframe. Defaults to `https://economist.com` |
| `collaborator_url` | Address to POST captured credentials to |
| `--logo` | URL or local file path to display as a logo in the nav bar |

Once running, open `http://localhost:9999` in your browser.

1. Enter the target URL and click Submit to load it in the iframe
2. If the site can be framed, the status badge will show Framed
3. Enter your collaborator address and click Clickjack to overlay the credential form
4. Submitted credentials are POSTed to the collaborator address

## Running with Docker

```
docker run -p 9999:9999 clickjacker [target_url] [collaborator_url]
```

The `CONTAINER=TRUE` environment variable disables the automatic browser open behaviour.

## Building

```
go build -o clickjack .
```

## Notes

- The tool sets `X-Frame-Options: Deny` on its own responses so the tool cannot be framed by another page
- The frame status indicator uses a cross-origin heuristic; a SecurityError on iframe access means the page loaded successfully, which is reported as Framed
