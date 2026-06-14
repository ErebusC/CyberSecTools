# ClickJacker

A clickjacking proof-of-concept tool written in Go. Loads a target site in an iframe with a fake login form overlay and optional collaborator exfiltration.

Built by Daniel Roberts.

## Features

- Loads any target URL in an iframe
- Frame status indicator (framed or blocked)
- Fake credential form overlaid on the framed site
- Captured credentials POSTed to a collaborator address (e.g. Burp Collaborator)
- Draggable, resizable decoy overlay for UI redressing tests
- Decoy templates: fake button, fake dialog, cookie banner, custom HTML
- Adjustable decoy opacity
- Decoy chrome fades after 10 seconds of inactivity, restores on interaction
- Fullscreen mode hides controls (Escape or button to exit)
- Session URL history panel
- Optional nav logo via `--logo` or auto-detected from a file alongside the binary

## Usage

```
clickjack [--logo <url|path>] [target_url] [collaborator_url]
```

| Argument | Description |
|---|---|
| `target_url` | URL to load in the iframe. Defaults to `https://economist.com` |
| `collaborator_url` | Address to POST captured credentials to |
| `--logo` | URL or local file path to display in the nav bar |

Once running, open `http://localhost:9999` in your browser.

1. Enter the target URL and click Submit
2. If the site can be framed, the status badge shows Framed
3. Enter a collaborator address and click Clickjack to overlay the credential form
4. Submitted credentials are POSTed to the collaborator address

## Docker

```
docker run -p 9999:9999 clickjacker [target_url] [collaborator_url]
```

Set `CONTAINER=TRUE` to disable the automatic browser open on startup.

## Building

```
go build -o clickjack .
```

## Notes

- The tool sets `X-Frame-Options: Deny` on its own responses so it cannot itself be framed
- The frame status indicator uses a cross-origin heuristic: a `SecurityError` on iframe access indicates the page loaded, which is reported as Framed
