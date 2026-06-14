// Stores the cleanup function for each interactive overlay so callers can
// detach listeners without needing a reference to the named functions.
export const dragCleanups = new WeakMap<HTMLElement, () => void>();

const DIRECTIONS = ["nw", "n", "ne", "e", "se", "s", "sw", "w"] as const;
const MIN_W = 80;
const MIN_H = 40;

export function makeOverlayInteractive(overlay: HTMLElement): void {
  const iframe = document.querySelector<HTMLIFrameElement>('iframe[name="website"]')!;
  const dragbar = overlay.querySelector<HTMLElement>(".overlay-dragbar")!;

  let isDragging = false;
  let isResizing = false;
  let resizeDir = "";
  let startX = 0, startY = 0;
  let startLeft = 0, startTop = 0, startW = 0, startH = 0;

  function beginDrag(e: MouseEvent): void {
    restoreHint();
    isDragging = true;
    startX = e.clientX;
    startY = e.clientY;
    startLeft = overlay.offsetLeft;
    startTop = overlay.offsetTop;
    iframe.style.pointerEvents = "none";
    e.preventDefault();
  }

  function beginResize(dir: string, e: MouseEvent): void {
    restoreHint();
    isResizing = true;
    resizeDir = dir;
    startX = e.clientX;
    startY = e.clientY;
    startLeft = overlay.offsetLeft;
    startTop = overlay.offsetTop;
    startW = overlay.offsetWidth;
    startH = overlay.offsetHeight;
    iframe.style.pointerEvents = "none";
    e.preventDefault();
  }

  const HINT_DELAY = 10_000;
  let hintTimer: ReturnType<typeof setTimeout> | null = null;

  function scheduleHintFade(): void {
    if (hintTimer !== null) clearTimeout(hintTimer);
    hintTimer = setTimeout(() => {
      overlay.classList.add("overlay--faded");
      hintTimer = null;
    }, HINT_DELAY);
  }

  function restoreHint(): void {
    if (hintTimer !== null) clearTimeout(hintTimer);
    overlay.classList.remove("overlay--faded");
  }

  scheduleHintFade();

  dragbar.addEventListener("mousedown", beginDrag);

  for (const dir of DIRECTIONS) {
    const handle = document.createElement("div");
    handle.className = `resize-handle resize-${dir}`;
    handle.addEventListener("mousedown", (e) => beginResize(dir, e));
    overlay.appendChild(handle);
  }

  function onMouseMove(e: MouseEvent): void {
    if (!isDragging && !isResizing) return;
    const dx = e.clientX - startX;
    const dy = e.clientY - startY;

    if (isDragging) {
      overlay.style.left = `${startLeft + dx}px`;
      overlay.style.top = `${startTop + dy}px`;
      return;
    }

    if (resizeDir.includes("e")) {
      overlay.style.width = `${Math.max(MIN_W, startW + dx)}px`;
    }
    if (resizeDir.includes("s")) {
      overlay.style.height = `${Math.max(MIN_H, startH + dy)}px`;
    }
    if (resizeDir.includes("w")) {
      const newW = Math.max(MIN_W, startW - dx);
      overlay.style.left = `${startLeft + startW - newW}px`;
      overlay.style.width = `${newW}px`;
    }
    if (resizeDir.includes("n")) {
      const newH = Math.max(MIN_H, startH - dy);
      overlay.style.top = `${startTop + startH - newH}px`;
      overlay.style.height = `${newH}px`;
    }
  }

  function onMouseUp(): void {
    if (isDragging || isResizing) scheduleHintFade();
    isDragging = false;
    isResizing = false;
    iframe.style.pointerEvents = "";
  }

  document.addEventListener("mousemove", onMouseMove);
  document.addEventListener("mouseup", onMouseUp);

  dragCleanups.set(overlay, () => {
    if (hintTimer !== null) clearTimeout(hintTimer);
    overlay.classList.remove("overlay--faded");
    dragbar.removeEventListener("mousedown", beginDrag);
    document.removeEventListener("mousemove", onMouseMove);
    document.removeEventListener("mouseup", onMouseUp);
    iframe.style.pointerEvents = "";
  });
}
