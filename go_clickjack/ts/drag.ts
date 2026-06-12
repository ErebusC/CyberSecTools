// Stores the cleanup function for each interactive overlay so callers can
// detach listeners without needing a reference to the named functions.
export const dragCleanups = new WeakMap<HTMLElement, () => void>();

const DIRECTIONS = ["nw", "n", "ne", "e", "se", "s", "sw", "w"] as const;
const MIN_W = 80;
const MIN_H = 40;

export function makeOverlayInteractive(overlay: HTMLElement): void {
  const iframe = document.querySelector<HTMLIFrameElement>('iframe[name="website"]')!;

  let isDragging = false;
  let isResizing = false;
  let resizeDir = "";
  let startX = 0, startY = 0;
  let startLeft = 0, startTop = 0, startW = 0, startH = 0;

  for (const dir of DIRECTIONS) {
    const handle = document.createElement("div");
    handle.className = `resize-handle resize-${dir}`;
    handle.dataset.dir = dir;
    overlay.appendChild(handle);
  }

  function onMouseDown(e: MouseEvent): void {
    const target = e.target as HTMLElement;
    const tag = target.tagName.toLowerCase();
    if (["input", "button", "label", "select", "textarea"].includes(tag)) return;

    startX = e.clientX;
    startY = e.clientY;
    startLeft = overlay.offsetLeft;
    startTop = overlay.offsetTop;
    startW = overlay.offsetWidth;
    startH = overlay.offsetHeight;

    if (target.classList.contains("resize-handle") && target.dataset.dir) {
      isResizing = true;
      resizeDir = target.dataset.dir;
    } else {
      isDragging = true;
    }

    iframe.style.pointerEvents = "none";
    e.preventDefault();
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
    isDragging = false;
    isResizing = false;
    iframe.style.pointerEvents = "";
  }

  overlay.addEventListener("mousedown", onMouseDown);
  document.addEventListener("mousemove", onMouseMove);
  document.addEventListener("mouseup", onMouseUp);

  dragCleanups.set(overlay, () => {
    overlay.removeEventListener("mousedown", onMouseDown);
    document.removeEventListener("mousemove", onMouseMove);
    document.removeEventListener("mouseup", onMouseUp);
    iframe.style.pointerEvents = "";
  });
}
