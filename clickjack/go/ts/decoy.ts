import { DECOY_TEMPLATES } from "./templates";
import { dragCleanups, makeOverlayInteractive } from "./drag";

function applyDecoyTemplate(key: string): void {
  const content = document.getElementById("decoy-content");
  if (!content) return;

  if (key === "custom") {
    const textarea = document.getElementById("custom-html-input") as HTMLTextAreaElement | null;
    content.innerHTML = textarea?.value ?? "";
  } else {
    content.innerHTML = DECOY_TEMPLATES[key] ?? "";
  }
}

export function onTemplateChange(): void {
  const select = document.getElementById("decoy-template") as HTMLSelectElement;
  const customRow = document.getElementById("custom-html-row");
  if (customRow) {
    customRow.style.display = select.value === "custom" ? "flex" : "none";
  }

  const overlay = document.getElementById("decoy-overlay");
  if (overlay) applyDecoyTemplate(select.value);
}

export function clickjackDecoy(): void {
  if (document.getElementById("decoy-overlay")) return;

  const wrapper = document.getElementById("wrapper");
  if (!wrapper) return;

  const overlay = document.createElement("div");
  overlay.id = "decoy-overlay";
  overlay.style.left = `${Math.round(wrapper.offsetWidth * 0.05)}px`;
  overlay.style.top = `${Math.round(wrapper.offsetHeight * 0.22)}px`;
  overlay.style.width = "240px";
  overlay.style.height = "100px";

  const dragbar = document.createElement("div");
  dragbar.className = "overlay-dragbar";
  dragbar.textContent = "⠿ Drag to reposition · resize from edges";

  const content = document.createElement("div");
  content.id = "decoy-content";

  overlay.appendChild(dragbar);
  overlay.appendChild(content);
  wrapper.appendChild(overlay);

  const select = document.getElementById("decoy-template") as HTMLSelectElement;
  applyDecoyTemplate(select.value);
  makeOverlayInteractive(overlay);

  document.getElementById("decoy-reset")!.style.display = "inline-block";

  const opacityControls = document.getElementById("opacity-controls");
  if (opacityControls) opacityControls.style.display = "contents";

  const slider = document.getElementById("opacity-slider") as HTMLInputElement | null;
  if (slider) slider.value = "100";

  const opacityLabel = document.getElementById("opacity-value");
  if (opacityLabel) opacityLabel.textContent = "100%";

  overlay.style.opacity = "1";
}

export function removeDecoyOverlay(): void {
  const overlay = document.getElementById("decoy-overlay");
  if (overlay) {
    dragCleanups.get(overlay)?.();
    dragCleanups.delete(overlay);
    overlay.remove();
  }

  document.getElementById("decoy-reset")!.style.display = "none";

  const opacityControls = document.getElementById("opacity-controls");
  if (opacityControls) opacityControls.style.display = "none";

  const customRow = document.getElementById("custom-html-row");
  if (customRow) customRow.style.display = "none";

  const select = document.getElementById("decoy-template") as HTMLSelectElement | null;
  if (select) select.value = "fake-button";
}

export function updateDecoyOpacity(val: string): void {
  const overlay = document.getElementById("decoy-overlay");
  if (overlay) overlay.style.opacity = (parseFloat(val) / 100).toFixed(2);

  const label = document.getElementById("opacity-value");
  if (label) label.textContent = `${val}%`;
}
