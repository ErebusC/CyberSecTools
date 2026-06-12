import { addToHistory } from "./history";
import { clickjackOverlay, removeOverlay } from "./phish";
import {
  clickjackDecoy,
  removeDecoyOverlay,
  updateDecoyOpacity,
  onTemplateChange,
} from "./decoy";

let elIframe: HTMLIFrameElement;
let elWebInput: HTMLInputElement;
let elHistory: HTMLUListElement;

function loadWebsite(): void {
  const url = elWebInput.value.trim();
  if (!url) return;
  elIframe.src = url;
  addToHistory(elHistory, elWebInput, elIframe, url);
}

document.addEventListener("DOMContentLoaded", () => {
  elIframe = document.getElementsByName("website")[0] as HTMLIFrameElement;
  elWebInput = document.getElementsByName("webInput")[0] as HTMLInputElement;
  elHistory = document.getElementById("url-history") as HTMLUListElement;

  if (elIframe.src && elIframe.src !== "about:blank" && elIframe.src !== window.location.href) {
    addToHistory(elHistory, elWebInput, elIframe, elIframe.src);
  }

  document.getElementById("submit-btn")!.addEventListener("click", loadWebsite);
  elWebInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") loadWebsite();
  });

  document.getElementById("phish-btn")!.addEventListener("click", clickjackOverlay);
  document.getElementById("overlay-reset")!.addEventListener("click", removeOverlay);

  document.getElementById("decoy-btn")!.addEventListener("click", clickjackDecoy);
  document.getElementById("decoy-reset")!.addEventListener("click", removeDecoyOverlay);
  document.getElementById("decoy-template")!.addEventListener("change", onTemplateChange);
  document.getElementById("opacity-slider")!.addEventListener("input", (e) => {
    updateDecoyOpacity((e.target as HTMLInputElement).value);
  });
});
