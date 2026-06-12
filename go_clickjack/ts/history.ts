const HISTORY_LIMIT = 20;

export function addToHistory(
  elHistory: HTMLUListElement,
  elWebInput: HTMLInputElement,
  elIframe: HTMLIFrameElement,
  url: string,
): void {
  const items = elHistory.querySelectorAll("li");
  for (let i = 0; i < items.length; i++) {
    if ((items[i] as HTMLElement).dataset.url === url) return;
  }

  if (items.length >= HISTORY_LIMIT) {
    elHistory.removeChild(elHistory.lastElementChild!);
  }

  const li = document.createElement("li");
  li.dataset.url = url;
  li.title = url;

  const label = document.createElement("span");
  label.className = "url-label";
  label.textContent = url;

  const btn = document.createElement("button");
  btn.className = "url-load";
  btn.textContent = "Load";
  btn.onclick = () => {
    elWebInput.value = url;
    elIframe.src = url;
  };

  li.appendChild(label);
  li.appendChild(btn);
  elHistory.prepend(li);
}
