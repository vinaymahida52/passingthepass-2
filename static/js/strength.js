// Adaptive password strength meter.
// Scores 0-4 and gives feedback that adapts to what's actually missing,
// not just a static checklist.

const COMMON_PASSWORDS = new Set([
  "password", "123456", "123456789", "qwerty", "abc123", "password1",
  "111111", "12345678", "letmein", "iloveyou", "admin", "welcome",
  "monkey", "login", "princess", "qwerty123", "solo", "passw0rd",
  "starwars", "dragon", "football", "baseball", "superman", "trustno1",
]);

function hasSequential(pw) {
  const seqs = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"];
  const lower = pw.toLowerCase();
  for (const seq of seqs) {
    for (let i = 0; i <= seq.length - 3; i++) {
      const chunk = seq.slice(i, i + 3);
      if (lower.includes(chunk) || lower.includes(chunk.split("").reverse().join(""))) return true;
    }
  }
  return false;
}

function hasRepeats(pw) {
  return /(.)\1\1/.test(pw);
}

function estimateEntropyBits(pw) {
  let poolSize = 0;
  if (/[a-z]/.test(pw)) poolSize += 26;
  if (/[A-Z]/.test(pw)) poolSize += 26;
  if (/[0-9]/.test(pw)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) poolSize += 32;
  if (poolSize === 0) return 0;
  return pw.length * Math.log2(poolSize);
}

function analyzePassword(pw, context = []) {
  if (!pw) {
    return { score: 0, label: "", bits: 0, tips: [] };
  }

  const lower = pw.toLowerCase();
  const tips = [];
  let bits = estimateEntropyBits(pw);

  const isCommon = COMMON_PASSWORDS.has(lower);
  const containsContext = context.some((c) => c && c.length >= 3 && lower.includes(c.toLowerCase()));
  const sequential = hasSequential(pw);
  const repeated = hasRepeats(pw);

  if (isCommon) bits = Math.min(bits, 6);
  if (containsContext) bits -= 10;
  if (sequential) bits -= 8;
  if (repeated) bits -= 6;
  bits = Math.max(bits, 0);

  if (pw.length < 8) tips.push("Use at least 8 characters");
  if (!/[A-Z]/.test(pw)) tips.push("Add an uppercase letter");
  if (!/[a-z]/.test(pw)) tips.push("Add a lowercase letter");
  if (!/[0-9]/.test(pw)) tips.push("Add a number");
  if (!/[^a-zA-Z0-9]/.test(pw)) tips.push("Add a symbol (e.g. ! @ # $)");
  if (isCommon) tips.push("This is a extremely common password — avoid it");
  if (sequential) tips.push("Avoid sequences like \"abc\" or \"123\"");
  if (repeated) tips.push("Avoid repeating the same character 3+ times");
  if (containsContext) tips.push("Avoid using your name or email in the password");

  let score;
  if (isCommon || bits < 20) score = 0;
  else if (bits < 35) score = 1;
  else if (bits < 50) score = 2;
  else if (bits < 65) score = 3;
  else score = 4;

  const labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
  return { score, label: labels[score], bits: Math.round(bits), tips: tips.slice(0, 2) };
}

function wireStrengthMeter(inputEl, opts = {}) {
  const barWrap = document.createElement("div");
  barWrap.className = "strength-meter";
  barWrap.innerHTML = `
    <div class="strength-bar">
      <div class="seg"></div><div class="seg"></div><div class="seg"></div><div class="seg"></div>
    </div>
    <div class="strength-label"><span class="strength-text">&nbsp;</span><span class="strength-bits"></span></div>
    <div class="strength-tips"></div>
  `;
  inputEl.insertAdjacentElement("afterend", barWrap);
  const segs = barWrap.querySelectorAll(".seg");
  const textEl = barWrap.querySelector(".strength-text");
  const bitsEl = barWrap.querySelector(".strength-bits");
  const tipsEl = barWrap.querySelector(".strength-tips");
  const colors = ["#e74c3c", "#e67e22", "#f5a623", "#2ecc71", "#27d980"];

  function update() {
    const contextInputs = (opts.contextSelectors || []).map((sel) => {
      const el = document.querySelector(sel);
      return el ? el.value : "";
    });
    const result = analyzePassword(inputEl.value, contextInputs);
    segs.forEach((seg, i) => {
      seg.style.background = i < result.score + (result.score === 0 && inputEl.value ? 1 : 0) && inputEl.value
        ? colors[result.score]
        : "";
    });
    if (!inputEl.value) {
      segs.forEach((seg) => (seg.style.background = ""));
      textEl.textContent = " ";
      bitsEl.textContent = "";
      tipsEl.textContent = "";
      return;
    }
    textEl.textContent = result.label;
    textEl.style.color = colors[result.score];
    bitsEl.textContent = `~${result.bits} bits`;
    tipsEl.textContent = result.tips.join(" · ");
  }

  inputEl.addEventListener("input", update);
  (opts.contextSelectors || []).forEach((sel) => {
    const el = document.querySelector(sel);
    if (el) el.addEventListener("input", update);
  });
  update();
}
