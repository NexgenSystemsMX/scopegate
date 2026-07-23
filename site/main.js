/* ScopeGate landing — interactive pieces (dependency-free, defer).
 * Everything on the page is readable without JS; this file only adds motion.
 * All animation is disabled under prefers-reduced-motion.
 */
"use strict";

const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const $ = (sel) => document.querySelector(sel);

/* ------------------------------------------------------------------ */
/* Before/After toggle (problem section)                               */
/* ------------------------------------------------------------------ */

(function beforeAfter() {
  const root = $("#before-after");
  if (!root) return;
  const btns = root.querySelectorAll(".ba-btn");
  const panels = root.querySelectorAll("[data-ba-panel]");
  btns.forEach((btn) => {
    btn.addEventListener("click", () => {
      btns.forEach((b) => {
        b.classList.toggle("active", b === btn);
        b.setAttribute("aria-selected", b === btn ? "true" : "false");
      });
      panels.forEach((p) => {
        const show = p.getAttribute("data-ba-panel") === btn.getAttribute("data-ba");
        p.classList.toggle("hidden", !show);
        if (show && !REDUCED) {
          p.classList.remove("ba-enter");
          void p.offsetWidth; // restart the transition
          p.classList.add("ba-enter");
        }
      });
    });
  });
})();

/* ------------------------------------------------------------------ */
/* Live TTL grant demo                                                 */
/* ------------------------------------------------------------------ */

(function ttlDemo() {
  const fill = $("#ttl-fill");
  const count = $("#ttl-count");
  const state = $("#ttl-state");
  if (!fill || !count || !state) return;

  const TOTAL = 60;
  let remaining = TOTAL;

  if (REDUCED) {
    count.textContent = "60s → 0s";
    state.textContent = "grants expire by construction";
    return;
  }

  function tick() {
    remaining -= 1;
    if (remaining <= 0) {
      state.textContent = "expired — worthless now";
      fill.style.width = "0%";
      count.textContent = "0s";
      remaining = TOTAL;
      setTimeout(() => {
        state.textContent = "granted · minted by the policy engine";
        tick();
      }, 1600);
      return;
    }
    count.textContent = remaining + "s";
    fill.style.width = (remaining / TOTAL) * 100 + "%";
    fill.classList.toggle("low", remaining <= 10);
    setTimeout(tick, 1000);
  }
  tick();
})();

/* ------------------------------------------------------------------ */
/* Terminal typing animation                                           */
/* ------------------------------------------------------------------ */

(function terminal() {
  const body = $("#term-body");
  const replay = $("#term-replay");
  if (!body) return;

  const FULL = body.textContent;
  if (REDUCED) return; // full text stays visible, no typing

  let timer = null;
  let played = false;

  function play() {
    if (timer) { clearTimeout(timer); timer = null; }
    body.textContent = "";
    const lines = FULL.split("\n");
    let li = 0, ci = 0;
    const cursor = document.createElement("span");
    cursor.className = "term-cursor";
    cursor.textContent = "▌";

    function step() {
      if (li >= lines.length) {
        body.appendChild(cursor);
        timer = null;
        return;
      }
      const line = lines[li];
      // Output lines (non-$) appear instantly; command lines type char by char.
      const isCmd = line.startsWith("$") || line.startsWith(">");
      if (!isCmd) {
        body.appendChild(document.createTextNode(line + "\n"));
        li++;
        timer = setTimeout(step, line.trim() === "" ? 500 : 260);
        return;
      }
      if (ci === 0) body.appendChild(document.createTextNode(""));
      if (ci < line.length) {
        body.appendChild(document.createTextNode(line[ci]));
        ci++;
        timer = setTimeout(step, 26 + Math.random() * 30);
      } else {
        body.appendChild(document.createTextNode("\n"));
        li++;
        ci = 0;
        timer = setTimeout(step, 420);
      }
    }
    step();
  }

  // Auto-play the first time the terminal scrolls into view.
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (e.isIntersecting && !played) {
        played = true;
        play();
        io.disconnect();
      }
    }
  }, { threshold: 0.4 });
  io.observe(body);

  if (replay) {
    replay.addEventListener("click", () => {
      played = true;
      play();
    });
  }
})();

/* ------------------------------------------------------------------ */
/* Live control-plane health badge                                     */
/* ------------------------------------------------------------------ */

(function health() {
  const text = $("#health-text");
  const dot = $("#health-dot");
  if (!text || !dot) return;
  fetch("/health", { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error("bad status"))))
    .then((data) => {
      if (data && data.status === "ok") {
        text.textContent = "control plane: online";
        dot.classList.add("on");
      } else {
        throw new Error("not ok");
      }
    })
    .catch(() => {
      text.textContent = "control plane: unreachable";
      dot.classList.add("off");
    });
})();
