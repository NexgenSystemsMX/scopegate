#!/usr/bin/env node
/**
 * build-docs-html.mjs — render the markdown docs to static HTML under
 * site/docs/ (SEO: crawlable on scopegate.io/docs), copy the raw .md sources
 * (GEO: text/markdown for AI crawlers), and regenerate site/sitemap.xml.
 *
 *   node scripts/build-docs-html.mjs          # write output
 *   node scripts/build-docs-html.mjs --check  # fail (1) if output would differ
 *
 * Sources:
 *   docs-site/*.md   → site/docs/<slug>.html        (collection "Docs")
 *   docs/agents/*.md → site/docs/agents/<slug>.html (collection "Agent guides")
 * Slug = filename without .md; index.md / README.md become the directory index.
 *
 * The converter intentionally supports only the markdown subset the docs
 * actually use (verified by inspection): headings #-####, fenced code with
 * language, tables, single-level ul/ol, task lists, blockquotes, hr, inline
 * code/bold/links. Everything is HTML-escaped first — no raw HTML passes.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const SITE = path.join(ROOT, "site");
const ORIGIN = "https://scopegate.io";
const GITHUB_BLOB = "https://github.com/NexgenSystemsMX/scopegate/blob/master/";
const CHECK = process.argv.includes("--check");
const TODAY = new Date().toISOString().slice(0, 10);

/* ------------------------------------------------------------------ */
/* markdown subset → html                                              */
/* ------------------------------------------------------------------ */

function esc(s) {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/** Inline markup: `code`, **bold**, [text](url). Input is already escaped. */
function inline(escaped, linkRewrite) {
  let out = escaped;
  // [text](url) — before code spans would break links containing backticks,
  // but the docs never nest those; keep the simple order: links, code, bold.
  out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, text, url) => {
    const href = linkRewrite(url);
    return `<a href="${esc(href)}">${text}</a>`;
  });
  out = out.replace(/`([^`]+)`/g, "<code>$1</code>");
  out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  out = out.replace(/(?<!\w)\*([^*\n]+)\*(?!\w)/g, "<em>$1</em>");
  return out;
}

/**
 * Convert one markdown document. `linkRewrite(url)` maps relative .md links
 * to site routes (and ../ paths to GitHub).
 */
export function mdToHtml(md, linkRewrite) {
  const lines = md.split("\n");
  const html = [];
  let i = 0;
  let firstPara = null;

  const isTableLine = (l) => l.trim().startsWith("|") && l.trim().endsWith("|");

  while (i < lines.length) {
    const line = lines[i];

    // fenced code
    const fence = line.match(/^```([a-zA-Z0-9_-]*)\s*$/);
    if (fence) {
      const lang = fence[1] || "";
      const buf = [];
      i++;
      while (i < lines.length && !/^```\s*$/.test(lines[i])) buf.push(lines[i++]);
      i++; // closing fence
      html.push(
        `<pre class="code"${lang ? ` data-lang="${esc(lang)}"` : ""}><code>${esc(buf.join("\n"))}</code></pre>`,
      );
      continue;
    }

    // headings
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      const level = h[1].length;
      const text = inline(esc(h[2].trim()), linkRewrite);
      const id = h[2].trim().toLowerCase().replace(/`([^`]+)`/g, "$1")
        .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
      html.push(`<h${level} id="${id}">${text}</h${level}>`);
      i++;
      continue;
    }

    // hr
    if (/^---+\s*$/.test(line.trim())) { html.push("<hr>"); i++; continue; }

    // table
    if (isTableLine(line) && i + 1 < lines.length && /^\|[\s:|-]+\|$/.test(lines[i + 1].trim())) {
      const splitRow = (l) => l.trim().slice(1, -1).split("|").map((c) => c.trim());
      const header = splitRow(line);
      i += 2; // header + separator
      const rows = [];
      while (i < lines.length && isTableLine(lines[i])) rows.push(splitRow(lines[i++]));
      html.push(
        "<table><thead><tr>" +
          header.map((c) => `<th>${inline(esc(c), linkRewrite)}</th>`).join("") +
          "</tr></thead><tbody>" +
          rows.map((r) => "<tr>" + r.map((c) => `<td>${inline(esc(c), linkRewrite)}</td>`).join("") + "</tr>").join("") +
          "</tbody></table>",
      );
      continue;
    }

    // blockquote
    if (/^>\s?/.test(line)) {
      const buf = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) buf.push(lines[i++].replace(/^>\s?/, ""));
      html.push(`<blockquote>${inline(esc(buf.join(" ")), linkRewrite)}</blockquote>`);
      continue;
    }

    // lists (single level; task items get a glyph)
    if (/^- /.test(line)) {
      const items = [];
      while (i < lines.length && /^- /.test(lines[i])) items.push(lines[i++].slice(2));
      html.push(
        "<ul>" +
          items.map((it) => {
            const task = it.match(/^\[([ xX])\]\s+(.*)$/);
            const body = task ? `${task[1].trim() ? "☑" : "☐"} ${task[2]}` : it;
            return `<li>${inline(esc(body), linkRewrite)}</li>`;
          }).join("") +
          "</ul>",
      );
      continue;
    }
    if (/^\d+\.\s/.test(line)) {
      const items = [];
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) items.push(lines[i++].replace(/^\d+\.\s/, ""));
      html.push("<ol>" + items.map((it) => `<li>${inline(esc(it), linkRewrite)}</li>`).join("") + "</ol>");
      continue;
    }

    // paragraph (accumulate until blank/structural line)
    if (line.trim().length > 0) {
      const buf = [];
      while (
        i < lines.length &&
        lines[i].trim().length > 0 &&
        !/^(#{1,4}\s|```|>|- |\d+\.\s|\|)/.test(lines[i]) &&
        !/^---+\s*$/.test(lines[i].trim())
      ) {
        buf.push(lines[i++]);
      }
      const text = inline(esc(buf.join(" ")), linkRewrite);
      if (firstPara === null) firstPara = buf.join(" ");
      html.push(`<p>${text}</p>`);
      continue;
    }

    i++; // blank line
  }

  return { html: html.join("\n"), firstPara: firstPara ?? "" };
}

/* ------------------------------------------------------------------ */
/* collections & routing                                               */
/* ------------------------------------------------------------------ */

function slugFor(file) {
  const base = path.basename(file, ".md");
  return base; // index/README handled by caller as directory index
}

/** Relative .md link → site route; ../ paths → GitHub blob. */
function makeLinkRewrite(fromDir, toRouteDir) {
  return (url) => {
    if (/^https?:\/\//.test(url) || url.startsWith("#") || url.startsWith("mailto:")) return url;
    if (url.endsWith(".md") || url.includes(".md#")) {
      const [file, hash] = url.split("#");
      const abs = path.normalize(path.join(fromDir, file));
      // Same collection?
      const relToRoot = path.relative(ROOT, abs).replace(/\\/g, "/");
      if (relToRoot.startsWith("docs-site/")) {
        const slug = slugFor(abs);
        return (slug === "index" ? "/docs/" : `/docs/${slug}`) + (hash ? `#${hash}` : "");
      }
      if (relToRoot.startsWith("docs/agents/")) {
        const slug = slugFor(abs);
        return (slug === "README" ? "/docs/agents/" : `/docs/agents/${slug}`) + (hash ? `#${hash}` : "");
      }
      return GITHUB_BLOB + relToRoot + (hash ? `#${hash}` : "");
    }
    if (url.startsWith(".") || url.startsWith("/")) {
      const abs = path.normalize(path.join(fromDir, url));
      const relToRoot = path.relative(ROOT, abs).replace(/\\/g, "/");
      if (!relToRoot.startsWith("..")) return GITHUB_BLOB + relToRoot;
    }
    return url;
  };
}

/* ------------------------------------------------------------------ */
/* html shell                                                          */
/* ------------------------------------------------------------------ */

function pageShell({ title, description, canonical, breadcrumb, body, prevNext }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — ScopeGate Docs</title>
<meta name="description" content="${esc(description.slice(0, 160))}">
<link rel="canonical" href="${ORIGIN}${canonical}">
<meta property="og:title" content="${esc(title)} — ScopeGate Docs">
<meta property="og:description" content="${esc(description.slice(0, 160))}">
<meta property="og:type" content="article">
<meta property="og:url" content="${ORIGIN}${canonical}">
<meta property="og:image" content="${ORIGIN}/og.png">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/styles.css">
</head>
<body>
<nav class="nav">
  <div class="wrap nav-inner">
    <a class="brand" href="/">
      <img src="/favicon.svg" alt="" width="22" height="22">
      <span>ScopeGate</span>
    </a>
    <input type="checkbox" id="nav-toggle" class="nav-toggle">
    <label for="nav-toggle" class="nav-burger" aria-label="Menu">☰</label>
    <div class="nav-links">
      <a href="/#how-it-works">How it works</a>
      <a href="/#features">Features</a>
      <a href="/#pricing">Pricing</a>
      <a href="/docs/" aria-current="page">Docs</a>
      <a href="https://github.com/NexgenSystemsMX/scopegate" rel="noopener">GitHub</a>
      <a class="btn btn-small" href="/#get-started">Get started</a>
    </div>
  </div>
</nav>
<main class="wrap doc">
  <nav class="breadcrumb" aria-label="Breadcrumb">${breadcrumb}</nav>
  <article>
${body}
  </article>
${prevNext ? `  <nav class="prevnext">${prevNext}</nav>` : ""}
</main>
<footer class="footer">
  <div class="wrap footer-inner">
    <div>
      <strong>ScopeGate</strong>
      <p class="dim">Ephemeral credentials &amp; persistent connections for coding agents.</p>
    </div>
    <div class="footer-links">
      <a href="https://github.com/NexgenSystemsMX/scopegate" rel="noopener">GitHub</a>
      <a href="https://www.npmjs.com/package/scopegate" rel="noopener">npm</a>
      <a href="/docs/">Documentation</a>
      <a href="/panel">Cloud panel</a>
      <a href="https://github.com/NexgenSystemsMX/scopegate/blob/master/LICENSE" rel="noopener">Apache-2.0</a>
    </div>
  </div>
</footer>
</body>
</html>
`;
}

function crumb(parts) {
  return parts
    .map((p, i) =>
      i < parts.length - 1
        ? `<a href="${p.href}">${esc(p.label)}</a><span class="sep">/</span>`
        : `<span>${esc(p.label)}</span>`,
    )
    .join("");
}

function prevNextHtml(prev, next) {
  const l = prev ? `<a class="prev" href="${prev.href}">← ${esc(prev.title)}</a>` : "<span></span>";
  const r = next ? `<a class="next" href="${next.href}">${esc(next.title)} →</a>` : "<span></span>";
  return l + r;
}

/* ------------------------------------------------------------------ */
/* build                                                               */
/* ------------------------------------------------------------------ */

function titleOf(md, fallback) {
  const m = md.match(/^#\s+(.+)$/m);
  return m ? m[1].replace(/`([^`]+)`/g, "$1").trim() : fallback;
}

/** Strip inline markdown for the meta description. */
function plain(s) {
  return s
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\s+/g, " ")
    .trim();
}

const AGENT_ORDER = [
  "01-quickstart-self-install",
  "02-protocol",
  "03-tools-reference",
  "04-connectors",
  "05-policies",
  "06-self-repair",
  "07-security-rules",
];
const DOCS_SITE_ORDER = ["quickstart", "security-model", "agent-protocol", "cli-reference", "configuration"];

function collect() {
  const pages = [];

  // docs-site collection
  const dsDir = path.join(ROOT, "docs-site");
  for (const file of fs.readdirSync(dsDir).filter((f) => f.endsWith(".md")).sort()) {
    const full = path.join(dsDir, file);
    const md = fs.readFileSync(full, "utf8");
    const slug = slugFor(file);
    const isIndex = slug === "index";
    pages.push({
      src: full,
      md,
      collection: "Docs",
      route: isIndex ? "/docs/" : `/docs/${slug}`,
      outHtml: isIndex ? path.join("docs", "index.html") : path.join("docs", `${slug}.html`),
      outMd: path.join("docs", file),
      title: titleOf(md, "Documentation"),
      isIndex,
    });
  }

  // agent guides collection
  const agDir = path.join(ROOT, "docs", "agents");
  for (const file of fs.readdirSync(agDir).filter((f) => f.endsWith(".md")).sort()) {
    const full = path.join(agDir, file);
    const md = fs.readFileSync(full, "utf8");
    const slug = slugFor(file);
    const isIndex = slug === "README";
    pages.push({
      src: full,
      md,
      collection: "Agent guides",
      route: isIndex ? "/docs/agents/" : `/docs/agents/${slug}`,
      outHtml: isIndex ? path.join("docs", "agents", "index.html") : path.join("docs", "agents", `${slug}.html`),
      outMd: path.join("docs", "agents", file),
      title: titleOf(md, "Agent guide"),
      isIndex,
    });
  }
  return pages;
}

function build() {
  const pages = collect();
  const outputs = new Map(); // relative output path → content

  for (const page of pages) {
    const linkRewrite = makeLinkRewrite(path.dirname(page.src), "");
    const { html, firstPara } = mdToHtml(page.md, linkRewrite);
    const description = plain(firstPara) || `${page.title} — ScopeGate documentation`;

    // prev/next within ordered collections
    let pn = "";
    const order = page.collection === "Agent guides" ? AGENT_ORDER : DOCS_SITE_ORDER;
    const slug = path.basename(page.src, ".md");
    const idx = order.indexOf(slug);
    if (idx >= 0) {
      const nav = (s) => {
        if (!s) return null;
        const target = pages.find((p) => path.basename(p.src, ".md") === s);
        return target ? { href: target.route, title: target.title } : null;
      };
      pn = prevNextHtml(nav(order[idx - 1]), nav(order[idx + 1]));
    }

    outputs.set(page.outHtml, pageShell({
      title: page.title,
      description,
      canonical: page.route,
      breadcrumb: crumb([
        { label: "ScopeGate", href: "/" },
        { label: "Docs", href: "/docs/" },
        ...(page.collection === "Agent guides" ? [{ label: "Agent guides", href: "/docs/agents/" }] : []),
        ...(page.isIndex ? [] : [{ label: page.title }]),
      ].filter((p, i, arr) => i < 2 || page.collection !== "Docs" || true)),
      body: html,
      prevNext: pn,
    }));
    // raw markdown copy (GEO: AI crawlers consume text/markdown directly)
    outputs.set(page.outMd, page.md);
  }

  // sitemap.xml — the single source of truth for public URLs.
  const docUrls = pages.map((p) => p.route);
  const urls = [
    { loc: "/", priority: "1.0", changefreq: "weekly" },
    ...docUrls.map((r) => ({
      loc: r,
      priority: r === "/docs/" ? "0.9" : "0.8",
      changefreq: "monthly",
    })),
  ];
  const sitemap =
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
    urls
      .map(
        (u) =>
          `  <url><loc>${ORIGIN}${u.loc}</loc><lastmod>${TODAY}</lastmod>` +
          `<changefreq>${u.changefreq}</changefreq><priority>${u.priority}</priority></url>`,
      )
      .join("\n") +
    `\n</urlset>\n`;
  outputs.set(path.join("sitemap.xml"), sitemap);

  return outputs;
}

function main() {
  const outputs = build();
  const diffs = [];
  for (const [rel, content] of outputs) {
    const dest = path.join(SITE, rel);
    const existing = fs.existsSync(dest) ? fs.readFileSync(dest, "utf8") : null;
    if (existing !== content) diffs.push(rel);
    if (!CHECK) {
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, content);
    }
  }
  if (CHECK) {
    // Also flag stale files that would no longer be generated.
    if (diffs.length > 0) {
      console.error(`build-docs-html --check FAILED: ${diffs.length} file(s) out of date:`);
      for (const d of diffs) console.error(`  - ${d}`);
      process.exit(1);
    }
    console.log(`build-docs-html --check OK (${outputs.size} files up to date)`);
    return;
  }
  console.log(`wrote ${outputs.size} files under site/ (${[...outputs.keys()].length} total):`);
  for (const rel of outputs.keys()) console.log(`  - ${rel}`);
}

main();
