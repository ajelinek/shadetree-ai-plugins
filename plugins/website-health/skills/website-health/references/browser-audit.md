# Browser audit (no account)

Use when the user wants a real-browser view: performance as a visitor experiences it,
accessibility problems only a rendered page shows, or whether the page works without
JavaScript. Needs a browser tool (the claude-in-chrome tools or the `playwright-cli`
skill). Everything here is read-only and leaves nothing on the site; only audit the
configured site or one the user owns.

## 1. Load and look
1. Open the page at 375x812 (phone) and 1366x768 (desktop). Take a screenshot of each.
2. Read console messages (errors and warnings) and the network log: report failed
   requests (4xx/5xx), blocked mixed content, and CORS/CSP errors.
3. Note anything visibly broken: overlapping text, cut-off content, a cookie banner that
   covers the page, horizontal scroll on the phone width.

## 2. Performance snapshot
Run this in the page (javascript tool) after load. It is one unthrottled run on the user's
machine and network: directional, not a Lighthouse score. Repeat twice and use the second
(warm DNS and TLS).

```js
(async () => {
  const nav = performance.getEntriesByType('navigation')[0];
  const res = performance.getEntriesByType('resource');
  const lcp = await new Promise(r => new PerformanceObserver(l => r(l.getEntries().at(-1)))
    .observe({ type: 'largest-contentful-paint', buffered: true }));
  let cls = 0;
  await new Promise(r => { new PerformanceObserver(l => { for (const e of l.getEntries())
    if (!e.hadRecentInput) cls += e.value; r(); })
    .observe({ type: 'layout-shift', buffered: true }); setTimeout(r, 300); });
  return { ttfbMs: Math.round(nav.responseStart), loadMs: Math.round(nav.loadEventEnd),
    lcpMs: Math.round(lcp.startTime), lcpElement: lcp.element?.outerHTML.slice(0, 140),
    cls: +cls.toFixed(3), requests: res.length,
    transferKB: Math.round(res.reduce((a, e) => a + e.transferSize, 0) / 1024),
    hosts: [...new Set(res.map(e => new URL(e.name).host))].length,
    slowest: [...res].sort((a, b) => b.duration - a.duration).slice(0, 5)
      .map(e => [e.name.slice(0, 90), Math.round(e.duration)]) };
})()
```

Read it against web.dev thresholds: LCP good at 2500 ms or less, CLS 0.1 or less, TTFB 800 ms
or less. `lcpElement` tells you what to optimize (preload it, don't lazy-load it, size it).
`slowest` and `transferKB` point at heavy files and third parties.

## 3. Accessibility (axe-core)
Inject a pinned build into the page for this session only, run it, and summarize violations
by rule with a count and one example selector each:

```js
await new Promise((ok, no) => { const s = document.createElement('script');
  s.src = 'https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.10.2/axe.min.js';
  s.onload = ok; s.onerror = no; document.head.appendChild(s); });
const r = await axe.run(); r.violations.map(v => [v.id, v.impact, v.nodes.length,
  v.nodes[0].target.join(' ')]);
```
If a Content-Security-Policy blocks the injection, say so and rely on the Lighthouse
accessibility score instead. Automated checks catch only part of accessibility: also tab
through the page and confirm a visible focus ring and a logical order.

## 4. Raw versus rendered
`audit_site` reads raw HTML, as most AI crawlers do. Compare it with the rendered DOM
(`document.title`, the `<h1>`, `link[rel=canonical]`, word count of `document.body.innerText`).
Content, a canonical, or JSON-LD that appears only after rendering is invisible to non-JS
crawlers: recommend server rendering.

## 5. Local Lighthouse (account-free alternative to PageSpeed)
With Node and Chrome installed, the user can run:
`npx lighthouse <url> --only-categories=performance,accessibility,seo,best-practices --output=json --output-path=lighthouse.json --chrome-flags="--headless"`
Read `categories.*.score`, `audits.largest-contentful-paint.numericValue`,
`audits.total-byte-weight` and the failing audits. This avoids Google's PageSpeed quota and
needs no key. Don't commit the report if it contains private URLs.
