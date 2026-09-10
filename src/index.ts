const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Vary': 'Accept-Encoding',
}

// Default toplist-edge URL — used if [vars] TOPLIST_EDGE is missing on an
// older site. New scaffolds set it explicitly in wrangler.toml.
const DEFAULT_TOPLIST_EDGE = 'https://toplist-edge.webtrico.com'

// Domain-based country detection mirrors what scaffold.ts uses for the
// placeholder HTML language. Used as a fallback when [vars] COUNTRY is unset
// (older sites that haven't been resynced yet).
const FRENCH_DOMAIN_HINT = /casino|meilleur|jeux|gratuit|bonus|machines|jackpot|roulette|blackjack|paris|en-ligne|argent|gain|.fr$/i

function detectCountry(env: { COUNTRY?: string }, hostname: string): 'IT' | 'FR' {
  const explicit = (env.COUNTRY ?? '').toUpperCase()
  if (explicit === 'IT' || explicit === 'FR') return explicit
  return FRENCH_DOMAIN_HINT.test(hostname) ? 'FR' : 'IT'
}

// FNV-1a → LCG → 6-char alphanum suffix. Same algorithm as
// toplist-edge's renderer so we can recognise the per-site logo prefix
// in incoming requests.
function fnv1a(s: string): number {
  let h = 0x811c9dc5
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return h >>> 0
}
function logoPrefixForDomain(domain: string): string {
  // Must match toplist-edge's render.ts classSuffix() exactly. Same alphabet,
  // same 'take then divide' loop, same fall-through when n hits 0.
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'
  let n = fnv1a((domain || '_').toLowerCase().trim())
  let out = ''
  for (let i = 0; i < 6; i++) {
    out += alphabet[n % alphabet.length]
    n = Math.floor(n / alphabet.length) || ((n + 17) >>> 0)
  }
  return out
}

// Fallback sitemap proxy. Used only when no static sitemap.xml exists.
// Returns homepage-only sitemap from toplist-edge.
async function handleSitemap(
  url: URL,
  env: { COUNTRY?: string; TOPLIST_EDGE?: string }
): Promise<Response> {
  const country = detectCountry(env, url.hostname)
  const edgeBase = (env.TOPLIST_EDGE ?? DEFAULT_TOPLIST_EDGE).replace(/\/+$/, '')
  const upstream = `${edgeBase}/sitemap/${country}?domain=${encodeURIComponent(url.hostname)}`
  let res: Response
  try {
    res = await fetch(upstream, { cf: { cacheTtl: 1200, cacheEverything: true } })
  } catch {
    return new Response('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"/>', {
      status: 200, headers: { 'Content-Type': 'application/xml' },
    })
  }
  if (!res.ok) {
    return new Response('Upstream error', { status: 502, headers: { 'Content-Type': 'text/plain' } })
  }
  const headers = new Headers()
  headers.set('Content-Type', 'application/xml; charset=utf-8')
  headers.set('Cache-Control', 'public, s-maxage=1200, stale-while-revalidate=2400')
  return new Response(res.body, { status: 200, headers })
}

// handleDirectory() and handleBrandPage() lived here. Both are gone; what
// replaces them is a tombstone — see the retirement note in fetch().
//
// 410 Gone, produced locally with no upstream fetch. Two reasons it has to
// be local: a proxied non-OK status would collapse to 502 ("try again
// later"), which keeps a page indexed indefinitely; and letting these paths
// fall through to the static 404 asset is a weaker signal that Google
// re-crawls for months. 410 is the one status that says "stop asking".
function handleRetiredPage(
  url: URL,
  env: { COUNTRY?: string }
): Response {
  const country = detectCountry(env, url.hostname)
  const copy = country === 'FR'
    ? { head: 'Page supprimée', body: "Cette page n'est plus disponible.", home: "Retour à l'accueil" }
    : { head: 'Pagina rimossa', body: 'Questa pagina non è più disponibile.', home: 'Torna alla home' }
  const html = '<!doctype html><html lang="' + (country === 'FR' ? 'fr' : 'it') + '">'
    + '<head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<meta name="robots" content="noindex,nofollow">'
    + '<title>' + copy.head + '</title>'
    + '<style>body{margin:0;min-height:100vh;display:flex;align-items:center;'
    + 'justify-content:center;background:#0f172a;color:#e2e8f0;'
    + 'font:16px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}'
    + 'main{max-width:32rem;padding:2rem;text-align:center}'
    + 'h1{font-size:1.5rem;margin:0 0 .75rem}'
    + 'p{margin:0 0 1.5rem;color:#94a3b8}a{color:#e2e8f0}</style>'
    + '</head><body><main><h1>' + copy.head + '</h1>'
    + '<p>' + copy.body + '</p>'
    + '<a href="/">' + copy.home + '</a></main></body></html>'
  const headers = new Headers()
  headers.set('Content-Type', 'text/html; charset=utf-8')
  // Short cache: a long-lived 410 would outlive any decision to bring a path
  // back for a single site.
  headers.set('Cache-Control', 'public, max-age=300')
  headers.set('X-Robots-Tag', 'noindex, nofollow')
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v)
  return new Response(html, { status: 410, headers })
}

// Proxy a brand logo through this site's own domain so the public URL is
// site-specific (not shared across EMD sites). The path looks like
// /_<6alphanum>/<slug> where the prefix is this domain's deterministic hash.
async function handleLogoProxy(
  url: URL,
  env: { COUNTRY?: string; TOPLIST_EDGE?: string },
  match: RegExpMatchArray
): Promise<Response> {
  const expectedPrefix = logoPrefixForDomain(url.hostname)
  // Reject any other prefix — keeps random scrapers from probing logos via
  // arbitrary paths and keeps the fingerprint surface domain-locked.
  if (match[1] !== expectedPrefix) {
    return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain' } })
  }
  const slug = match[2]!.toLowerCase()
  const country = detectCountry(env, url.hostname)
  const edgeBase = (env.TOPLIST_EDGE ?? DEFAULT_TOPLIST_EDGE).replace(/\/+$/, '')
  const upstream = `${edgeBase}/img/${country}/${encodeURIComponent(slug)}`
  let res: Response
  try {
    res = await fetch(upstream, { cf: { cacheTtl: 86400, cacheEverything: true } })
  } catch {
    return new Response('Upstream unavailable', { status: 502, headers: { 'Content-Type': 'text/plain' } })
  }
  if (!res.ok) {
    return new Response('Not found', { status: res.status === 404 ? 404 : 502, headers: { 'Content-Type': 'text/plain' } })
  }
  // Re-emit with our own caching headers — strip any CF-specific headers
  // that would expose the upstream (e.g. Server: cloudflare appears anyway,
  // but Cf-Cache-Status etc. don't need to bleed through).
  const headers = new Headers()
  headers.set('Content-Type', res.headers.get('Content-Type') ?? 'image/png')
  headers.set('Cache-Control', 'public, max-age=86400, must-revalidate')
  headers.set('X-Content-Type-Options', 'nosniff')
  return new Response(res.body, { status: 200, headers })
}

function withSecurityHeaders(response: Response, request?: Request): Response {
  const headers = new Headers(response.headers)
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v)
  if (request && (response.headers.get('Content-Type') ?? '').includes('text/html')) {
    const u = new URL(request.url)
    headers.set('Link', `<${u.origin}${u.pathname}>; rel="canonical"`)
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
}

// Inject a tiny, cache-proof beacon into every HTML page. It runs in the
// visitor's browser on EVERY view — even when Cloudflare serves cached HTML
// without invoking this worker — and pings the admin /beacon, which decides what
// the hit was. There is no CSP on these sites so the inline script runs; a
// text/plain body avoids a CORS preflight, and sendBeacon adds zero latency.
//
// It used to return early unless document.referrer named some OTHER host:
//
//   var r=document.referrer||"";if(!r)return;
//   ...if(h===location.hostname||h==="www."+location.hostname)return;
//
// which is right for a beacon that only counts organic entries, and that is what
// it was built as. But the server end was later widened to count every hit as a
// human page view whatever referred it — the comment there says so — and the
// client was never widened with it. So human_pageviews_daily has never held
// human page views. It holds first-pages-of-visits-that-arrived-from-elsewhere:
// no direct traffic, no bookmarks, no typed-in domain, no second page of any
// session, and nothing from a browser that strips the referrer. It is the only
// bot-free number Raptor has, it is labelled "People", and it has been reporting
// a fraction of them.
//
// The classification is the server's job and the server already does it: it
// screens for bots on cf signals the page cannot see, and it decides organic by
// matching the referrer against a list of search engines. Sending every view
// gives it something to classify; withholding views could only ever undercount.
// Where this site's beacon posts: same origin, on a path derived from the apex
// host so no two sites share one. Normalised through apexHost because the page
// and this worker must agree on it, or the site stops being counted in silence.
function apexHost(host: string): string {
  return host.indexOf('www.') === 0 ? host.slice(4) : host
}
function beaconPath(host: string): string {
  const h = apexHost(host)
  let x = 2166136261
  for (let i = 0; i < h.length; i++) { x = Math.imul(x ^ h.charCodeAt(i), 16777619) }
  return '/' + (x >>> 0).toString(16).padStart(8, '0')
}

// Take the hit, judge it here, forward it server-side. The bot verdict has to
// be made at this edge - it is the only place the visitor's own cf signals
// exist. Always 204, always immediately: a page never waits on analytics.
async function handleBeaconHit(request: Request, url: URL, env: Env, ctx: ExecutionContext): Promise<Response> {
  const ok = new Response(null, { status: 204 })
  if (isBotRequest(request)) return ok
  let hit: { r?: unknown; s?: unknown } | null = null
  try { hit = await request.json() } catch { hit = null }
  const admin = (env.TOPLIST_ADMIN ?? DEFAULT_TOPLIST_ADMIN).replace(/\/+$/, '')
  const body = JSON.stringify({
    domain: apexHost(url.hostname),
    referer: typeof hit?.r === 'string' ? hit.r.slice(0, 300) : '',
    // s is the page's answer to "is this the first view of a session". Sent as
    // a boolean so the admin never has to guess what a missing field meant.
    visit: hit?.s === 1,
    country: request.headers.get('CF-IPCountry') ?? '',
  })
  ctx.waitUntil(
    fetch(admin + '/beacon', {
      method: 'POST',
      // Never follow a redirect. The admin answers a beacon with 2xx or an
      // error; anything else is a doorway, and following it turns the 302
      // Cloudflare Access puts in front of /beacon into a cheerful 200 for a
      // login page. That is precisely how six days of traffic reporting went
      // missing while every hit was being thrown away.
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': request.headers.get('User-Agent') ?? '',
        // This hit was already filtered at the edge, against the visitor's own
        // request, by isBotRequest above. The admin repeats the User-Agent half
        // of that check and skips the Cloudflare-signal half, which on THIS
        // request describes this worker in a datacentre rather than the person.
        'X-Beacon-Edge': '1',
      },
      body,
    })
      .then(function (res) {
        if (!res.ok) console.warn('beacon forward rejected by ' + admin + ': HTTP ' + res.status)
      })
      .catch(function (e) {
        console.warn('beacon forward failed: ' + ((e && e.message) ? e.message : String(e)))
      })
  )
  return ok
}

// Inject the beacon into every HTML page. It fires on EVERY view, even when
// Cloudflare serves cached HTML without invoking this worker. Sends the referrer
// for the admin to classify, and s: whether this is the first view of a session,
// which is the difference between page views and visits. sessionStorage never
// leaves the browser; when it is blocked the referrer stands in.
function injectBeacon(response: Response, url: URL, env: { TOPLIST_ADMIN?: string }): Response {
  const ct = response.headers.get('Content-Type') ?? ''
  if (!ct.includes('text/html')) return response
  const s = '<script>(function(){try{var v=1;try{if(sessionStorage.getItem("_s"))v=0;else sessionStorage.setItem("_s","1")}catch(e){v=document.referrer.indexOf(location.host)<0?1:0}var p=JSON.stringify({r:document.referrer||"",s:v});navigator.sendBeacon("' + beaconPath(url.hostname) + '",new Blob([p],{type:"text/plain"}));}catch(e){}})();</script>'
  return new HTMLRewriter().on('body', { element(el) { el.append(s, { html: true }) } }).transform(response)
}

// Inject the server-rendered toplist into any element with a [data-toplist]
// attribute. The element's existing contents are REPLACED with the fragment.
// Optional [data-toplist="IT|FR"] overrides the country detection.
// Optional [data-toplist-theme="light|dark"] controls colour scheme.
//
// SEOs author pages with: <div data-toplist></div> (or with explicit country)
// and the toplist appears server-side. Output is per-domain randomised by
// toplist-edge so this site's HTML doesn't fingerprint with sibling sites.
async function injectToplist(
  response: Response,
  request: Request,
  env: { COUNTRY?: string; TOPLIST_EDGE?: string; TOPLIST_EXCLUDE_SLUGS?: string }
): Promise<Response> {
  const ct = response.headers.get('Content-Type') ?? ''
  if (!ct.includes('text/html')) return response

  const url = new URL(request.url)
  const hostname = url.hostname
  const edgeBase = (env.TOPLIST_EDGE ?? DEFAULT_TOPLIST_EDGE).replace(/\/+$/, '')

  // Cache the rendered fragment per (country, theme, exclude, limit) so
  // multiple [data-toplist] elements on one page only fetch once per
  // unique combo.
  const cache = new Map<string, string>()
  async function fetchFragment(country: string, theme: string, exclude: string, limit: string): Promise<string> {
    const key = country + '|' + theme + '|' + exclude + '|' + limit
    const hit = cache.get(key)
    if (hit !== undefined) return hit
    let renderUrl = `${edgeBase}/render/${country}?domain=${encodeURIComponent(hostname)}&theme=${theme}`
    if (exclude) renderUrl += `&exclude=${encodeURIComponent(exclude)}`
    if (limit) renderUrl += `&limit=${encodeURIComponent(limit)}`
    try {
      const r = await fetch(renderUrl, { cf: { cacheTtl: 300, cacheEverything: true } })
      if (!r.ok) { cache.set(key, ''); return '' }
      const html = await r.text()
      cache.set(key, html)
      return html
    } catch {
      cache.set(key, '')
      return ''
    }
  }

  // Default exclude list comes from the site's wrangler.toml. Page-level
  // [data-toplist-exclude] overrides it.
  const defaultExclude = (env.TOPLIST_EXCLUDE_SLUGS ?? '').trim()

  // Country precedence (most specific wins):
  //   1. data-toplist="IT" or "FR" attribute on the placeholder
  //   2. <html lang="it"/"fr"> on the page being served
  //   3. env.COUNTRY in the site's wrangler.toml
  //   4. domain heuristic (FRENCH_DOMAIN_HINT regex)
  // We capture (2) here in a closure so the placeholder handler can read it.
  let pageLang: 'IT' | 'FR' | null = null

  return new HTMLRewriter()
    .on('html', {
      element(el) {
        const lang = (el.getAttribute('lang') ?? '').toLowerCase().split('-')[0]
        if (lang === 'it') pageLang = 'IT'
        else if (lang === 'fr') pageLang = 'FR'
      },
    })
    .on('[data-toplist]', {
      async element(el) {
        const explicit = (el.getAttribute('data-toplist') ?? '').toUpperCase()
        let country: 'IT' | 'FR'
        if (explicit === 'IT' || explicit === 'FR') country = explicit
        else if (pageLang) country = pageLang
        else country = detectCountry(env, hostname)
        const theme = el.getAttribute('data-toplist-theme') === 'light' ? 'light' : 'dark'
        const pageExclude = el.getAttribute('data-toplist-exclude')
        const exclude = (pageExclude ?? defaultExclude).trim()
        // Optional cap: data-toplist-limit="5" renders top 5 instead of 10.
        // Validated to a 1..10 integer; ignored if invalid or unset.
        const rawLimit = el.getAttribute('data-toplist-limit') ?? ''
        const limit = /^([1-9]|10)$/.test(rawLimit) ? rawLimit : ''
        const fragment = await fetchFragment(country, theme, exclude, limit)
        if (fragment) {
          el.setInnerContent(fragment, { html: true })
        }
        // If fetch failed, leave the element untouched — SEO can author a
        // text fallback inside the placeholder if they want.
      },
    })
    .transform(response)
}

// Resolve /go/:slug → 302 redirect to the brand's affiliate URL. Looks up the
// brand on toplist-edge; relies on Cloudflare's edge cache so we don't hit
// toplist-edge for every click after the first. After resolving, fires a
// fire-and-forget POST to /api/click so the brand's click count updates in
// the admin without slowing the redirect.
async function handleCloak(
  request: Request,
  url: URL,
  env: { COUNTRY?: string; TOPLIST_EDGE?: string },
  ctx: { waitUntil(p: Promise<unknown>): void }
): Promise<Response> {
  const cloakPrefix = ['/vai/', '/aller/', '/go/'].find(p => url.pathname.startsWith(p)) ?? '/go/'
  const slug = url.pathname.slice(cloakPrefix.length).toLowerCase().replace(/\/+$/, '')
  if (!/^[a-z0-9-]+$/.test(slug)) {
    return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain' } })
  }
  // The cloak prefix already states the market: /vai/ is always Italian and
  // /aller/ always French. Only the generic /go/ needs the env/domain
  // heuristic, which is wrong often enough to send a brand link to the
  // wrong country's affiliate URL. (Template string: no backticks here.)
  const country = cloakPrefix === '/vai/' ? 'IT' : cloakPrefix === '/aller/' ? 'FR' : detectCountry(env, url.hostname)
  const edgeBase = (env.TOPLIST_EDGE ?? DEFAULT_TOPLIST_EDGE).replace(/\/+$/, '')
  const lookup = `${edgeBase}/api/brand/${country}/${slug}`

  let brandRes: Response
  try {
    brandRes = await fetch(lookup, {
      // Cache the lookup at the colocation cache. CF picks the longer of
      // toplist-edge's own Cache-Control header and our cf.cacheTtl.
      cf: { cacheTtl: 300, cacheEverything: true },
    })
  } catch {
    return new Response('Upstream unavailable', { status: 502, headers: { 'Content-Type': 'text/plain' } })
  }
  if (!brandRes.ok) {
    return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain' } })
  }
  const data = await brandRes.json<{ brand?: { affiliate_url?: string } }>()
  const target = data.brand?.affiliate_url
  if (!target) {
    return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain' } })
  }

  // Append tracking params from the incoming /go URL onto the affiliate
  // URL. Allowlisted to standard UTM + the most common affiliate
  // sub-id keys; everything else is dropped so attackers can't smuggle
  // arbitrary garbage through to the partner's landing page.
  //
  // We also stamp subid = this site's own host so the affiliate network can
  // report conversions back per source site (powering REAL per-site/per-owner
  // attribution instead of estimates). The visitor's own subid, if any, wins.
  const trackedTarget = appendTrackingParams(target, url.searchParams, url.hostname)

  // Log the click without blocking the user's redirect. Failures are
  // swallowed — analytics gaps are acceptable; a slow redirect is not.
  //
  // Bots are redirected exactly like anyone else, they just aren't logged.
  // This check has to live HERE, not on the edge: logClick is a server-to-
  // server fetch, so by the time it reaches /api/click the visitor's
  // User-Agent and cf bot signals are gone and only ua_hash survives. This is
  // the last point that still sees the real visitor request.
  if (!isBotRequest(request)) {
    ctx.waitUntil(logClick(edgeBase, request, url, country, slug))
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: trackedTarget,
      // Don't let the redirect itself be cached — sales must be able to
      // change an affiliate URL and have new clicks pick it up.
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Robots-Tag': 'noindex, nofollow',
    },
  })
}

const TRACKING_KEYS = new Set([
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
  'subid', 'sub_id', 'clickid', 'click_id', 'aff_sub', 'aff_sub2', 'aff_sub3',
  'gclid', 'fbclid',
])

// The query key the affiliate network reads as the source identifier. ReferOn
// reads "subid"; if a future network uses a different key, change it here (and
// the SUBID_HEADERS in toplist-admin's connector must match the report column).
const SUBID_PARAM = 'subid'

// Opaque, stable per-site code used as the subid. We deliberately do NOT send
// the raw host: the network's reports are visible to the casino brands, and we
// don't want to reveal which domains send their traffic. The code is a salted
// FNV-1a hash of the host — deterministic so toplist-admin can resolve it back,
// opaque so brands can't. Keep SUBID_SALT + this function byte-identical in
// toplist-admin (subidForHost) and toplist-edge.
const SUBID_SALT = 'tl-subid-v1'
function siteSubid(host: string): string {
  const s = SUBID_SALT + host.toLowerCase()
  let h = 0x811c9dc5
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) }
  return 's' + (h >>> 0).toString(36)
}

function appendTrackingParams(targetUrl: string, incoming: URLSearchParams, sourceHost?: string): string {
  // Collect allowlisted incoming params (lowercased keys).
  const additions: Array<[string, string]> = []
  for (const [k, v] of incoming) {
    if (TRACKING_KEYS.has(k.toLowerCase()) && v.length <= 200) additions.push([k, v])
  }
  // Stamp this site's OPAQUE code as the subid so conversions attribute back to
  // it — unless the visitor already supplied one (campaign tracking wins). Never
  // the raw host: brands must not see which domain sent the traffic.
  const host = (sourceHost ?? '').toLowerCase()
  const visitorHasSubid = additions.some(([k]) => k.toLowerCase() === SUBID_PARAM)
  if (host && !visitorHasSubid) additions.push([SUBID_PARAM, siteSubid(host)])

  if (additions.length === 0) return targetUrl

  let parsed: URL
  try { parsed = new URL(targetUrl) } catch { return targetUrl }
  // Existing affiliate URL params win — sales' configured value is canonical;
  // tracking params (and our subid) only supplement what's missing.
  for (const [k, v] of additions) {
    if (!parsed.searchParams.has(k)) parsed.searchParams.append(k, v)
  }
  return parsed.toString()
}

// Bot detection for click logging. Mirrors toplist-edge/src/bots.ts, but it
// has to be duplicated here because this file is a template string that
// becomes a standalone worker — it cannot import from the edge package.
//
// Only ever decides whether to COUNT a click. The redirect is unaffected, so a
// false positive costs one uncounted click and never a lost referral.
const BOT_UA = /(?:bot|crawl|spider|slurp|scrape|feedfetcher|mediapartners|facebookexternalhit|whatsapp|telegrambot|discordbot|slackbot|twitterbot|linkedinbot|embedly|pinterest|redditbot|applebot|bingpreview|yandex|baidu|duckduck|petalbot|semrush|ahrefs|mj12|dotbot|dataforseo|screaming frog|sitebulb|headless|phantomjs|puppeteer|playwright|selenium|python-requests|python-urllib|aiohttp|httpx|curl\/|wget\/|libwww|okhttp|axios\/|node-fetch|go-http-client|java\/|apache-httpclient|postmanruntime|insomnia|lighthouse|pagespeed|gtmetrix|uptimerobot|pingdom|statuscake|monitoring)/i

function isBotRequest(request: Request): boolean {
  const cf = (request as unknown as { cf?: Record<string, unknown> }).cf
  if (cf) {
    const verified = cf['verifiedBotCategory']
    if (typeof verified === 'string' && verified.trim() !== '') return true
    const bm = cf['botManagement'] as { score?: unknown; verifiedBot?: unknown } | undefined
    if (bm) {
      if (bm.verifiedBot === true) return true
      // score 0 means "not computed", not "maximally bot" — treating it as a
      // detection would drop every click on a plan without Bot Management.
      const score = typeof bm.score === 'number' ? bm.score : null
      if (score !== null && score > 0 && score <= 30) return true
    }
  }
  const ua = request.headers.get('User-Agent') ?? ''
  return ua !== '' && BOT_UA.test(ua)
}

async function logClick(
  edgeBase: string,
  request: Request,
  url: URL,
  country: string,
  slug: string
): Promise<void> {
  // Hash the user-agent (8 char prefix) for unique-visitor estimates without
  // storing the raw UA. The hash is per-request — privacy-friendly enough
  // that it doesn't need cookie consent.
  const ua = request.headers.get('User-Agent') ?? ''
  let uaHash: string | null = null
  if (ua) {
    try {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ua))
      uaHash = Array.from(new Uint8Array(buf).slice(0, 4))
        .map((b) => b.toString(16).padStart(2, '0')).join('')
    } catch { /* shrug */ }
  }
  const referer = request.headers.get('Referer') ?? ''
  let refererHost: string | null = null
  let refererPath: string | null = null
  if (referer) {
    try {
      const u = new URL(referer)
      refererHost = u.hostname.toLowerCase()
      refererPath = u.pathname || null
    } catch { /* */ }
  }

  try {
    await fetch(`${edgeBase}/api/click`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        country,
        slug,
        source_host: url.hostname,
        referer_host: refererHost,
        referer_path: refererPath,
        ua_hash: uaHash,
      }),
    })
  } catch { /* never bubble click-log errors */ }
}

// Admin worker URL for the organic beacon (overridable via [vars] TOPLIST_ADMIN).
const DEFAULT_TOPLIST_ADMIN = 'https://toplist-admin.webtrico.com'

interface Env {
  ASSETS: Fetcher
  COUNTRY?: string
  TOPLIST_EDGE?: string
  TOPLIST_ADMIN?: string          // admin worker URL for organic beacon
  TOPLIST_EXCLUDE_SLUGS?: string  // optional comma-separated slugs to omit
  SITEMAP_AUTO?: string           // "off" to disable the dynamic sitemap.xml route
  SISTER_SITE?: string            // optional "FR:foo.fr" → emits hreflang on /brand/:slug
  SUBDOMAIN_HOST?: string         // optional mirror subdomain for hreflang (e.g. sitinonaams.egoe.it)
  SUBDOMAIN_SLUG?: string         // optional inner-page slug for it-it hreflang (e.g. it-it)
  REDIRECT_HOSTS?: string         // optional comma-separated hosts that 301 to SUBDOMAIN_HOST
  ROBOTS_TAG?: string             // optional site-wide robots directive, replaces per-page tags
}

// When SUBDOMAIN_HOST + SUBDOMAIN_SLUG are set, strip existing canonical/hreflang from HTML
// responses and inject per-hostname values so both apex and mirror subdomain cross-reference
// each other correctly. Canonical: apex → apex root; subdomain root → subdomain root;
// subdomain inner page → inner page URL.
function injectSubdomainMirrorMeta(
  response: Response,
  url: URL,
  env: { SUBDOMAIN_HOST?: string; SUBDOMAIN_SLUG?: string }
): Response {
  const ct = response.headers.get('Content-Type') ?? ''
  if (!ct.includes('text/html')) return response

  const subHost = (env.SUBDOMAIN_HOST ?? '').toLowerCase().trim()
  const innerSlug = (env.SUBDOMAIN_SLUG ?? '').toLowerCase().replace(/^\/+|\/+$/g, '').trim()
  if (!subHost || !innerSlug) return response

  const currentHost = url.hostname.toLowerCase()
  const isSubdomain = currentHost === subHost
  const apexHost = isSubdomain ? currentHost.slice(currentHost.indexOf('.') + 1) : currentHost

  const isInnerPage = url.pathname === `/${innerSlug}/` || url.pathname === `/${innerSlug}`
  const canonicalUrl = isSubdomain
    ? (isInnerPage ? `https://${subHost}/${innerSlug}/` : `https://${subHost}/`)
    : `https://${apexHost}/`

  const metaBlock = [
    `<link rel="canonical" href="${canonicalUrl}">`,
    `<link rel="alternate" hreflang="x-default" href="https://${apexHost}/">`,
    `<link rel="alternate" hreflang="it" href="https://${subHost}/">`,
    `<link rel="alternate" hreflang="it-it" href="https://${subHost}/${innerSlug}/">`,
  ].join('\n')

  return new HTMLRewriter()
    .on('link', {
      element(el) {
        const rel = (el.getAttribute('rel') ?? '').toLowerCase()
        if (rel === 'canonical') { el.remove(); return }
        if (rel === 'alternate' && el.getAttribute('hreflang')) el.remove()
      },
    })
    .on('head', {
      element(el) { el.append(`\n${metaBlock}\n`, { html: true }) },
    })
    .transform(response)
}

// ROBOTS_TAG replaces the robots meta on every HTML response, so one directive covers
// the whole site without editing each file. Existing tags are stripped first — two
// conflicting robots metas on a page let the crawler pick the more restrictive one.
function injectRobotsMeta(response: Response, env: { ROBOTS_TAG?: string }): Response {
  const ct = response.headers.get('Content-Type') ?? ''
  if (!ct.includes('text/html')) return response

  const directive = (env.ROBOTS_TAG ?? '').trim()
  if (!directive) return response

  return new HTMLRewriter()
    .on('meta', {
      element(el) {
        if ((el.getAttribute('name') ?? '').toLowerCase() === 'robots') el.remove()
      },
    })
    .on('head', {
      element(el) {
        el.append(`\n<meta name="robots" content="${directive}">\n`, { html: true })
      },
    })
    .transform(response)
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url)

    if (url.hostname.startsWith('www.')) {
      url.hostname = url.hostname.slice(4)
      return Response.redirect(url.toString(), 301)
    }

    // Retired mirror hostnames 301 to the canonical mirror, keeping path and query, so
    // old links and already-indexed URLs consolidate on the host hreflang points at.
    const retiredHosts = (env.REDIRECT_HOSTS ?? '')
      .toLowerCase()
      .split(',')
      .map((h) => h.trim())
      .filter(Boolean)
    const mirrorHost = (env.SUBDOMAIN_HOST ?? '').toLowerCase().trim()
    if (mirrorHost && retiredHosts.includes(url.hostname.toLowerCase())) {
      url.hostname = mirrorHost
      return Response.redirect(url.toString(), 301)
    }

    // Traffic is counted by a cache-proof client-side beacon injected into every
    // HTML page (see injectBeacon) — it fires in the browser even when CF serves
    // cached HTML without invoking this worker, so no server-side ping is needed
    // here (and we avoid double-counting). It posts back to this origin, on a
    // path derived from this domain, and the hop to the admin happens below.
    //
    // POST only: a GET to the same path still falls through to the assets, so
    // this can never shadow a real page.
    if (request.method === 'POST' && url.pathname === beaconPath(url.hostname)) {
      return handleBeaconHit(request, url, env, ctx)
    }

    if (url.pathname === '/go' || url.pathname.startsWith('/go/') ||
        url.pathname === '/vai' || url.pathname.startsWith('/vai/') ||
        url.pathname === '/aller' || url.pathname.startsWith('/aller/')) {
      return handleCloak(request, url, env, ctx)
    }

    // Auto-generated per-brand review pages (/recensioni/<slug>, /avis/<slug>,
    // …) and the brand directory hub (/casino) used to be proxied from
    // toplist-edge here. They are retired: publishing the same brand data as a
    // page on every site in the network is near-duplicate content, and they
    // were never meant to be a default.
    //
    // Aliases that were live on every site:
    //   IT: /brand/, /recensione/, /recensioni/, /casino-online/
    //   FR: /brand/, /avis/, /marque/, /casino-en-ligne/
    //   both: /casino, /casinos (the directory hub)
    //
    // The flag is only READ at the very bottom, after static assets have had
    // their say. Deciding here would be wrong on a rescued expired domain:
    // /casino/ and /recensioni/<slug> are perfectly ordinary paths for an
    // Italian or French site to have had real pages on, and link-equity
    // rescue writes _redirects rules for exactly those URLs. Assets and
    // redirects win; the tombstone is what is left when nothing claims the
    // path.
    const isRetiredPath =
      /^\/(?:brand|recensione|recensioni|avis|marque|casino-online|casino-en-ligne)\/[a-z0-9-]+\/?$/.test(url.pathname) ||
      /^\/casinos?\/?$/.test(url.pathname)

    // Sitemap: serve the static sitemap.xml (built from actual site pages by
    // push-site-files) if one exists. Fall back to the dynamic endpoint only
    // when no static file is present and SITEMAP_AUTO is not "off".
    if (url.pathname === '/sitemap.xml') {
      try {
        const staticSitemap = await env.ASSETS.fetch(request)
        if (staticSitemap.ok) return withSecurityHeaders(staticSitemap, request)
      } catch {}
      if (env.SITEMAP_AUTO !== 'off') return handleSitemap(url, env)
    }

    // Per-site logo proxy. Path shape: /_<6alphanum>/<slug>
    // The prefix is computed from the site's own domain so two EMD sites
    // never expose an identical logo URL (no image footprint).
    const logoMatch = url.pathname.match(/^\/_([a-z0-9]{6})\/([a-z0-9-]+)$/)
    if (logoMatch) {
      return handleLogoProxy(url, env, logoMatch)
    }

    try {
      const assetResponse = await env.ASSETS.fetch(request)
      // Nothing real lives here and it is a retired path: 410 Gone rather
      // than the site's 404 page. 410 gets the URL dropped from the index on
      // the next crawl; a 404 leaves Google re-checking it for months.
      // Matched on 404 specifically, not on !ok — a _redirects rule answers
      // 301, and a rescued redirect must not be turned into a tombstone.
      if (isRetiredPath && assetResponse.status === 404) {
        return handleRetiredPage(url, env)
      }
      const withToplist = await injectToplist(assetResponse, request, env)
      const withMirror = (env.SUBDOMAIN_HOST && env.SUBDOMAIN_SLUG)
        ? injectSubdomainMirrorMeta(withToplist, url, env)
        : withToplist
      const withRobots = injectRobotsMeta(withMirror, env)
      return withSecurityHeaders(injectBeacon(withRobots, url, env), request)
    } catch {
      return new Response('Service temporarily unavailable. Please try again in a moment.', {
        status: 503,
        headers: { 'Content-Type': 'text/plain', 'Retry-After': '30' },
      })
    }
  },
}
