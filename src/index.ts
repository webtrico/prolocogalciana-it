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

// Brand directory. Same proxy pattern as /brand/<slug>: fetch HTML from
// edge with this site's hostname as cache key, re-emit with our security
// headers. Search engines see a per-domain hub page linking every brand.
async function handleDirectory(
  url: URL,
  env: { COUNTRY?: string; TOPLIST_EDGE?: string; TOPLIST_ADMIN?: string }
): Promise<Response> {
  const country = detectCountry(env, url.hostname)
  const edgeBase = (env.TOPLIST_EDGE ?? DEFAULT_TOPLIST_EDGE).replace(/\/+$/, '')
  const upstream = `${edgeBase}/directory/${country}?domain=${encodeURIComponent(url.hostname)}`
  let res: Response
  try {
    res = await fetch(upstream, { cf: { cacheTtl: 300, cacheEverything: true } })
  } catch {
    return new Response('Service unavailable', { status: 503, headers: { 'Content-Type': 'text/plain', 'Retry-After': '30' } })
  }
  if (!res.ok) return new Response('Upstream error', { status: 502, headers: { 'Content-Type': 'text/plain' } })
  const headers = new Headers()
  headers.set('Content-Type', 'text/html; charset=utf-8')
  headers.set('Cache-Control', 'public, s-maxage=300, stale-while-revalidate=600')
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v)
  return injectBeacon(new Response(res.body, { status: 200, headers }), env)
}

// Per-brand SEO page. Proxies toplist-edge's /brand-page endpoint with
// the site's own hostname as the cache key so the rendered page is
// per-domain (different layout / accent / copy variants from other
// EMD sites' versions of the same brand).
async function handleBrandPage(
  slug: string,
  url: URL,
  env: { COUNTRY?: string; TOPLIST_EDGE?: string; SISTER_SITE?: string; TOPLIST_ADMIN?: string }
): Promise<Response> {
  const country = detectCountry(env, url.hostname)
  const edgeBase = (env.TOPLIST_EDGE ?? DEFAULT_TOPLIST_EDGE).replace(/\/+$/, '')
  // Optional sister-site for hreflang: e.g. SISTER_SITE = "FR:casinopremium.fr"
  // means this IT site has a French sibling at casinopremium.fr.
  const sisterParam = env.SISTER_SITE ? `&sister=${encodeURIComponent(env.SISTER_SITE)}` : ''
  const upstream = `${edgeBase}/brand-page/${country}/${encodeURIComponent(slug)}?domain=${encodeURIComponent(url.hostname)}${sisterParam}`
  let res: Response
  try {
    res = await fetch(upstream, { cf: { cacheTtl: 300, cacheEverything: true } })
  } catch {
    return new Response('Service unavailable', { status: 503, headers: { 'Content-Type': 'text/plain', 'Retry-After': '30' } })
  }
  if (res.status === 404) {
    return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain' } })
  }
  if (!res.ok) {
    return new Response('Upstream error', { status: 502, headers: { 'Content-Type': 'text/plain' } })
  }
  // Re-emit so we own the response headers: same security headers as
  // the rest of the site, with strong-cache directives intact.
  const headers = new Headers()
  headers.set('Content-Type', 'text/html; charset=utf-8')
  headers.set('Cache-Control', 'public, s-maxage=300, stale-while-revalidate=600')
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v)
  return injectBeacon(new Response(res.body, { status: 200, headers }), env)
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

// Inject a tiny, cache-proof organic beacon into every HTML page. It runs in the
// visitor's browser on EVERY view — even when Cloudflare serves cached HTML
// without invoking this worker — reads document.referrer, and pings the admin
// /beacon, which counts it only when the referrer is a search engine. There is no
// CSP on these sites so the inline script runs; a text/plain body avoids a CORS
// preflight, and sendBeacon adds zero latency for the visitor.
function injectBeacon(response: Response, env: { TOPLIST_ADMIN?: string }): Response {
  const ct = response.headers.get('Content-Type') ?? ''
  if (!ct.includes('text/html')) return response
  const admin = (env.TOPLIST_ADMIN ?? DEFAULT_TOPLIST_ADMIN).replace(/\/+$/, '')
  const s = '<script>(function(){try{var r=document.referrer||"";if(!r)return;var h="";try{h=new URL(r).hostname;}catch(e){return;}if(!h||h===location.hostname||h==="www."+location.hostname)return;var p=JSON.stringify({domain:location.hostname,referer:r});navigator.sendBeacon("' + admin + '/beacon",new Blob([p],{type:"text/plain"}));}catch(e){}})();</script>'
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
  const country = detectCountry(env, url.hostname)
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
  ctx.waitUntil(logClick(edgeBase, request, url, country, slug))

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
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url)

    if (url.hostname.startsWith('www.')) {
      url.hostname = url.hostname.slice(4)
      return Response.redirect(url.toString(), 301)
    }

    // Organic search is now tracked by a cache-proof client-side beacon injected
    // into every HTML page (see injectBeacon) — it fires in the browser even when
    // CF serves cached HTML without invoking this worker, so no server-side ping
    // is needed here (and we avoid double-counting).

    if (url.pathname === '/go' || url.pathname.startsWith('/go/') ||
        url.pathname === '/vai' || url.pathname.startsWith('/vai/') ||
        url.pathname === '/aller' || url.pathname.startsWith('/aller/')) {
      return handleCloak(request, url, env, ctx)
    }

    // Per-brand SEO page. We accept multiple URL prefixes because the
    // canonical prefix is per-domain ("/brand/" vs "/recensione/" vs
    // "/avis/" etc.), but a visitor with an old URL might land on any
    // of them. The brand-page handler proxies to toplist-edge regardless;
    // toplist-edge emits the canonical (prefix, slug) pair for THIS site.
    //
    // Aliases recognised on every site:
    //   IT: /brand/, /recensione/, /recensioni/, /casino-online/
    //   FR: /brand/, /avis/, /marque/, /casino-en-ligne/
    const brandPageMatch = url.pathname.match(/^\/(?:brand|recensione|recensioni|avis|marque|casino-online|casino-en-ligne)\/([a-z0-9-]+)\/?$/)
    if (brandPageMatch) {
      return handleBrandPage(brandPageMatch[1]!, url, env)
    }

    // Brand directory page. Both /casino and /casinos are common SEO
    // landing slugs in IT/FR; we accept both.
    if (url.pathname === '/casino' || url.pathname === '/casino/' ||
        url.pathname === '/casinos' || url.pathname === '/casinos/') {
      return handleDirectory(url, env)
    }

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
      const withToplist = await injectToplist(assetResponse, request, env)
      return withSecurityHeaders(injectBeacon(withToplist, env), request)
    } catch {
      return new Response('Service temporarily unavailable. Please try again in a moment.', {
        status: 503,
        headers: { 'Content-Type': 'text/plain', 'Retry-After': '30' },
      })
    }
  },
}
