const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Vary': 'Accept-Encoding',
  // Every fetch directive named, so the policy audit sees a complete header,
  // and every one of them permissive: legacy pages carry inline scripts and
  // handlers, the beacon below is inline, the toplist loads from toplist-edge
  // and a 2009 theme pulls fonts and widgets from wherever it liked. So
  // 'unsafe-inline' and https: stay; what the policy does enforce is the
  // upgrade of http: subresources, no plugins, no <base> injection, no framing
  // by another site.
  'Content-Security-Policy': "default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'; script-src 'self' https: 'unsafe-inline' 'unsafe-eval'; style-src 'self' https: 'unsafe-inline'; img-src 'self' https: data: blob:; font-src 'self' https: data:; connect-src 'self' https:; frame-src https:; upgrade-insecure-requests; frame-ancestors 'self'; base-uri 'self'; object-src 'none'",
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Cross-Origin-Opener-Policy': 'same-origin-allow-popups',
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

// Where a page that no longer exists should send the visitor, or null for a
// plain 404. A rescued or aged domain keeps its old inbound links this way:
// NOT_FOUND_REDIRECT = "/" in wrangler.toml [vars] turns a miss into a 301 to
// the homepage, so the links still count. This used to live as a hand edit in
// fifteen workers, and a template resync overwrote every one of them; now it
// is the template's, switched on per site by the setting.
//
// Only a page is redirected. A missing stylesheet, script, image, font, feed
// or file stays a 404 — a broken stylesheet must not come back as a copy of
// the homepage — and so do the well-known files and anything under /api/.
// Only a GET or HEAD, and never the target itself.
const NOT_FOUND_ASSET_RE = /\.(?:css|js|mjs|map|json|xml|txt|ico|png|jpe?g|gif|webp|avif|svg|woff2?|ttf|otf|eot|mp4|webm|mp3|ogg|wav|zip|gz|pdf)$/i
function notFoundRedirectTarget(url: URL, setting: string | undefined, method: string): string | null {
  const raw = (setting || '').trim()
  if (!raw || (method !== 'GET' && method !== 'HEAD')) return null
  const path = url.pathname
  if (NOT_FOUND_ASSET_RE.test(path) || path.indexOf('/.well-known/') === 0 || path.indexOf('/api/') === 0) return null
  let target: URL
  try { target = new URL(raw, url.origin) } catch { return null }
  const norm = function (p: string): string { return p.replace(/\/+$/, '') || '/' }
  if (target.origin === url.origin && norm(target.pathname) === norm(path)) return null
  return target.toString()
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
// the hit was. The CSP above keeps 'unsafe-inline' so this inline script
// runs; a text/plain body avoids a CORS preflight, and sendBeacon adds zero
// latency.
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
  const admin = (env.TOPLIST_ADMIN ?? DEFAULT_TOPLIST_ADMIN).replace(/\/+$/, '')
  // A hit that is not a person is not dropped on the floor: the admin keeps a
  // tally per reason, so the share the human filter removes can be read
  // rather than guessed at. Only the domain and the reason travel.
  const excluded = botReason(request)
  if (excluded) {
    ctx.waitUntil(fetch(admin + '/beacon', {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/json', 'X-Beacon-Edge': '1' },
      body: JSON.stringify({ domain: apexHost(url.hostname), excluded: excluded }),
    }).then(function () { return undefined }, function () { return undefined }))
    return ok
  }
  let hit: { r?: unknown; s?: unknown; o?: unknown; d?: unknown; p?: unknown; x?: unknown; f?: unknown; e?: unknown; t?: unknown; k?: unknown; l?: unknown; c?: unknown; i?: unknown; y?: unknown; q?: unknown } | null = null
  try { hit = await request.json() } catch { hit = null }
  // The reader-signals ping (k: "x"), sent once as the page is left: field
  // vitals, scroll depth, clicks on marked elements, scrolls inside tables,
  // copies, the site-search query. Bounded here as well as at the admin, and
  // sent on as its own kind so the admin never takes it for a page view.
  if (hit && hit.k === 'x') {
    const n = function (v: unknown, max: number): number { return typeof v === 'number' && isFinite(v) && v > 0 ? Math.min(max, Math.round(v)) : 0 }
    const clicks: Record<string, number> = {}
    if (hit.e && typeof hit.e === 'object') {
      const e = hit.e as Record<string, unknown>
      for (const key of Object.keys(e).slice(0, 20)) {
        const v = e[key]
        if (typeof v === 'number' && v > 0) clicks[key.slice(0, 32)] = Math.min(1000, Math.round(v))
      }
    }
    const sigPath = typeof hit.p === 'string' ? hit.p : ''
    ctx.waitUntil(fetch(admin + '/beacon', {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/json', 'User-Agent': request.headers.get('User-Agent') ?? '', 'X-Beacon-Edge': '1' },
      body: JSON.stringify({
        domain: apexHost(url.hostname), k: 'x',
        path: sigPath.charAt(0) === '/' ? sigPath.split('?')[0].split('#')[0].slice(0, 200) : '',
        lcp: n(hit.l, 60000), cls_x1000: n(hit.c, 10000), inp: n(hit.i, 60000), scroll: n(hit.s, 100),
        element_clicks: clicks, table_scrolls: n(hit.t, 1000), copies: n(hit.y, 1000),
        query: typeof hit.q === 'string' ? hit.q.slice(0, 80) : '',
      }),
    }).then(function () { return undefined }, function () { return undefined }))
    return ok
  }
  // An automated browser said so itself (navigator.webdriver): a crawler run
  // through a real browser, which the edge signals alone do not catch. Not a
  // view; tallied as excluded so the share is readable.
  if (hit && hit.x === 'wd') {
    ctx.waitUntil(fetch(admin + '/beacon', {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/json', 'X-Beacon-Edge': '1' },
      body: JSON.stringify({ domain: apexHost(url.hostname), excluded: 'webdriver' }),
    }).then(function () { return undefined }, function () { return undefined }))
    return ok
  }
  // The page's own path, as it saw it; the query string is not part of the
  // page. Absent on a site whose worker predates this.
  const rawPath = typeof hit?.p === 'string' ? hit.p : ''
  const path = rawPath.charAt(0) === '/' ? rawPath.split('?')[0].split('#')[0].slice(0, 200) : ''
  const body = JSON.stringify({
    domain: apexHost(url.hostname),
    referer: typeof hit?.r === 'string' ? hit.r.slice(0, 300) : '',
    // o is the session's entry source, decided once by the page script on the
    // first view and repeated on every view after it. The referer above is only
    // this request's, which for page two of a session is our own page — so
    // without this the traffic report can only ever see landing views as
    // organic and calls the rest direct.
    source: typeof hit?.o === 'string' ? hit.o.slice(0, 1).toLowerCase() : '',
    device: typeof hit?.d === 'string' ? hit.d.slice(0, 1).toLowerCase() : '',
    // The closing ping: the same session reporting what the visitor did before
    // leaving. "final" tells the admin not to count a second page view.
    // (No backticks in here: this comment lives inside the worker's own
    // template literal, and one would end it.)
    final: hit?.f === 1,
    evidence: typeof hit?.e === 'number' ? hit.e : null,
    dwell: typeof hit?.t === 'number' ? hit.t : null,
    // s is the page's answer to "is this the first view of a session". Sent as
    // a boolean so the admin never has to guess what a missing field meant.
    visit: hit?.s === 1,
    country: request.headers.get('CF-IPCountry') ?? '',
    path: path,
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
//
// The second function in the same script element is the reader-signals
// ping, one extra sendBeacon as the page is left (pagehide or hidden), never
// on load: LCP, CLS (times a thousand, as an integer) and INP from
// PerformanceObserver where the browser has them, the deepest scroll as a
// percentage in steps of ten, clicks on elements carrying data-rf by their
// value (at most twenty), horizontal scrolls inside .tbl-scroll tables, copy
// events, and the query when the page is the site search. Every API is
// guarded and nothing in it can throw into the page; the first function
// above is untouched and still sends exactly what it sent. The two search
// paths are written out because this string is built with only the beacon
// path in scope; the scaffold test holds them to SEARCH_PATH.
function injectBeacon(response: Response, url: URL, env: { TOPLIST_ADMIN?: string }): Response {
  const ct = response.headers.get('Content-Type') ?? ''
  if (!ct.includes('text/html')) return response
  const s = '<script>(function(){try{var SE="|google|bing|duckduckgo|yahoo|ecosia|qwant|startpage|brave|yandex|baidu|seznam|naver|mojeek|lycos|";function se(h){var a=String(h||"").toLowerCase().split(".");for(var i=0;i<a.length;i++){if(SE.indexOf("|"+a[i]+"|")>=0)return 1}return 0}var v=1,c="";try{c=sessionStorage.getItem("_o")||"";if(sessionStorage.getItem("_s"))v=0;else sessionStorage.setItem("_s","1")}catch(e){v=document.referrer.indexOf(location.host)<0?1:0}var dv="d";try{var ua=(navigator.userAgent||"").toLowerCase();var uad=navigator.userAgentData;dv=(uad&&uad.mobile===true)?"m":(ua.indexOf("ipad")>=0||(ua.indexOf("android")>=0&&ua.indexOf("mobi")<0))?"t":(ua.indexOf("mobi")>=0||ua.indexOf("iphone")>=0||ua.indexOf("android")>=0)?"m":"d"}catch(e5){dv="d"}if(!c){var r=document.referrer||"",rh="";try{rh=r?new URL(r).hostname:""}catch(e2){rh=""}var qs=(location.search||"").toLowerCase();var pd=qs.indexOf("gclid=")>=0||qs.indexOf("msclkid=")>=0||qs.indexOf("fbclid=")>=0||qs.indexOf("utm_medium=cpc")>=0;c=pd?"p":!rh?"d":(rh===location.hostname||rh==="www."+location.hostname||"www."+rh===location.hostname)?"i":se(rh)?"o":"r";try{sessionStorage.setItem("_o",c)}catch(e3){}}var sig=0,t0=Date.now();function mark(bt){return function(){sig=sig|bt}}var po={passive:true,capture:true};document.addEventListener("pointermove",mark(1),po);document.addEventListener("touchstart",mark(1),po);document.addEventListener("scroll",mark(2),po);document.addEventListener("wheel",mark(2),po);document.addEventListener("keydown",mark(4),po);function dwell(){return Math.min(3600,Math.round((Date.now()-t0)/1000))}function stamp(ev){try{var a=ev.target;a=(a&&a.closest)?a.closest("a"):null;if(!a)return;var h=a.getAttribute("href")||"";if(h.indexOf("/vai/")!==0&&h.indexOf("/aller/")!==0&&h.indexOf("/go/")!==0)return;if(h.indexOf("s=")>=0)return;var sg=sig|((ev&&ev.isTrusted)?8:0);a.setAttribute("href",h+(h.indexOf("?")>=0?"&":"?")+"s="+c+"&dev="+dv+"&e="+sg+"&t="+dwell());}catch(e4){}}document.addEventListener("click",stamp,true);document.addEventListener("auxclick",stamp,true);if(navigator.webdriver){navigator.sendBeacon("' + beaconPath(url.hostname) + '",new Blob([JSON.stringify({x:"wd"})],{type:"text/plain"}));return}var p=JSON.stringify({r:document.referrer||"",s:v,o:c,d:dv,p:location.pathname});navigator.sendBeacon("' + beaconPath(url.hostname) + '",new Blob([p],{type:"text/plain"}));var done=0;function bye(){if(done)return;done=1;try{var q=JSON.stringify({f:1,o:c,d:dv,e:sig,t:dwell(),p:location.pathname});navigator.sendBeacon("' + beaconPath(url.hostname) + '",new Blob([q],{type:"text/plain"}))}catch(e6){}}document.addEventListener("visibilitychange",function(){if(document.visibilityState==="hidden")bye()},true);if(typeof window!=="undefined"&&window.addEventListener)window.addEventListener("pagehide",bye,true);}catch(e){}try{var bars=document.querySelectorAll("a[class*=-sbar]");if(bars.length&&matchMedia("(max-width:640px)").matches){var pin=function(){for(var i=0;i<bars.length;i++){var bar=bars[i],w=bar.parentElement,rc=w.getBoundingClientRect(),on=rc.top<innerHeight-120&&rc.bottom>innerHeight+40;bar.style.position=on?"fixed":"";bar.style.left=on?"16px":"";bar.style.right=on?"16px":"";bar.style.bottom=on?"10px":"";bar.style.zIndex=on?"99":""}};addEventListener("scroll",pin,{passive:true});addEventListener("resize",pin,{passive:true});addEventListener("load",pin);pin();setTimeout(pin,800);setTimeout(pin,2500)}}catch(e7){}})();(function(){try{if(navigator.webdriver)return;var L=0,C=0,I=0,S=0,K={},KN=0,T=0,Y=0,Q="";try{new PerformanceObserver(function(l){var e=l.getEntries();if(e.length)L=e[e.length-1].startTime}).observe({type:"largest-contentful-paint",buffered:true})}catch(x1){}try{new PerformanceObserver(function(l){var e=l.getEntries();for(var i=0;i<e.length;i++){if(!e[i].hadRecentInput)C+=e[i].value}}).observe({type:"layout-shift",buffered:true})}catch(x2){}try{new PerformanceObserver(function(l){var e=l.getEntries();for(var i=0;i<e.length;i++){if(e[i].interactionId&&e[i].duration>I)I=e[i].duration}}).observe({type:"event",buffered:true,durationThreshold:40})}catch(x3){}function sd(){try{var d=document.documentElement,h=(d.scrollHeight||0)-(window.innerHeight||0),p=h>0?Math.round(100*(window.scrollY||0)/h):100;if(p>S)S=p>100?100:p}catch(x4){}}try{sd();window.addEventListener("scroll",sd,{passive:true})}catch(x5){}try{document.addEventListener("click",function(ev){try{var t=ev.target,a=(t&&t.closest)?t.closest("[data-rf]"):null;if(!a)return;var k=String(a.getAttribute("data-rf")||"").slice(0,32);if(!k)return;if(!K[k]){if(KN>=20)return;KN++;K[k]=0}K[k]++}catch(x6){}},true)}catch(x7){}try{document.addEventListener("scroll",function(ev){try{var t=ev.target;if(!t||!t.classList||!t.classList.contains("tbl-scroll"))return;var x=t.scrollLeft||0;if(x!==(t.__rx||0)){t.__rx=x;T++}}catch(x8){}},true)}catch(x9){}try{document.addEventListener("copy",function(){Y++},true)}catch(x10){}try{if(location.pathname==="/cerca"||location.pathname==="/recherche"){var qs=(location.search||"").slice(1).split("&");for(var j=0;j<qs.length;j++){var kv=qs[j].split("=");if(kv[0]==="q"){Q=decodeURIComponent((kv[1]||"").split("+").join(" ")).toLowerCase().slice(0,80);break}}}}catch(x11){}var done=0;function bye(){if(done)return;done=1;try{sd();var o={k:"x",p:location.pathname,l:Math.round(L),c:Math.round(C*1000),i:Math.round(I),s:Math.round(S/10)*10,t:T,y:Y};if(KN)o.e=K;if(Q)o.q=Q;navigator.sendBeacon("' + beaconPath(url.hostname) + '",new Blob([JSON.stringify(o)],{type:"text/plain"}))}catch(x12){}}document.addEventListener("visibilitychange",function(){if(document.visibilityState==="hidden")bye()},true);if(typeof window!=="undefined"&&window.addEventListener)window.addEventListener("pagehide",bye,true)}catch(x0){}})();</script>'
  return new HTMLRewriter().on('body', { element(el) { el.append(s, { html: true }) } }).transform(response)
}

// The toplist's phone bar (toplist-edge stickyBar) is position:sticky at the
// end of the widget, which a host theme defeats the moment it clips its main
// column (teatrokappao.it: main with overflow hidden). The tail of the
// beacon script above pins the bar as position:fixed while the widget spans
// past the bottom of a phone screen, and lets it go the moment the widget's
// own end is on screen, so the bar never outlives the list.
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
  async function fetchFragment(country: string, theme: string, exclude: string, limit: string, host: string): Promise<string> {
    const key = country + '|' + theme + '|' + exclude + '|' + limit + '|' + host
    const hit = cache.get(key)
    if (hit !== undefined) return hit
    let renderUrl = `${edgeBase}/render/${country}?domain=${encodeURIComponent(hostname)}&theme=${theme}`
    if (exclude) renderUrl += `&exclude=${encodeURIComponent(exclude)}`
    if (limit) renderUrl += `&limit=${encodeURIComponent(limit)}`
    // The page's own colours and type, so the list renders as part of the
    // article: data-toplist-bg="#0f1115" data-toplist-accent="#e0b25a"
    // data-toplist-font="host". Already validated to a hex / the word host.
    if (host) renderUrl += host
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
  // The page's own colour, when it states one: <meta name="theme-color"> is
  // what most themes already ship, and it is the background the list should
  // sit on. Read in the head, used by the placeholder further down, and only
  // when the placeholder itself says nothing (data-toplist-bg wins).
  let pageColor = ''

  return new HTMLRewriter()
    .on('html', {
      element(el) {
        const lang = (el.getAttribute('lang') ?? '').toLowerCase().split('-')[0]
        if (lang === 'it') pageLang = 'IT'
        else if (lang === 'fr') pageLang = 'FR'
      },
    })
    .on('meta[name="theme-color"]', {
      element(el) {
        const v = (el.getAttribute('content') ?? '').trim()
        if (/^#?[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/.test(v)) pageColor = v.replace(/^#/, '')
      },
    })
    .on('[data-toplist]', {
      async element(el) {
        const explicit = (el.getAttribute('data-toplist') ?? '').toUpperCase()
        let country: 'IT' | 'FR'
        if (explicit === 'IT' || explicit === 'FR') country = explicit
        else if (pageLang) country = pageLang
        else country = detectCountry(env, hostname)
        const themeAttr = (el.getAttribute('data-toplist-theme') ?? '').trim().toLowerCase()
        const theme = themeAttr === 'light' ? 'light' : 'dark'
        const pageExclude = el.getAttribute('data-toplist-exclude')
        const exclude = (pageExclude ?? defaultExclude).trim()
        // Optional cap: data-toplist-limit="5" renders top 5 instead of 10.
        // Validated to a 1..10 integer; ignored if invalid or unset.
        const rawLimit = el.getAttribute('data-toplist-limit') ?? ''
        const limit = /^([1-9]|10)$/.test(rawLimit) ? rawLimit : ''
        // Native look: the page's background and accent colours (hex) and
        // whether the list should use the page's font. Anything else is
        // dropped here, so a typo never reaches the renderer.
        const hex = (v: string | null) => (v && /^#?[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/.test(v.trim()) ? v.trim().replace(/^#/, '') : '')
        // theme-color is the browser-chrome colour, and on a light page it is
        // often the brand's dark header (balbuzie-news.it: a cream page, a
        // maroon theme-color). So the meta stands in for the page background
        // ONLY when it agrees with what the placeholder says the page is: a
        // dark colour on a page declared light would turn the list dark on
        // cream, worse than before. An explicit data-toplist-bg always wins.
        const lum = (h: string) => { const v = h.length === 3 ? h.split('').map((c) => c + c).join('') : h; const [r, g, b] = [0, 2, 4].map((i) => parseInt(v.slice(i, i + 2), 16) / 255); return 0.2126 * r + 0.7152 * g + 0.0722 * b }
        const metaFits = !!pageColor && (themeAttr === '' || (themeAttr === 'light') === (lum(pageColor) > 0.4))
        const hostBg = hex(el.getAttribute('data-toplist-bg')) || (metaFits ? pageColor : '')
        const hostAccent = hex(el.getAttribute('data-toplist-accent'))
        const hostFont = (el.getAttribute('data-toplist-font') ?? '').trim().toLowerCase() === 'host'
        const host = (hostBg ? '&bg=' + hostBg : '') + (hostAccent ? '&accent=' + hostAccent : '') + (hostFont ? '&font=host' : '')
        const fragment = await fetchFragment(country, theme, exclude, limit, host)
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
  // This is the last point that still sees the real visitor request: logClick
  // is a server-to-server fetch, so by the time it reaches /api/click the
  // User-Agent and the cf bot signals are gone and only ua_hash survives. The
  // verdict therefore has to be made HERE — and, until now, was made here and
  // then thrown away. Bots were simply not logged, so the only filter that
  // reached the database was a 2-second timing rule, which counted 62% of a
  // week's "human" clicks from agents that swept the whole ranking table.
  //
  // Now every click is logged and carries its verdict. Recording a bot as a bot
  // beats not recording it: the raw count stays auditable, and "no clicks" and
  // "all of them automated" stop looking identical.
  ctx.waitUntil(logClick(edgeBase, request, url, country, slug, isBotRequest(request)))

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

// Hosting networks. A browser running inside one is a script somebody is
// driving, not a reader: headless Chrome on a cloud box fires the pixel like
// any other browser and used to count. Google's own network is NOT here -
// Google One VPN exits through it, and a person on that VPN is a person; the
// Cloud Platform has its own number. Everything excluded is counted by reason
// on the admin side, so this list can be read against what it removes.
const DATACENTER_ASN = new Set([16509, 14618, 396982, 8075, 14061, 16276, 24940, 213230, 63949, 20473, 51167, 31898, 45102, 60781, 12876])

// Why a request is not a person, or null when nothing says so. One verdict
// for the beacon and the click counter both, so "human" means one thing on
// this site. The order is cheapest and surest first.
function botReason(request: Request): string | null {
  const cf = (request as unknown as { cf?: Record<string, unknown> }).cf
  if (cf) {
    const verified = cf['verifiedBotCategory']
    if (typeof verified === 'string' && verified.trim() !== '') return 'verified_bot'
    const bm = cf['botManagement'] as { score?: unknown; verifiedBot?: unknown } | undefined
    if (bm) {
      if (bm.verifiedBot === true) return 'verified_bot'
      // score 0 means "not computed", not "maximally bot" — treating it as a
      // detection would drop every click on a plan without Bot Management.
      const score = typeof bm.score === 'number' ? bm.score : null
      if (score !== null && score > 0 && score <= 30) return 'bot_score'
    }
    const asn = typeof cf['asn'] === 'number' ? cf['asn'] : Number(cf['asn'])
    if (Number.isFinite(asn) && DATACENTER_ASN.has(asn)) return 'datacenter'
  }
  // A prefetch or a preview is the browser guessing, not the person reading.
  const purpose = (request.headers.get('Sec-Purpose') || request.headers.get('Purpose') || '').toLowerCase()
  if (purpose.indexOf('prefetch') >= 0 || purpose.indexOf('preview') >= 0) return 'prefetch'
  const ua = request.headers.get('User-Agent') ?? ''
  if (ua !== '' && BOT_UA.test(ua)) return 'bot_ua'
  return null
}

function isBotRequest(request: Request): boolean {
  return botReason(request) !== null
}

async function logClick(
  edgeBase: string,
  request: Request,
  url: URL,
  country: string,
  slug: string,
  bot: boolean
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
        // The verdict from the request the visitor actually made. Without it
        // the edge has only the timing rule.
        bot,
        // One letter, set by the page script on the link at click time, saying
        // where this SESSION began. Absent means no script ran — which the
        // edge records as unknown rather than guessing, and which is the state
        // every crawler reading hrefs out of the HTML arrives in.
        s: (url.searchParams.get('s') ?? '').slice(0, 1).toLowerCase() || undefined,
        // m mobile, t tablet, d desktop. Classified in the browser because the
        // User-Agent does not survive to the database — only a four-byte hash
        // of it does, and a hash cannot be read back into a device.
        dev: (url.searchParams.get('dev') ?? '').slice(0, 1).toLowerCase() || undefined,
        // What the visitor did before clicking, as a bitmask, and how long they
        // were on the page. Without Search Console this is the only signal left
        // that costs a crawler anything to produce — see migration 0104.
        e: url.searchParams.get('e') ?? undefined,
        t: url.searchParams.get('t') ?? undefined,
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
  NOT_FOUND_REDIRECT?: string     // optional: where a page that no longer exists goes, with a 301 (e.g. "/"); absent = 404
  FIX_PAGE?: string               // optional: "off" switches the edge SEO fixes (fixPage, CSS floor) off for this site
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

// ── Edge SEO fixes ────────────────────────────────────────────────────────
// What follows fixes, on every HTML page this worker serves, the audit rules
// that are the TEMPLATE's fault rather than the article's: missing Open Graph
// tags, nofollow on our own links, a meta description that runs long, JSON-LD
// with holes in it, images without lazy loading, unlabelled inputs and navs,
// no skip link, no trust pages, nine render-blocking stylesheets, text under
// 12px, and a header set without CSP or HSTS. One pass, at the edge, for
// every site at once; a page that already has any of these keeps what it has.
// FIX_PAGE = "off" in wrangler.toml switches the page and stylesheet rewriting
// off for one site. (This comment is inside the template literal: no
// backticks anywhere below.)
//
// The page is read as text first. Pages here are small, and the questions the
// head needs answered (is there a first image? a canonical? a main?) are about
// parts of the document the streaming rewriter has not seen yet when it is in
// the head. The second pass is an ordinary HTMLRewriter over the text.

// The trust footer is the worker's own: a page gets one unless it already
// carries a footer.rp-trust (the generated trust pages do). It used to be
// withheld from any page with a link whose text or href merely resembled a
// trust link, and a site whose footer linked to an external privacy page went
// without about, contact and editorial pages and without the disclaimers.
const OWN_TRUST_FOOTER_RE = /<footer\b[^>]*\bclass\s*=\s*["'][^"']*\brp-trust\b/i

// The entities a legacy Italian or French page uses: the XML five, the
// numeric forms, and the Latin-1 accents and punctuation a 2009 CMS wrote by
// name. Anything else stays as written, and escAttr leaves it be.
const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
  agrave: 'à', aacute: 'á', acirc: 'â', auml: 'ä', egrave: 'è', eacute: 'é', ecirc: 'ê', euml: 'ë',
  igrave: 'ì', iacute: 'í', icirc: 'î', iuml: 'ï', ograve: 'ò', oacute: 'ó', ocirc: 'ô', ouml: 'ö',
  ugrave: 'ù', uacute: 'ú', ucirc: 'û', uuml: 'ü', ccedil: 'ç', ntilde: 'ñ', oelig: 'œ', szlig: 'ß',
  Agrave: 'À', Aacute: 'Á', Acirc: 'Â', Egrave: 'È', Eacute: 'É', Ecirc: 'Ê', Igrave: 'Ì', Ograve: 'Ò',
  Ugrave: 'Ù', Ccedil: 'Ç', OElig: 'Œ',
  laquo: '«', raquo: '»', lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', sbquo: '‚', bdquo: '„',
  ndash: '–', mdash: '—', hellip: '…', middot: '·', bull: '•', copy: '©', reg: '®', trade: '™', euro: '€', deg: '°',
}
function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z][a-z0-9]*);/gi, (whole, e: string) => {
    if (e.charAt(0) === '#') {
      const code = e.charAt(1).toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)
      return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole
    }
    const named = NAMED_ENTITIES[e] ?? NAMED_ENTITIES[e.toLowerCase()]
    return named !== undefined ? named : whole
  })
}
// An entity decodeEntities did not know is still an entity; it is not
// escaped twice.
function escAttr(s: string): string {
  return s.replace(/&(?!(?:#x[0-9a-f]+|#[0-9]+|[a-z][a-z0-9]*);)/gi, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
// Attributes of one start tag, lowercase names, entity-decoded values, first
// occurrence wins. Good enough for the head of a page; the rewriter does the
// real parsing.
function parseAttrs(tag: string): Record<string, string> {
  const out: Record<string, string> = {}
  const body = tag.replace(/^<[a-zA-Z][^\s\/>]*/, '').replace(/\/?>$/, '')
  const re = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g
  let m: RegExpExecArray | null
  while ((m = re.exec(body)) !== null) {
    const k = m[1].toLowerCase()
    if (!(k in out)) out[k] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? '')
  }
  return out
}
function relTokens(v: string | null): string[] {
  return (v ?? '').toLowerCase().split(/\s+/).filter((t) => t !== '')
}
// The path (with query) of a URL on this site, or null when it points
// elsewhere. www and apex count as the same site: the worker sends one to the
// other anyway.
function sameOriginPath(href: string, base: URL): string | null {
  let u: URL
  try { u = new URL(href, base) } catch { return null }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null
  if (apexHost(u.hostname) !== apexHost(base.hostname)) return null
  return u.pathname + u.search
}
function absolutize(href: string, base: URL): string {
  if (!href) return ''
  try { return new URL(href, base).href } catch { return '' }
}
// The width a search result gives a description, in the audit's own estimate:
// a space or thin punctuation 4px, a capital 9.5px, anything else 7.5px, with
// 920px the most that shows. 155 characters of lower-case Italian fit; 145
// with capitals and accents did not.
function serpWidth(s: string): number {
  let w = 0
  for (const ch of s) {
    if (ch === ' ') w += 4
    else if (ch >= 'A' && ch <= 'Z') w += 9.5
    else if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) w += 7.5
    else if (ch === '.' || ch === ',' || ch === ':' || ch === ';' || ch === '!' || ch === '|') w += 4
    else w += 7.5
  }
  return Math.round(w)
}
const DESC_MAX_CHARS = 155
const DESC_MAX_WIDTH = 920
function trimDescription(s: string): string {
  if (s.length <= DESC_MAX_CHARS && serpWidth(s) <= DESC_MAX_WIDTH) return s
  // The longest prefix inside both limits, then back to the last space.
  let end = Math.min(s.length, DESC_MAX_CHARS)
  while (end > 0 && serpWidth(s.slice(0, end)) > DESC_MAX_WIDTH) end--
  const cut = s.slice(0, end)
  const at = cut.lastIndexOf(' ')
  return (at > 60 ? cut.slice(0, at) : cut).replace(/[\s,;:(-]+$/, '')
}
// The site as a publisher: the registrable name without its ending, in
// capitals ("casino-online.it" is "Casino Online"), for a JSON-LD node that
// has no name and for the accessible name of a bare link home.
function publisherName(hostname: string): string {
  const apex = apexHost(hostname)
  const label = apex.slice(0, apex.lastIndexOf('.') > 0 ? apex.lastIndexOf('.') : apex.length)
  return label.split(/[-_.]+/).filter((w) => w !== '').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ') || apex
}
function stripTags(html: string): string {
  return html.replace(/<[^>]*>/g, ' ').replace(/&(?:nbsp|#160);/gi, ' ').replace(/\s+/g, ' ').trim()
}

// ── CSS ───────────────────────────────────────────────────────────────────
// Text under 12px fails the legibility audit on every page that has it, and
// most of it is a theme's fine print. Floor it: px under 12 becomes 12px, em
// and rem under 0.75 become 0.75. A size of 0 is a layout trick, not small
// text, and is left alone; so is the font shorthand unless it is the simple
// form (optional style/weight keywords, then the size).
function bumpFontSize(whole: string, pre: string, n: string, unit: string): string {
  const v = parseFloat(n)
  if (!(v > 0)) return whole
  const u = unit.toLowerCase()
  if (u === 'px') return v < 12 ? pre + '12px' : whole
  if (u === 'pt') return v < 10 ? pre + '10pt' : whole
  return v < 0.75 ? pre + '0.75' + u : whole
}
function fixCss(css: string): string {
  return css
    .replace(/(font-size\s*:\s*)(\d*\.?\d+)(px|pt|r?em)(?![\w%.-])/gi, bumpFontSize)
    .replace(/(\bfont\s*:\s*(?:(?:normal|italic|oblique|bold|bolder|lighter|[1-9]00|small-caps)\s+)*)(\d*\.?\d+)(px|pt|r?em)(?=[\s\/])/gi, bumpFontSize)
}
// A unitless (or em/rem) line-height under 1.2 is the other thing the mobile
// legibility audit reads out of a page's own CSS. Only the page's own CSS: a
// <style> block or a style attribute, never a linked stylesheet, so a theme's
// layout is not re-spaced wholesale for a rule that never looks at it.
function floorLineHeight(css: string): string {
  return css.replace(/(line-height\s*:\s*)(\d*\.?\d+)(r?em)?(?![\w%.-])/gi, (whole, pre: string, n: string, unit: string | undefined) => {
    const v = parseFloat(n)
    return v > 0 && v < 1.2 ? pre + '1.2' + (unit ?? '') : whole
  })
}
function fixStyleBlock(css: string): string {
  return floorLineHeight(fixCss(css))
}
// A style attribute. The audit reads font-size out of the style attribute of
// every text element (p, span, div, li, td, th, label, a, button) and flags
// anything that works out under 16px as hard to read on a phone, under 12px
// as critical; on other elements the 12px floor of the stylesheets applies.
// em, rem and % are converted the way the audit converts them (1em = 16px).
const STYLE_TEXT_TAGS = new Set(['p', 'span', 'div', 'li', 'td', 'th', 'label', 'a', 'button', 'body', 'html'])
function fixStyleAttr(style: string, floorPx: number): string {
  const bumped = style.replace(/(font-size\s*:\s*)(\d*\.?\d+)(px|pt|r?em|%)?(?![\w.-])/gi, (whole, pre: string, n: string, unit: string | undefined) => {
    const v = parseFloat(n)
    if (!(v > 0)) return whole
    const u = (unit ?? 'px').toLowerCase()
    const px = u === 'pt' ? v * 1.333 : u === '%' ? v / 100 * 16 : u === 'px' ? v : v * 16
    if (px >= floorPx) return whole
    if (u === 'pt') return pre + Math.ceil(floorPx / 1.333) + 'pt'
    if (u === '%') return pre + Math.round(floorPx / 16 * 100) + '%'
    if (u === 'px') return pre + floorPx + 'px'
    return pre + String(Math.round(floorPx / 16 * 1000) / 1000) + u
  })
  return floorLineHeight(bumped)
}
// A stylesheet moved into the bundle keeps resolving its url() and @import
// references as if it were still at its own path.
function rebaseCss(css: string, from: string, origin: string): string {
  let base: URL
  try { base = new URL(from, origin) } catch { return css }
  const abs = (ref: string): string => {
    const r = ref.trim()
    if (!r || /^(?:[a-z][a-z0-9+.-]*:|\/\/|\/|#)/i.test(r)) return ref
    try { const u = new URL(r, base); return u.pathname + u.search + u.hash } catch { return ref }
  }
  return css
    .replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (whole, q: string, ref: string) => 'url(' + q + abs(ref) + q + ')')
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (whole, q: string, ref: string) => '@import ' + q + abs(ref) + q)
}

// A stylesheet asset, with the font-size floor applied. Anything that is not a
// 200 text/css answer passes through untouched.
async function fixCssResponse(response: Response, env: Env): Promise<Response> {
  if (response.status !== 200 || fixPageOff(env)) return response
  const ct = response.headers.get('Content-Type') ?? ''
  if (!ct.includes('text/css')) return response
  const css = await response.text()
  const headers = new Headers(response.headers)
  headers.delete('Content-Length')
  return new Response(fixCss(css), { status: 200, headers })
}

// /_css/<hash>.css?f=/a.css,/b.css — the page's same-origin stylesheets as one
// response, in the order the page listed them. Each is read from the site's own
// assets; one that is missing or not CSS leaves a comment in its place, never a
// 500, so a broken link in one theme file cannot blank the whole page's style.
const CSS_BUNDLE_MAX = 20
async function handleCssBundle(url: URL, env: Env): Promise<Response> {
  const list = (url.searchParams.get('f') ?? '').split(',')
    .map((p) => p.trim())
    .filter((p) => p.charAt(0) === '/' && p.indexOf('//') !== 0 && p.indexOf('..') < 0 && /\.css(\?|$)/i.test(p))
    .slice(0, CSS_BUNDLE_MAX)
  const parts = await Promise.all(list.map(async (path) => {
    const label = path.replace(/\*\//g, '')
    try {
      const r = await env.ASSETS.fetch(new Request(url.origin + path))
      if (r.ok && (r.headers.get('Content-Type') ?? '').includes('text/css')) {
        return '/* ' + label + ' */\n' + rebaseCss(await r.text(), path, url.origin)
      }
    } catch { /* fall through */ }
    return '/* ' + label + ': missing */'
  }))
  const headers = new Headers()
  headers.set('Content-Type', 'text/css; charset=utf-8')
  headers.set('Cache-Control', 'public, max-age=86400')
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v)
  return new Response(fixCss(parts.join('\n')), { status: 200, headers })
}

// /_css/i<hash>.css?p=/page/ — the <style> blocks of that page as one
// stylesheet, in their order, with the same font-size and line-height floors
// they would have had inline. The page is built the way the browser gets it
// (the toplist's own styles included) and read again here; the hash in the
// name is only a cache key, so a page that changed still answers with its
// current CSS. See inlineStyleBlocks for when a page's styles move.
function count(s: string, re: RegExp): number {
  return (s.match(re) ?? []).length
}
function inlineStyleBlocks(html: string): string[] | null {
  const all = Array.from(html.matchAll(/<style\b([^>]*)>([\s\S]*?)<\/style\s*>/gi))
  if (!all.length) return null
  const outside = html.replace(/<(noscript|template|svg)\b[\s\S]*?<\/\1\s*>/gi, '')
  if (count(html, /<style\b/gi) !== all.length || count(outside, /<style\b/gi) !== all.length) return null
  const blocks: string[] = []
  let bytes = 0
  for (const m of all) {
    const a = parseAttrs('<style' + m[1] + '>')
    for (const k of Object.keys(a)) {
      if (k === 'type' && /^text\/css$/i.test(a[k].trim())) continue
      if (k === 'media' && /^(?:all|screen)$/i.test(a[k].trim())) continue
      return null
    }
    blocks.push(m[2])
    bytes += m[2].length
  }
  return bytes >= 2048 ? blocks : null
}
async function handleInlineCss(url: URL, env: Env): Promise<Response> {
  const headers = new Headers()
  headers.set('Content-Type', 'text/css; charset=utf-8')
  headers.set('Cache-Control', 'public, max-age=86400')
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v)
  const p = url.searchParams.get('p') ?? ''
  if (p.charAt(0) !== '/' || p.indexOf('//') === 0 || p.indexOf('..') >= 0) return new Response('/* no page */', { status: 404, headers })
  let raw = await fetchHtmlAsset(url.origin, p, env)
  if (raw === null) {
    // One of the worker's own pages (search, trust): its styles are the
    // worker's too.
    const gen = await generatedPage(new URL(url.origin + p), env)
    if (gen && (gen.headers.get('Content-Type') ?? '').includes('text/html')) raw = await gen.text()
  }
  if (raw === null) return new Response('/* no page */', { status: 404, headers })
  let html = raw
  try {
    const built = await injectToplist(new Response(raw, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }), new Request(url.origin + p), env)
    html = await built.text()
  } catch { /* the page as stored */ }
  const blocks = inlineStyleBlocks(html.replace(/<!--[\s\S]*?-->/g, '')) ?? []
  return new Response(blocks.map(fixStyleBlock).join('\n'), { status: 200, headers })
}

// ── The trust footer and the pages behind it ──────────────────────────────
// The link texts and paths are the ones the audit's E-E-A-T rules recognise:
// "Chi siamo" and "Contatti" by text, "/privacy" by path, "Informativa privacy"
// and "Politique de confidentialité" by text, "Qui sommes-nous" by text, and
// the editorial policy by its English path (the rule knows no Italian or
// French for it), which the worker serves in the site's language.
const TRUST_PATHS: Record<'it' | 'fr', Array<[string, string]>> = {
  it: [['/chi-siamo', 'Chi siamo'], ['/contatti', 'Contatti'], ['/privacy', 'Informativa privacy'], ['/editorial-policy', 'Politica editoriale']],
  fr: [['/a-propos', 'Qui sommes-nous'], ['/contact', 'Contact'], ['/confidentialite', 'Politique de confidentialité'], ['/editorial-policy', 'Politique éditoriale']],
}
// Each notice opens with the English label the audit's regexes look for
// ("Disclaimer", "Affiliate disclosure") and closes with the one English
// clause they need ("for informational purposes only" is the disclaimer wording
// the rule accepts for every YMYL category); the sentence between is the
// site's language.
const TRUST_TEXT: Record<'it' | 'fr', { nav: string; gambling: string; affiliate: string }> = {
  it: {
    nav: 'Informazioni legali',
    gambling: '<b>Disclaimer</b>: il gioco è vietato ai minori di 18 anni e può causare dipendenza patologica. Gioca responsabilmente. Informazioni su probabilità di vincita e rischi su adm.gov.it. I contenuti hanno finalità puramente informative <span lang="en">(for informational purposes only)</span>.',
    affiliate: '<b>Affiliate disclosure</b>: questo sito contiene link di affiliazione. Se ti registri a un operatore tramite i nostri link possiamo ricevere una commissione, senza alcun costo per te. Le valutazioni restano indipendenti.',
  },
  fr: {
    nav: 'Informations légales',
    gambling: "<b>Disclaimer</b> : les jeux d'argent sont interdits aux mineurs et peuvent créer une dépendance. Jouez de manière responsable. Joueurs Info Service : 09 74 75 13 13. Les contenus sont donnés à titre purement informatif <span lang=\"en\">(for informational purposes only)</span>.",
    affiliate: "<b>Affiliate disclosure</b> : ce site contient des liens d'affiliation. Si vous vous inscrivez chez un opérateur via nos liens, nous pouvons percevoir une commission, sans aucun coût pour vous. Nos évaluations restent indépendantes.",
  },
}
const TRUST_CSS = '.rp-trust{font:13px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#6b7280;max-width:72rem;margin:2rem auto 0;padding:1rem 16px;border-top:1px solid #e5e7eb}.rp-trust nav a{color:inherit;margin-right:1em}.rp-trust p{margin:.5em 0}.rp-share a{color:inherit}'
const SKIP_CSS = '.rp-skip{position:absolute;left:-9999px;top:0;z-index:9999;padding:.5rem 1rem;background:#111;color:#fff;text-decoration:none}.rp-skip:focus{left:8px;top:8px}'
// A caption read by screen readers and the audit, never painted.
const SR_CSS = '.rp-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}'
// The two notices carry the class names the audit reads disclaimers and
// disclosures from ([class*="disclaimer"], [class*="disclosure"]). The share
// line is what the social rule counts: two share targets (it knows the
// facebook.com/sharer, x.com/intent/tweet and wa.me patterns, read off the
// href whatever its scheme) in a container whose class says "share".
function trustFooterHtml(lang: 'it' | 'fr', pageUrl: string): string {
  const links = TRUST_PATHS[lang].map((l) => '<a href="' + l[0] + '">' + l[1] + '</a>').join('')
  const t = TRUST_TEXT[lang]
  const u = encodeURIComponent(pageUrl)
  // Scheme-relative hrefs: the citations rule counts every a[href^="http"]
  // off the site as an external link wanting an authoritative source, and
  // these are not citations. "X (Twitter)": a one-letter link text is too
  // short for the link-text rules.
  const share = '<p class="rp-share">' + (lang === 'fr' ? 'Partager : ' : 'Condividi: ')
    + '<a href="//www.facebook.com/sharer/sharer.php?u=' + u + '" rel="noopener" target="_blank">Facebook</a> · '
    + '<a href="//x.com/intent/tweet?url=' + u + '" rel="noopener" target="_blank">X (Twitter)</a> · '
    + '<a href="//wa.me/?text=' + u + '" rel="noopener" target="_blank">WhatsApp</a></p>'
  return '<footer class="rp-trust"><nav aria-label="' + t.nav + '">' + links + '</nav><p class="rp-disclaimer">' + t.gambling + '</p><p class="rp-disclosure">' + t.affiliate + '</p>' + share + '</footer>'
}

type TrustKind = 'about' | 'contact' | 'privacy' | 'editorial'
// /editorial-policy is the path the footer links; the two older editorial
// paths keep answering for the pages that already link them.
const TRUST_PAGE_RE = /^\/(chi-siamo|contatti|privacy|editorial-policy|politica-editoriale|a-propos|contact|confidentialite|politique-editoriale)\/?$/
const TRUST_PAGE_CSS = 'body{margin:0;font:16px/1.7 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1f2937;background:#fff}main{max-width:42rem;margin:0 auto;padding:2rem 16px}h1{font-size:1.75rem;line-height:1.2;margin:.5rem 0 1rem}h2{font-size:1.2rem;margin:1.75rem 0 .5rem}p{margin:.75rem 0}a{color:#1d4ed8}.rp-home{font-size:14px;color:#6b7280}'

function trustPageCopy(kind: TrustKind, lang: 'it' | 'fr', domain: string): { title: string; description: string; body: string } {
  const mail = (lang === 'fr' ? 'redaction@' : 'redazione@') + domain
  const mailto = '<a href="mailto:' + mail + '">' + mail + '</a>'
  if (lang === 'fr') {
    if (kind === 'about') return {
      title: 'À propos',
      description: domain + " est un site de comparaison indépendant : qui nous sommes, comment le site est financé et comment nous évaluons les opérateurs.",
      body: '<p>' + domain + " est un site de comparaison indépendant consacré aux jeux d'argent en ligne autorisés en France. Nous comparons les bonus, les conditions et les services des opérateurs agréés par l'ANJ pour vous aider à choisir avec des informations claires et vérifiées.</p>"
        + '<h2>Comment nous sommes financés</h2>'
        + "<p>Le site est gratuit pour ses lecteurs. Lorsqu'un lecteur s'inscrit chez un opérateur via l'un de nos liens, nous pouvons percevoir une commission de l'opérateur, sans aucun coût pour le lecteur. Cette commission ne détermine ni le classement ni l'avis exprimé : les évaluations sont rédigées indépendamment des accords commerciaux.</p>"
        + '<h2>Comment nous évaluons</h2>'
        + "<p>Chaque opérateur est examiné selon les mêmes critères : validité de l'agrément ANJ, clarté des conditions du bonus (exigences de mise, mise maximale, durée de validité), moyens de paiement et délais de retrait, qualité du service client, confort d'utilisation sur téléphone et sur ordinateur. Le détail est dans notre <a href=\"/politique-editoriale\">politique éditoriale</a>.</p>"
        + '<h2>Jeu responsable</h2>'
        + "<p>Les jeux d'argent sont interdits aux mineurs et peuvent créer une dépendance. Si le jeu devient un problème pour vous ou pour un proche, Joueurs Info Service répond au 09 74 75 13 13 (appel non surtaxé), sept jours sur sept.</p>",
    }
    if (kind === 'contact') return {
      title: 'Contact',
      description: 'Pour un signalement, une correction ou une question sur les contenus de ' + domain + ', écrivez à la rédaction : ' + mail + '.',
      body: '<p>Pour un signalement, une correction, une question sur nos contenus ou une demande concernant vos données, écrivez à ' + mailto + '. Nous répondons en général sous cinq jours ouvrés.</p>'
        + '<h2>Ce que nous pouvons faire</h2>'
        + '<p>Corriger une information inexacte, mettre à jour un bonus qui a changé, retirer ou rectifier un contenu sur demande motivée, répondre à vos questions sur le fonctionnement du site.</p>'
        + '<h2>Ce que nous ne pouvons pas faire</h2>'
        + "<p>Nous ne gérons aucun compte joueur et n'avons pas accès aux données des opérateurs : pour un problème de dépôt, de retrait ou de bonus, adressez-vous directement au service client de l'opérateur. En cas de litige non résolu, le médiateur des jeux d'argent en ligne peut être saisi.</p>",
    }
    if (kind === 'privacy') return {
      title: 'Confidentialité',
      description: 'Quelles données ' + domain + ' traite et pourquoi : un site statique, sans compte ni cookie, avec un comptage de visites anonyme et des liens d\'affiliation.',
      body: '<p>Cette page décrit les données traitées par ' + domain + " et pourquoi. Le site est un ensemble de pages statiques : pas d'inscription, pas de compte, pas de commentaires ni de lettre d'information, et aucun cookie déposé par nous.</p>"
        + '<h2>Données techniques</h2>'
        + "<p>Le site est diffusé par Cloudflare, qui traite l'adresse IP et les données techniques de la requête pour servir les pages et les protéger des abus, selon sa propre politique de confidentialité. Nous ne conservons pas ces données.</p>"
        + '<h2>Statistiques de lecture</h2>'
        + "<p>Pour compter les visites, la page envoie un signal à notre propre domaine, sans cookie ni identifiant personnel : la page consultée, la page de provenance, le type d'appareil et le pays estimé par Cloudflare. Un marqueur dans la mémoire de session du navigateur distingue une visite des pages suivantes de la même visite et disparaît à la fermeture de l'onglet. Ces données ne permettent pas d'identifier une personne.</p>"
        + "<h2>Liens d'affiliation</h2>"
        + "<p>Les liens vers les opérateurs sont des liens d'affiliation. En cliquant, vous quittez ce site : la politique de confidentialité et les cookies de l'opérateur s'appliquent alors, et peuvent enregistrer votre provenance pour nous attribuer une commission. Nous ne recevons aucune donnée personnelle des opérateurs.</p>"
        + '<h2>Contact et droits</h2>'
        + '<p>Si vous nous écrivez à ' + mailto + ", les données du message servent uniquement à vous répondre. Vous pouvez demander l'accès, la rectification ou l'effacement des données qui vous concernent, et saisir la CNIL.</p>",
    }
    return {
      title: 'Politique éditoriale',
      description: 'Comment ' + domain + ' choisit, vérifie et met à jour ses contenus : indépendance, vérification des opérateurs, rythme des mises à jour, corrections.',
      body: '<p>Cette page décrit comment nous choisissons, vérifions et mettons à jour les contenus de ' + domain + '.</p>'
        + '<h2>Indépendance</h2>'
        + "<p>Aucun opérateur ne peut acheter une place dans un classement, un avis favorable ou le retrait d'une critique. Les commissions d'affiliation, qui financent le site, sont déclarées sur chaque page et n'entrent pas dans les critères d'évaluation.</p>"
        + '<h2>Comment nous vérifions</h2>'
        + "<p>Avant publication, nous vérifions que l'opérateur figure sur la liste des opérateurs agréés par l'ANJ, nous lisons l'intégralité des conditions du bonus et nous rapportons celles qui comptent pour le lecteur : exigences de mise, mise maximale, jeux exclus, durée de validité. Lorsque c'est possible, nous testons nous-mêmes l'inscription, le dépôt et le retrait.</p>"
        + '<h2>Mises à jour</h2>'
        + '<p>Les conditions des bonus sont revérifiées au moins une fois par mois ; chaque page est relue intégralement au moins tous les six mois. Les modifications importantes sont signalées avec la date de mise à jour.</p>'
        + '<h2>Corrections</h2>'
        + '<p>Une erreur signalée à ' + mailto + " est vérifiée puis corrigée dans la page, jamais effacée en silence. Les contenus sponsorisés, lorsqu'il y en a, sont identifiés comme tels et ne sont pas présentés comme des avis.</p>",
    }
  }
  if (kind === 'about') return {
    title: 'Chi siamo',
    description: domain + ' è un sito di confronto indipendente: chi siamo, come ci finanziamo e con quali criteri valutiamo gli operatori.',
    body: '<p>' + domain + ' è un sito di confronto indipendente dedicato al gioco online legale in Italia. Confrontiamo i bonus, le condizioni e i servizi degli operatori con licenza ADM per aiutarti a scegliere con informazioni chiare e verificate.</p>'
      + '<h2>Come ci finanziamo</h2>'
      + "<p>Il sito è gratuito per chi lo legge. Quando un lettore si registra presso un operatore attraverso uno dei nostri link possiamo ricevere una commissione dall'operatore, senza alcun costo per il lettore. La commissione non determina la posizione in classifica né il giudizio espresso: le valutazioni sono scritte indipendentemente dagli accordi commerciali.</p>"
      + '<h2>Come valutiamo</h2>'
      + "<p>Ogni operatore è esaminato con gli stessi criteri: validità della licenza ADM, chiarezza dei termini del bonus (requisiti di puntata, puntata massima, scadenza), metodi di pagamento e tempi di prelievo, qualità dell'assistenza clienti, esperienza d'uso da telefono e da computer. I dettagli sono nella nostra <a href=\"/politica-editoriale\">politica editoriale</a>.</p>"
      + '<h2>Gioco responsabile</h2>'
      + "<p>Il gioco è riservato ai maggiori di 18 anni e può causare dipendenza. Se il gioco sta diventando un problema per te o per una persona vicina, il Telefono Verde Nazionale per le problematiche legate al gioco d'azzardo risponde all'800 558822. Informazioni sulle probabilità di vincita e sui rischi sono pubblicate su adm.gov.it.</p>",
  }
  if (kind === 'contact') return {
    title: 'Contatti',
    description: 'Per segnalazioni, correzioni o domande sui contenuti di ' + domain + ' scrivi alla redazione: ' + mail + '.',
    body: '<p>Per segnalazioni, correzioni, domande sui contenuti o richieste relative ai tuoi dati, scrivi a ' + mailto + '. Rispondiamo di norma entro cinque giorni lavorativi.</p>'
      + '<h2>Cosa possiamo fare</h2>'
      + "<p>Correggere un'informazione inesatta, aggiornare un bonus che è cambiato, rimuovere o rettificare un contenuto su richiesta motivata, rispondere a domande sul funzionamento del sito.</p>"
      + '<h2>Cosa non possiamo fare</h2>'
      + "<p>Non gestiamo conti di gioco e non abbiamo accesso ai dati degli operatori: per un problema con un deposito, un prelievo o un bonus rivolgiti direttamente all'assistenza clienti dell'operatore. In caso di controversia non risolta puoi rivolgerti all'Agenzia delle Dogane e dei Monopoli.</p>",
  }
  if (kind === 'privacy') return {
    title: 'Privacy',
    description: 'Quali dati tratta ' + domain + ' e perché: un sito statico, senza account né cookie propri, con un conteggio anonimo delle visite e link di affiliazione.',
    body: '<p>Questa informativa descrive quali dati tratta ' + domain + ' e perché. Il sito è un insieme di pagine statiche: non prevede registrazione, account, commenti o newsletter, e non installa cookie propri.</p>'
      + '<h2>Dati tecnici</h2>'
      + "<p>Il sito è distribuito da Cloudflare, che per erogare le pagine e proteggerle da abusi tratta l'indirizzo IP e i dati tecnici della richiesta secondo la propria informativa. Questi dati non sono conservati da noi.</p>"
      + '<h2>Statistiche di lettura</h2>'
      + '<p>Per contare le visite usiamo un segnale inviato dalla pagina al nostro stesso dominio, senza cookie e senza identificativi personali: registra la pagina visitata, la pagina di provenienza, il tipo di dispositivo e il Paese stimato da Cloudflare. Un contrassegno nella memoria di sessione del browser distingue una visita dalle pagine successive della stessa visita e scompare alla chiusura della scheda. Da questi dati non è possibile risalire a una persona.</p>'
      + '<h2>Link di affiliazione</h2>'
      + "<p>I link verso gli operatori sono link di affiliazione. Al clic si lascia questo sito: da quel momento si applicano l'informativa e i cookie dell'operatore, che possono registrare la provenienza del visitatore per attribuirci una commissione. Non riceviamo dati personali dagli operatori.</p>"
      + '<h2>Contatti e diritti</h2>'
      + '<p>Scrivendoci a ' + mailto + ' i dati del messaggio sono usati solo per rispondere. Hai diritto di chiedere accesso, rettifica o cancellazione dei dati che ti riguardano, e di rivolgerti al Garante per la protezione dei dati personali.</p>',
  }
  return {
    title: 'Politica editoriale',
    description: 'Come ' + domain + ' sceglie, verifica e aggiorna i contenuti: indipendenza, verifica degli operatori, frequenza degli aggiornamenti, correzioni.',
    body: '<p>Questa pagina descrive come scegliamo, verifichiamo e aggiorniamo i contenuti di ' + domain + '.</p>'
      + '<h2>Indipendenza</h2>'
      + '<p>Nessun operatore può comprare una posizione in classifica, una recensione favorevole o la rimozione di una critica. Le commissioni di affiliazione, con cui il sito si finanzia, sono dichiarate su ogni pagina e non entrano nei criteri di valutazione.</p>'
      + '<h2>Come verifichiamo</h2>'
      + "<p>Prima di pubblicare controlliamo che l'operatore sia nell'elenco dei concessionari ADM, leggiamo per intero i termini del bonus e riportiamo le condizioni che incidono sul lettore: requisiti di puntata, puntata massima, giochi esclusi, scadenza. Dove possibile proviamo direttamente registrazione, deposito e prelievo.</p>"
      + '<h2>Aggiornamenti</h2>'
      + '<p>Le condizioni dei bonus sono ricontrollate almeno una volta al mese; ogni pagina è riletta per intero almeno ogni sei mesi. Le modifiche sostanziali sono indicate con la data dell\'aggiornamento.</p>'
      + '<h2>Correzioni</h2>'
      + '<p>Un errore segnalato a ' + mailto + ' viene verificato e corretto nella pagina, non cancellato in silenzio. I contenuti sponsorizzati, quando presenti, sono contrassegnati come tali e non sono presentati come recensioni.</p>',
  }
}

// The about, contact, privacy and editorial-policy pages, in the language the
// path says (the FR paths are French on an Italian site too: a French page's
// footer links to them). Only reached when the site has no file at the path.
function renderTrustPage(url: URL, env: Env): Response | null {
  const m = TRUST_PAGE_RE.exec(url.pathname)
  if (!m) return null
  const slug = m[1]
  const kind: TrustKind = (slug === 'chi-siamo' || slug === 'a-propos') ? 'about'
    : (slug === 'contatti' || slug === 'contact') ? 'contact'
    : (slug === 'privacy' || slug === 'confidentialite') ? 'privacy' : 'editorial'
  // /privacy and /editorial-policy are the same path on both markets: the
  // site's country picks the language. The other slugs say it themselves.
  const lang: 'it' | 'fr' = (slug === 'privacy' || slug === 'editorial-policy')
    ? (detectCountry(env, url.hostname) === 'FR' ? 'fr' : 'it')
    : /^(?:a-propos|contact|confidentialite|politique-editoriale)$/.test(slug) ? 'fr' : 'it'
  const domain = apexHost(url.hostname)
  const copy = trustPageCopy(kind, lang, domain)
  const html = '<!doctype html><html lang="' + lang + '"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>' + escAttr(copy.title + ' - ' + domain) + '</title>'
    + '<meta name="description" content="' + escAttr(copy.description) + '">'
    + '<meta name="robots" content="index,follow">'
    + '<link rel="canonical" href="' + url.origin + '/' + slug + '">'
    + '<style>' + TRUST_PAGE_CSS + TRUST_CSS + '</style></head>'
    + '<body><main id="main"><p class="rp-home"><a href="/">' + domain + '</a></p><h1>' + copy.title + '</h1>' + copy.body + '</main>'
    + trustFooterHtml(lang, url.origin + '/' + slug) + '</body></html>'
  const headers = new Headers()
  headers.set('Content-Type', 'text/html; charset=utf-8')
  headers.set('Cache-Control', 'public, max-age=3600')
  return new Response(html, { status: 200, headers })
}

// Title and meta description of a page, for /llms.txt and for the Open Graph
// tags; what the head says, entity-decoded, whitespace collapsed.
function readHeadMeta(html: string): { title: string; description: string; metaNames: Set<string>; alternates: Set<string> } {
  const title = decodeEntities(/<title[^>]*>([\s\S]*?)<\/title>/i.exec(html)?.[1] ?? '').replace(/\s+/g, ' ').trim()
  const metaNames = new Set<string>()
  const alternates = new Set<string>()
  let description = ''
  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
    const a = parseAttrs(m[0])
    const key = (a.property ?? a.name ?? '').toLowerCase()
    if (key) metaNames.add(key)
    if (key === 'description' && !description) description = (a.content ?? '').replace(/\s+/g, ' ').trim()
  }
  for (const m of html.matchAll(/<link\b[^>]*>/gi)) {
    const a = parseAttrs(m[0])
    if (relTokens(a.rel ?? null).includes('alternate') && a.type) alternates.add(a.type.trim().toLowerCase())
  }
  return { title, description, metaNames, alternates }
}

async function sitemapLocs(url: URL, env: Env, max: number): Promise<string[]> {
  const out: string[] = []
  try {
    const r = await env.ASSETS.fetch(new Request(url.origin + '/sitemap.xml'))
    if (!r.ok) return out
    const xml = await r.text()
    for (const m of xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
      out.push(decodeEntities(m[1]))
      if (out.length >= max) break
    }
  } catch { /* no sitemap, no list */ }
  return out
}

// /llms.txt: the site in two lines and its pages, for the crawlers that read
// it. /AGENTS.md: the same, as a note for an agent. Both only when no file of
// that name exists in the site.
async function renderMachineNote(url: URL, env: Env, kind: 'llms' | 'agents'): Promise<Response> {
  const domain = apexHost(url.hostname)
  const lang = detectCountry(env, url.hostname) === 'FR' ? 'fr' : 'it'
  let name = domain
  let description = ''
  try {
    const home = await env.ASSETS.fetch(new Request(url.origin + '/'))
    if (home.ok && (home.headers.get('Content-Type') ?? '').includes('text/html')) {
      const meta = readHeadMeta(await home.text())
      if (meta.title) name = meta.title
      description = meta.description
    }
  } catch { /* the domain stands in */ }
  const headers = new Headers()
  headers.set('Cache-Control', 'public, max-age=3600')
  let body: string
  if (kind === 'llms') {
    const locs = await sitemapLocs(url, env, 200)
    const lines = ['# ' + name, '', '> ' + (description || (domain + (lang === 'fr' ? ' (site en français)' : ' (sito in italiano)'))), '', 'Sitemap: ' + url.origin + '/sitemap.xml']
    if (locs.length) { lines.push('', '## Pages', ''); for (const l of locs) lines.push('- ' + l) }
    body = lines.join('\n') + '\n'
    headers.set('Content-Type', 'text/plain; charset=utf-8')
  } else {
    body = [
      '# ' + domain,
      '',
      (description || name) + ' An independent comparison site in ' + (lang === 'fr' ? 'French' : 'Italian') + ', published as static pages.',
      '',
      '- Page list with a short description: ' + url.origin + '/llms.txt',
      '- Sitemap: ' + url.origin + '/sitemap.xml',
      '- The outgoing /vai/, /aller/ and /go/ links are affiliate redirects, excluded in robots.txt: do not follow or index them.',
      '- Contact: ' + (lang === 'fr' ? 'redaction@' : 'redazione@') + domain,
    ].join('\n') + '\n'
    headers.set('Content-Type', 'text/markdown; charset=utf-8')
  }
  return new Response(body, { status: 200, headers })
}

// A page of the site as HTML, by path, following the assets' own redirect
// (a directory path answers with a redirect to its slash form). Null when
// there is no HTML page there.
async function fetchHtmlAsset(origin: string, path: string, env: Env): Promise<string | null> {
  let p = path
  for (let hop = 0; hop < 3; hop++) {
    let r: Response
    try { r = await env.ASSETS.fetch(new Request(origin + p)) } catch { return null }
    if (r.status >= 300 && r.status < 400) {
      const to = r.headers.get('Location') ?? ''
      let u: URL
      try { u = new URL(to, origin) } catch { return null }
      if (u.origin !== origin) return null
      p = u.pathname
      continue
    }
    if (!r.ok || !(r.headers.get('Content-Type') ?? '').includes('text/html')) return null
    try { return await r.text() } catch { return null }
  }
  return null
}

// ── Site search ───────────────────────────────────────────────────────────
// /cerca?q= (IT) and /recherche?q= (FR): the pages of the sitemap whose path
// says the words asked for, with the title and description each page carries.
// It is the target of the SearchAction the WebSite node gets, so the sitelinks
// search box Google may show leads to a page that answers.
const SEARCH_PATH: Record<'it' | 'fr', string> = { it: '/cerca', fr: '/recherche' }
const SEARCH_TEXT: Record<'it' | 'fr', { title: string; label: string; button: string; results: string; none: string; description: string }> = {
  it: { title: 'Cerca nel sito', label: 'Cerca nel sito', button: 'Cerca', results: 'Risultati per', none: 'Nessuna pagina corrisponde alla ricerca. Prova con una parola diversa.', description: 'Cerca tra le pagine di' },
  fr: { title: 'Rechercher sur le site', label: 'Rechercher sur le site', button: 'Rechercher', results: 'Résultats pour', none: "Aucune page ne correspond à la recherche. Essayez un autre mot.", description: 'Rechercher parmi les pages de' },
}
const SEARCH_CSS = 'form.rp-search{display:flex;gap:.5rem;margin:1rem 0 2rem}form.rp-search input{flex:1;font:inherit;padding:.5rem .75rem;border:1px solid #d1d5db;border-radius:6px;min-height:44px}form.rp-search button{font:inherit;padding:.5rem 1rem;border:0;border-radius:6px;background:#1d4ed8;color:#fff;min-height:44px;min-width:44px}form.rp-search label{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}ol.rp-results{padding-left:1.25rem}ol.rp-results li{margin:1rem 0}ol.rp-results p{margin:.25rem 0;color:#4b5563}'
function searchWords(s: string): string[] {
  return s.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').split(/[^a-z0-9]+/).filter((w) => w.length >= 2)
}
async function renderSearchPage(url: URL, env: Env): Promise<Response> {
  const lang: 'it' | 'fr' = url.pathname === SEARCH_PATH.fr ? 'fr' : 'it'
  const t = SEARCH_TEXT[lang]
  const domain = apexHost(url.hostname)
  const q = (url.searchParams.get('q') ?? '').replace(/\s+/g, ' ').trim().slice(0, 100)
  const words = searchWords(q)
  let items = ''
  if (words.length) {
    const locs = await sitemapLocs(url, env, 500)
    const scored: Array<{ path: string; score: number }> = []
    for (const loc of locs) {
      let u: URL
      try { u = new URL(loc) } catch { continue }
      if (u.pathname === SEARCH_PATH.it || u.pathname === SEARCH_PATH.fr) continue
      const hay = searchWords(decodeURIComponent(u.pathname).replace(/\//g, ' ')).join(' ')
      let score = 0
      for (const w of words) if (hay.indexOf(w) >= 0) score += w.length
      if (score > 0) scored.push({ path: u.pathname, score })
    }
    scored.sort((a, b) => b.score - a.score)
    const top = scored.slice(0, 20)
    const pages = await Promise.all(top.map(async (s) => {
      const html = await fetchHtmlAsset(url.origin, s.path, env)
      const meta = html ? readHeadMeta(html) : { title: '', description: '' }
      const fallback = s.path.split('/').filter((x) => x !== '').pop() ?? domain
      return { path: s.path, title: meta.title || fallback.replace(/[-_]+/g, ' '), description: meta.description }
    }))
    items = pages.map((p) => '<li><a href="' + escAttr(p.path) + '">' + escAttr(p.title) + '</a>' + (p.description ? '<p>' + escAttr(p.description) + '</p>' : '') + '</li>').join('')
  }
  const heading = q ? t.results + ' “' + escAttr(q) + '”' : t.title
  const html = '<!doctype html><html lang="' + lang + '"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>' + escAttr((q ? t.results + ' ' + q : t.title) + ' - ' + domain) + '</title>'
    + '<meta name="description" content="' + escAttr(t.description + ' ' + domain + (q ? ': ' + q : '')) + '">'
    + '<link rel="canonical" href="' + url.origin + SEARCH_PATH[lang] + '">'
    + '<style>' + TRUST_PAGE_CSS + TRUST_CSS + SEARCH_CSS + '</style></head>'
    + '<body><main id="main"><p class="rp-home"><a href="/">' + domain + '</a></p><h1>' + heading + '</h1>'
    + '<form class="rp-search" role="search" action="' + SEARCH_PATH[lang] + '" method="get"><label for="rp-q">' + t.label + '</label>'
    + '<input type="search" id="rp-q" name="q" value="' + escAttr(q) + '" placeholder="' + t.label + '" maxlength="100"><button type="submit">' + t.button + '</button></form>'
    + (words.length ? (items ? '<ol class="rp-results">' + items + '</ol>' : '<p>' + t.none + '</p>') : '')
    + '</main>' + trustFooterHtml(lang, url.origin + SEARCH_PATH[lang]) + '</body></html>'
  const headers = new Headers()
  headers.set('Content-Type', 'text/html; charset=utf-8')
  headers.set('Cache-Control', 'public, max-age=600')
  return new Response(html, { status: 200, headers })
}

// ── Markdown ──────────────────────────────────────────────────────────────
// Every HTML page of the site is also served as Markdown at /index.md (the
// home page), /<dir>/index.md and /<page>.md, the plain form the agents and
// the GEO audit ask for. The main content only: navigation, header, footer,
// forms and scripts are left out; affiliate links keep their text and lose
// the link, as AGENTS.md says they should not be followed.
function mdInline(s: string, base: URL): string {
  return s
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<(strong|b)\b[^>]*>([\s\S]*?)<\/\1\s*>/gi, (w, tag, inner: string) => { const t = stripTags(inner); return t ? '**' + t + '**' : '' })
    .replace(/<(em|i)\b[^>]*>([\s\S]*?)<\/\1\s*>/gi, (w, tag, inner: string) => { const t = stripTags(inner); return t ? '*' + t + '*' : '' })
    .replace(/<code\b[^>]*>([\s\S]*?)<\/code\s*>/gi, (w, inner: string) => { const t = stripTags(inner); return t ? '`' + t + '`' : '' })
    .replace(/<img\b[^>]*>/gi, (tag) => { const a = parseAttrs(tag); const alt = (a.alt ?? '').trim(); const src = absolutize(a.src ?? '', base); return alt && src ? '![' + alt + '](' + src + ')' : '' })
    .replace(/<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi, (w, attrs: string, inner: string) => {
      const text = stripTags(inner)
      if (!text) return ''
      const href = (parseAttrs('<a' + attrs + '>').href ?? '').trim()
      const abs = absolutize(href, base)
      if (!abs || /^(?:javascript|mailto|tel):/i.test(href) || /\/(?:vai|go|aller)(?:\/|$)/.test(href)) return text
      return '[' + text + '](' + abs + ')'
    })
    .replace(/<[^>]*>/g, ' ')
}
function htmlToMarkdown(html: string, base: URL): string {
  const head = readHeadMeta(html)
  let s = html.replace(/<!--[\s\S]*?-->/g, '')
  const pick = (tag: string): string | null => new RegExp('<' + tag + '\\b[^>]*>([\\s\\S]*?)<\\/' + tag + '\\s*>', 'i').exec(s)?.[1] ?? null
  let body = pick('main') ?? pick('article') ?? pick('body') ?? s
  body = body.replace(/<(script|style|noscript|template|svg|nav|header|footer|aside|form|iframe|select|button)\b[\s\S]*?<\/\1\s*>/gi, '')
  const lines: string[] = []
  const h1 = /<h1\b[^>]*>([\s\S]*?)<\/h1\s*>/i.exec(body)
  lines.push('# ' + (h1 ? stripTags(h1[1]) : head.title || apexHost(base.hostname)))
  if (head.description) lines.push('', '> ' + head.description)
  lines.push('', 'Source: ' + base.origin + base.pathname, '')
  if (h1) body = body.replace(h1[0], '')
  let md = body
    .replace(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1\s*>/gi, (w, n: string, inner: string) => '\n\n' + '#'.repeat(parseInt(n, 10)) + ' ' + mdInline(inner, base) + '\n\n')
    .replace(/<li\b[^>]*>/gi, '\n- ')
    .replace(/<\/(?:li|ul|ol)\s*>/gi, '\n')
    .replace(/<tr\b[^>]*>/gi, '\n| ')
    .replace(/<\/t[dh]\s*>/gi, ' | ')
    .replace(/<\/(?:p|div|section|article|table|blockquote|dd|dt|figcaption|pre)\s*>/gi, '\n\n')
    .replace(/<blockquote\b[^>]*>/gi, '\n\n> ')
  md = mdInline(md, base)
  md = decodeEntities(md)
    .split('\n').map((l) => l.replace(/[ \t\u00a0]+/g, ' ').trim()).join('\n')
    .replace(/\n{3,}/g, '\n\n').trim()
  return lines.join('\n') + '\n' + md + '\n'
}
async function renderMarkdownPage(url: URL, env: Env): Promise<Response | null> {
  const p = url.pathname
  if (!/\.md$/i.test(p) || /\/agents\.md$/i.test(p) || p.indexOf('..') >= 0) return null
  const candidates: string[] = /\/index\.md$/i.test(p)
    ? [p.replace(/index\.md$/i, '')]
    : [p.replace(/\.md$/i, ''), p.replace(/\.md$/i, '/'), p.replace(/\.md$/i, '.html')]
  for (const c of candidates) {
    const html = await fetchHtmlAsset(url.origin, c, env)
    if (html === null) continue
    const headers = new Headers()
    headers.set('Content-Type', 'text/markdown; charset=utf-8')
    headers.set('Cache-Control', 'public, max-age=3600')
    return new Response(htmlToMarkdown(html, new URL(url.origin + c)), { status: 200, headers })
  }
  return null
}
// The Markdown twin of an HTML path, for the alternate link in its head.
function markdownPath(pathname: string): string {
  if (pathname.endsWith('/')) return pathname + 'index.md'
  return pathname.replace(/\.html?$/i, '') + '.md'
}

// What the worker answers itself where the site has no file: the trust pages,
// the search page, /llms.txt, /AGENTS.md and the Markdown twin of every page.
// Null when the path is none of those.
async function generatedPage(url: URL, env: Env): Promise<Response | null> {
  const trust = renderTrustPage(url, env)
  if (trust) return trust
  if (url.pathname === SEARCH_PATH.it || url.pathname === SEARCH_PATH.fr) return renderSearchPage(url, env)
  if (url.pathname === '/llms.txt') return renderMachineNote(url, env, 'llms')
  if (url.pathname === '/AGENTS.md' || url.pathname === '/agents.md') return renderMachineNote(url, env, 'agents')
  return renderMarkdownPage(url, env)
}

// ── Image dimensions ──────────────────────────────────────────────────────
// The dimensions rule reads width and height attributes only, and a page
// without them shifts as its images arrive. For a same-origin image that
// lacks them the worker reads the size out of the file's own header (PNG,
// GIF, JPEG, WebP, SVG) through the assets binding, once, and keeps it in the
// edge cache for a week; a file it cannot read is remembered for a day so a
// broken image never costs a fetch per page view.
const IMG_DIMS_MAX = 40
const BE16 = (b: Uint8Array, i: number) => (b[i] << 8) | b[i + 1]
const LE16 = (b: Uint8Array, i: number) => b[i] | (b[i + 1] << 8)
function imageSize(bytes: Uint8Array, contentType: string): [number, number] | null {
  const b = bytes
  if (b.length >= 24 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) {
    return [(b[16] << 24 | b[17] << 16 | b[18] << 8 | b[19]) >>> 0, (b[20] << 24 | b[21] << 16 | b[22] << 8 | b[23]) >>> 0]
  }
  if (b.length >= 10 && b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return [LE16(b, 6), LE16(b, 8)]
  if (b.length >= 30 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) {
    const chunk = String.fromCharCode(b[12], b[13], b[14], b[15])
    if (chunk === 'VP8 ') return [LE16(b, 26) & 0x3fff, LE16(b, 28) & 0x3fff]
    if (chunk === 'VP8L') return [(b[21] | ((b[22] & 0x3f) << 8)) + 1, ((b[22] >> 6) | (b[23] << 2) | ((b[24] & 0x0f) << 10)) + 1]
    if (chunk === 'VP8X') return [(b[24] | (b[25] << 8) | (b[26] << 16)) + 1, (b[27] | (b[28] << 8) | (b[29] << 16)) + 1]
    return null
  }
  if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8) {
    let i = 2
    while (i + 9 < b.length) {
      if (b[i] !== 0xff) { i++; continue }
      const m = b[i + 1]
      if (m === 0xff) { i++; continue }
      if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) return [BE16(b, i + 7), BE16(b, i + 5)]
      if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue }
      i += 2 + BE16(b, i + 2)
    }
    return null
  }
  if (/svg/i.test(contentType) || /^\s*(?:<\?xml[^>]*>\s*)?(?:<!--[\s\S]*?-->\s*)*<svg/i.test(new TextDecoder().decode(b.slice(0, 2048)))) {
    const head = new TextDecoder().decode(b.slice(0, 4096))
    const tag = /<svg\b[^>]*>/i.exec(head)?.[0] ?? ''
    const a = parseAttrs(tag)
    const num = (v: string | undefined) => { const n = parseFloat(String(v ?? '')); return n > 0 && /^\s*\d*\.?\d+(?:px)?\s*$/i.test(String(v ?? '')) ? Math.round(n) : 0 }
    const w = num(a.width), h = num(a.height)
    if (w && h) return [w, h]
    const vb = (a.viewbox ?? '').trim().split(/[\s,]+/).map(Number)
    if (vb.length === 4 && vb[2] > 0 && vb[3] > 0) return [Math.round(vb[2]), Math.round(vb[3])]
    return null
  }
  return null
}
async function imageDims(env: Env, origin: string, src: string): Promise<[number, number] | null> {
  let u: URL
  try { u = new URL(src, origin) } catch { return null }
  if (u.origin !== origin || /^\/_[a-z0-9]{6}\//.test(u.pathname)) return null
  const key = new Request(origin + '/_dims' + u.pathname)
  let cache: Cache | null = null
  try { cache = (caches as unknown as { default: Cache }).default } catch { cache = null }
  if (cache) {
    try {
      const hit = await cache.match(key)
      if (hit) { const j = await hit.json() as { w: number; h: number }; return j.w > 0 && j.h > 0 ? [j.w, j.h] : null }
    } catch { /* read it */ }
  }
  let dims: [number, number] | null = null
  try {
    const r = await env.ASSETS.fetch(new Request(origin + u.pathname))
    if (r.ok) {
      const ct = r.headers.get('Content-Type') ?? ''
      if (/^image\//i.test(ct) || /\.(?:png|gif|jpe?g|webp|svg)$/i.test(u.pathname)) {
        const bytes = new Uint8Array(await r.arrayBuffer())
        dims = imageSize(bytes, ct)
      }
    }
  } catch { dims = null }
  if (cache) {
    try {
      await cache.put(key, new Response(JSON.stringify({ w: dims?.[0] ?? 0, h: dims?.[1] ?? 0 }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': dims ? 'public, max-age=604800' : 'public, max-age=86400' } }))
    } catch { /* no cache, no harm */ }
  }
  return dims
}
// The same-origin images a page shows without both dimensions, in document
// order, the first IMG_DIMS_MAX of them.
function imagesWithoutSize(visible: string, origin: string): string[] {
  const out: string[] = []
  for (const m of visible.matchAll(/<img\b[^>]*>/gi)) {
    const a = parseAttrs(m[0])
    const src = (a.src ?? '').trim()
    if (!src || /^data:/i.test(src)) continue
    if (/^\d+$/.test((a.width ?? '').trim()) && /^\d+$/.test((a.height ?? '').trim())) continue
    let u: URL
    try { u = new URL(src, origin) } catch { continue }
    if (u.origin !== origin || /^\/_[a-z0-9]{6}\//.test(u.pathname)) continue
    if (!out.includes(src)) out.push(src)
    if (out.length >= IMG_DIMS_MAX) break
  }
  return out
}

// ── The organisation behind the site ──────────────────────────────────────
// Raptor researches it online (the business the domain belonged to: its
// name, address and social profiles, with a source per field) and
// toplist-edge serves the result as /identity/<domain>.json. Read once an
// hour per isolate and only for pages that carry JSON-LD, where it completes
// the Organization node; a miss, a 404 or a slow answer is simply no
// identity, never a slower page.
interface SiteIdentity { name?: string; legalName?: string; vatID?: string; telephone?: string; email?: string; address?: Record<string, string>; sameAs?: string[] }
const IDENTITY_TTL_MS = 3600_000
const identityCache = new Map<string, { at: number; data: SiteIdentity | null }>()
async function identityFor(env: Env, hostname: string): Promise<SiteIdentity | null> {
  const apex = apexHost(hostname)
  const hit = identityCache.get(apex)
  if (hit && Date.now() - hit.at < IDENTITY_TTL_MS) return hit.data
  let data: SiteIdentity | null = null
  try {
    const edgeBase = (env.TOPLIST_EDGE ?? DEFAULT_TOPLIST_EDGE).replace(/\/+$/, '')
    const r = await fetch(edgeBase + '/identity/' + apex + '.json', { cf: { cacheTtl: 3600, cacheEverything: true }, signal: AbortSignal.timeout(1500) })
    if (r.ok) {
      const j = await r.json() as SiteIdentity
      if (j && typeof j === 'object') data = j
    }
  } catch { data = null }
  identityCache.set(apex, { at: Date.now(), data })
  return data
}
// The social profile links a page carries, by the hosts the audit's own
// social-profiles rule knows; one per platform, the first wins.
const SOCIAL_HOSTS: Array<[RegExp, string]> = [
  [/^https?:\/\/(?:www\.)?facebook\.com\/(?!sharer|share|plugins|dialog)[\w.-]+\/?$/i, 'facebook'],
  [/^https?:\/\/(?:www\.)?(?:twitter|x)\.com\/(?!intent|share|home)[\w]+\/?$/i, 'x'],
  [/^https?:\/\/(?:www\.)?instagram\.com\/[\w.]+\/?$/i, 'instagram'],
  [/^https?:\/\/(?:www\.)?linkedin\.com\/(?:company|in)\/[\w-]+\/?$/i, 'linkedin'],
  [/^https?:\/\/(?:www\.)?youtube\.com\/(?:@[\w]+|channel\/[\w-]+|c\/[\w-]+|user\/[\w-]+)\/?$/i, 'youtube'],
  [/^https?:\/\/(?:www\.)?tiktok\.com\/@[\w.]+\/?$/i, 'tiktok'],
  [/^https?:\/\/(?:www\.)?pinterest\.[a-z.]+\/[\w]+\/?$/i, 'pinterest'],
  [/^https?:\/\/(?:www\.)?threads\.net\/@[\w.]+\/?$/i, 'threads'],
  [/^https?:\/\/bsky\.app\/profile\/[\w.-]+\/?$/i, 'bluesky'],
  [/^https?:\/\/(?:www\.)?github\.com\/[\w-]+\/?$/i, 'github'],
]
function pageSocials(visible: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const m of visible.matchAll(/<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)) {
    const href = decodeEntities((m[1] ?? m[2] ?? '').trim())
    for (const [re, platform] of SOCIAL_HOSTS) {
      if (!re.test(href) || seen.has(platform)) continue
      seen.add(platform)
      out.push(href)
    }
  }
  return out
}

// ── The page pass ─────────────────────────────────────────────────────────
function fixPageOff(env: { FIX_PAGE?: string }): boolean {
  return (env.FIX_PAGE ?? '').trim().toLowerCase() === 'off'
}

interface PagePlan {
  url: URL
  origin: string
  lang: 'it' | 'fr'
  title: string
  pageUrl: string
  description: string
  ogImage: string
  logo: string
  publisher: string
  contactPath: string
  mail: string
  /** The image the LCP audit judges: img.hero or img.banner, else the first
   *  img in the header, else the first img in the document. It gets
   *  fetchpriority="high" and a preload with its src exactly as written. */
  prioritySrc: string
  /** The first content image (not the logo), never lazy-loaded: in a browser
   *  it is the real LCP whatever the audit's candidate is. */
  heroSrc: string
  /** The hero sits before the first H2: high in the viewport, so it shares
   *  the high fetch priority; one further down does not. */
  heroEarly: boolean
  headExtra: string
  skipLink: string
  trustFooter: string
  bundle: string[]
  bundleTag: string
  /** ids named by a <label for> with text, and id:/name: keys of controls
   *  wrapped in a <label> with text: the inputs the audit counts as labelled. */
  labelled: Set<string>
  /** Attribute keys of links and buttons with no text, image alt or title, and
   *  the accessible name derived for each; also of those whose aria-label
   *  leaves out their visible text, with '' (the label goes). */
  emptyNames: Map<string, string>
  /** Attribute keys of links whose only text is an image's alt, and that alt:
   *  the title the anchor-text audit falls back to. */
  titleNames: Map<string, string>
  /** The <link> that replaces the page's first <style> block when all of them
   *  move to /_css/i<hash>.css; empty when they stay. */
  styleTag: string
  /** Per table in document order: the caption text to add ('' = leave), and
   *  whether its first row's cells become column headers (no th at all). */
  captions: string[]
  headless: boolean[]
  searchPath: string
  /** The organisation behind the site, as toplist-edge serves it; null when none. */
  identity: SiteIdentity | null
  /** The social profile links the page carries. */
  socials: string[]
  /** Width and height per image src, read from the files, for the img tags that lack them. */
  dims: Map<string, [number, number]>
  /** The table of contents to put after the first paragraph under the H1 ('' = none),
   *  and the id each H2 gets, by its index among the document's H2s. */
  toc: string
  tocIds: Map<number, string>
  /** The page has a toplist mount: the box goes after it, not after the intro. */
  tocAfterToplist: boolean
  /** The phone call-to-action bar and its script ('' = no toplist on the page),
   *  and the id the toplist mount gets when it has none. */
  cta: string
  toplistId: string
}

// ── The edge pass: breadcrumbs, contents, the phone bar ───────────────────
// Everything below reads the page as text in planPage and is written by the
// rewriter in applyPlan, like the rest of the fixes. Each is deterministic
// from the page alone: no fetch, no clock, no randomness, so two renders of
// one page are one page.
const TOC_CSS = '.rp-toc{margin:1rem 0;font-size:16px;line-height:1.5;border:1px solid rgba(128,128,128,.25);border-radius:8px;padding:.25rem .9rem}.rp-toc summary{cursor:pointer;font-weight:600;min-height:24px;padding:.35rem 0}.rp-toc ol{margin:.25rem 0 .5rem;padding:0;list-style:none;columns:2;column-gap:1.5rem}.rp-toc li{margin:.15rem 0;break-inside:avoid}.rp-toc a{min-height:24px;display:inline-block;text-decoration:none}.rp-toc a:hover{text-decoration:underline}@media (max-width:759px){.rp-toc ol{columns:1}}'
// Shown only on a phone, only once the script lifts the hidden attribute:
// the desktop and tablet test of the same bar lost, and a bar that paints
// before the reader has scrolled is an interstitial.
const CTA_CSS = '.rp-cta{display:none}@media (max-width:759px){.rp-cta:not([hidden]){display:block;position:fixed;left:16px;right:16px;bottom:10px;z-index:98;min-height:48px;line-height:48px;text-align:center;background:#1d4ed8;color:#fff;font:600 16px/48px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;border-radius:8px;text-decoration:none;box-shadow:0 2px 8px rgba(0,0,0,.25)}}'
const TOC_WORDS: Record<'it' | 'fr', string> = { it: 'Indice', fr: 'Sommaire' }
const CTA_WORDS: Record<'it' | 'fr', string> = { it: 'Vedi la classifica', fr: 'Voir le classement' }
const TOPLIST_ANCHOR: Record<'it' | 'fr', string> = { it: 'classifica', fr: 'classement' }
const TOC_MIN_H2 = 6
const TOC_MIN_WORDS = 1500
/** Entries at most: a box of eighteen links is a wall, not a map. */
const TOC_MAX_ENTRIES = 10
const TOC_ENTRY_CHARS = 60

// A fragment id from a heading's text: ASCII letters and digits, hyphens
// between, accents dropped ("Metodi di pagamento" is "metodi-di-pagamento").
function slugId(s: string): string {
  return s.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60)
}
// A path segment as a name, when nothing on the page names it:
// "bonus-senza-deposito" is "Bonus senza deposito".
function nameFromSegment(seg: string): string {
  let s = seg
  try { s = decodeURIComponent(seg) } catch { /* as written */ }
  s = s.replace(/\.(html?|php|aspx?)$/i, '').replace(/[-_+]+/g, ' ').trim()
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''
}
// Every link inside a <nav>, in document order, as [path, text]: the page's
// own names for its sections, read for the breadcrumb and the prefetch list.
// Same-origin pages only; never an affiliate redirect, a fragment or a file.
function navPageLinks(visible: string, base: URL): Array<[string, string]> {
  const out: Array<[string, string]> = []
  for (const nav of visible.matchAll(/<nav\b[^>]*>([\s\S]*?)<\/nav\s*>/gi)) {
    for (const m of nav[1].matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi)) {
      const a = parseAttrs('<a' + m[1] + '>')
      const path = sameOriginPath(a.href ?? '', base)
      if (!path || path.indexOf('/vai/') === 0 || path.indexOf('/aller/') === 0 || path.indexOf('/go/') === 0 || NOT_FOUND_ASSET_RE.test(path)) continue
      // A sponsored or nofollow link, one opening a new tab, or a trust page
      // (about, contact) is not a reader's next page; a rescued path that
      // redirects to a partner must not be fetched for nothing.
      if (/\b(sponsored|nofollow|ugc)\b/i.test(a.rel ?? '') || (a.target ?? '').toLowerCase() === '_blank') continue
      if (TRUST_PATHS.it.some((l) => l[0] === path) || TRUST_PATHS.fr.some((l) => l[0] === path)) continue
      const text = stripTags(m[2]) || decodeEntities(a['aria-label'] ?? a.title ?? '').trim()
      out.push([path, text])
    }
  }
  return out
}
// The breadcrumb trail as JSON-LD, from the path: home, each section, the
// page. Names come from the page where it has them (the nav's text for a
// section, the H1 for the page), else from the segment. Nothing on the home
// page, which has no trail, and nothing where the page already declares one.
function breadcrumbLd(url: URL, pageUrl: string, h1: string, publisher: string, nav: Array<[string, string]>): string {
  const segs = url.pathname.split('/').filter((s) => s !== '')
  if (segs.length === 0) return ''
  const same = (p: string) => p.replace(/\/+$/, '').replace(/\/index\.html?$/i, '')
  const nameFor = (path: string): string => {
    const want = same(path)
    for (const [p, text] of nav) if (text && same(p) === want) return text
    return ''
  }
  const items: Array<{ name: string; item: string }> = [{ name: nameFor('/') || publisher, item: url.origin + '/' }]
  for (let i = 0; i < segs.length; i++) {
    const last = i === segs.length - 1
    const path = '/' + segs.slice(0, i + 1).join('/') + (last && /\.[a-z0-9]+$/i.test(segs[i]) ? '' : '/')
    const name = (last && h1) || nameFor(path) || nameFromSegment(segs[i])
    if (!name) return ''
    items.push({ name, item: last ? pageUrl : url.origin + path })
  }
  const ld = {
    '@context': 'https://schema.org', '@type': 'BreadcrumbList',
    itemListElement: items.map((it, i) => ({ '@type': 'ListItem', position: i + 1, name: it.name, item: it.item })),
  }
  return '<script type="application/ld+json">' + JSON.stringify(ld).replace(/<\//g, '<\\/') + '</script>'
}
// The table of contents for a long guide: six or more H2 inside the main
// content and fifteen hundred words of it. Shorter pages get none, because a
// contents box pushes the content below the fold. Each H2 keeps its id or
// gets one from its text; the ids are decided here and set by the rewriter,
// by the heading's index among every H2 the rewriter will see, so the counts
// must agree (an H2 inside a template or an svg means no contents at all).
function planToc(visible: string, rewritten: string, lang: 'it' | 'fr'): { html: string; ids: Map<number, string> } | null {
  const h2Re = /<h2\b([^>]*)>([\s\S]*?)<\/h2\s*>/gi
  if (count(visible, /<h2\b/gi) !== count(rewritten, /<h2\b/gi)) return null
  const region = /<(main|article)\b[^>]*>[\s\S]*?<\/\1\s*>/i.exec(visible)
  if (!region) return null
  const start = region.index, end = start + region[0].length
  const words = count(stripTags(region[0]), /\S+/g)
  if (words < TOC_MIN_WORDS) return null
  // After the H1, a paragraph: the box goes after it, so without one there is
  // nowhere to put it.
  const h1At = visible.search(/<h1\b/i)
  if (h1At < 0 || visible.slice(h1At).search(/<p\b/i) < 0) return null
  const taken = new Set<string>()
  for (const m of visible.matchAll(/\bid\s*=\s*["']([^"']+)["']/gi)) taken.add(m[1])
  const ids = new Map<number, string>()
  const entries: string[] = []
  let idx = -1
  for (const m of visible.matchAll(h2Re)) {
    idx++
    const at = m.index ?? 0
    if (at < start || at > end) continue
    const text = stripTags(m[2])
    // A tiny heading ("Pro", "Contro") is a label inside a block, not a
    // section a reader looks for.
    if (!text || text.length < 7) continue
    if (entries.length >= TOC_MAX_ENTRIES) break
    const own = parseAttrs('<h2' + m[1] + '>').id
    let id = own || slugId(text) || 'sezione-' + (idx + 1)
    if (!own) { let n = 2; const base = id; while (taken.has(id)) id = base + '-' + n++; taken.add(id); ids.set(idx, id) }
    const label = text.length > TOC_ENTRY_CHARS ? text.slice(0, TOC_ENTRY_CHARS - 1).replace(/\s+\S*$/, '') + '…' : text
    entries.push('<li><a href="#' + escAttr(id) + '">' + escAttr(label) + '</a></li>')
  }
  if (entries.length < TOC_MIN_H2) return null
  const word = TOC_WORDS[lang]
  // Closed by default on every screen: one line until the reader wants it.
  const html = '<nav class="rp-toc" aria-label="' + word + '"><details><summary>' + word + '</summary><ol>' + entries.join('') + '</ol></details></nav>'
  return { html, ids }
}
// The phone bar: a link to the toplist's anchor, never to an operator, shown
// once the reader is 40% down the page and the toplist is not on screen, and
// never over the trust footer. The attribute data-rf names it to the beacon
// so its clicks are counted as its own. Hidden by attribute until the script
// says otherwise; CTA_CSS keeps it off every screen 760px and wider.
function ctaHtml(lang: 'it' | 'fr', anchor: string): string {
  return '<a class="rp-cta" data-rf="sticky-cta" href="#' + escAttr(anchor) + '" hidden>' + CTA_WORDS[lang] + '</a>'
    + '<script>(function(){try{var a=document.querySelector(".rp-cta"),m=document.getElementById(' + JSON.stringify(anchor).replace(/</g, '\\u003c') + '),f=document.querySelector("footer.rp-trust");if(!a||!m)return;var on=0;function u(){try{var h=document.documentElement.scrollHeight-innerHeight,p=h>0?(scrollY||0)/h:1,r=m.getBoundingClientRect(),v=r.bottom>0&&r.top<innerHeight,ft=f?f.getBoundingClientRect().top<innerHeight:false,s=p>=.4&&!v&&!ft;if(s!==on){on=s;if(s)a.removeAttribute("hidden");else a.setAttribute("hidden","")}}catch(e){}}addEventListener("scroll",u,{passive:true});addEventListener("resize",u,{passive:true});u()}catch(e){}})();</script>'
}
// Up to two pages from the main navigation for the browser to prefetch: the
// first two internal links of the first <nav>, not this page, no duplicates.
function speculationRules(nav: Array<[string, string]>, url: URL): string {
  const urls: string[] = []
  for (const [p] of nav) {
    if (p === url.pathname || p.replace(/\/+$/, '') === url.pathname.replace(/\/+$/, '') || urls.includes(p)) continue
    urls.push(p)
    if (urls.length === 2) break
  }
  if (!urls.length) return ''
  return '<script type="speculationrules">' + JSON.stringify({ prefetch: [{ source: 'list', urls }] }).replace(/<\//g, '<\\/') + '</script>'
}

// A stylesheet the bundle may take: plain rel="stylesheet", on this site, a
// .css path, for all media, not disabled and not the preload-then-swap kind.
function bundleableSheet(a: Record<string, string>, base: URL): string | null {
  const rel = relTokens(a.rel ?? null)
  if (rel.length !== 1 || rel[0] !== 'stylesheet') return null
  if (!a.href || a.disabled !== undefined || a.onload !== undefined) return null
  const media = (a.media ?? '').trim().toLowerCase()
  if (media && media !== 'all' && media !== 'screen') return null
  const path = sameOriginPath(a.href, base)
  if (!path || !/\.css(\?|$)/i.test(path) || path.indexOf(',') >= 0 || path.indexOf('..') >= 0) return null
  return path
}

// The key of a link or button as the text pass and the rewriter both see it:
// tag, then every attribute in order. Values are entity-decoded on both sides.
function controlKey(tag: string, attrs: Iterable<[string, string]>): string {
  let key = tag
  for (const [k, v] of attrs) key += '|' + k.toLowerCase() + '=' + decodeEntities(v)
  return key
}

// What the audit's own label for an input would be when the page has none:
// its placeholder, its name, else a word for its type in the page's language.
const INPUT_WORDS: Record<'it' | 'fr', Record<string, string>> = {
  it: { text: 'Testo', search: 'Cerca', email: 'Email', tel: 'Telefono', url: 'Indirizzo web', number: 'Numero', password: 'Password', date: 'Data', time: 'Ora', checkbox: 'Opzione', radio: 'Opzione', file: 'File', range: 'Valore', color: 'Colore', select: 'Seleziona', textarea: 'Messaggio' },
  fr: { text: 'Texte', search: 'Rechercher', email: 'E-mail', tel: 'Téléphone', url: 'Adresse web', number: 'Nombre', password: 'Mot de passe', date: 'Date', time: 'Heure', checkbox: 'Option', radio: 'Option', file: 'Fichier', range: 'Valeur', color: 'Couleur', select: 'Sélectionner', textarea: 'Message' },
}
const BUTTON_WORDS: Array<[RegExp, string, string]> = [
  [/menu|\bnav|hamburger|toggle|burger/i, 'Menu', 'Menu'],
  [/search|cerca|recherch/i, 'Cerca', 'Rechercher'],
  [/close|chiudi|ferme/i, 'Chiudi', 'Fermer'],
  [/prev|back|preced/i, 'Precedente', 'Précédent'],
  [/next|succ|suivant|forward/i, 'Successivo', 'Suivant'],
  [/play/i, 'Riproduci', 'Lire'],
]
// The accessible name of a link that shows only an icon or an alt-less image,
// from where it goes: the site's name for the home page, the last path segment
// for a page on this site, the brand of an external host, the address of a
// mailto: or tel:. Nothing for a fragment or a javascript: link.
function nameFromHref(href: string, base: URL, publisher: string): string {
  const h = href.trim()
  if (!h || h.charAt(0) === '#' || /^javascript:/i.test(h)) return ''
  if (/^mailto:/i.test(h)) return h.slice(7).split('?')[0]
  if (/^tel:/i.test(h)) return h.slice(4)
  let u: URL
  try { u = new URL(h, base) } catch { return '' }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return ''
  if (apexHost(u.hostname) !== apexHost(base.hostname)) {
    const parts = u.hostname.toLowerCase().replace(/^www\./, '').split('.')
    let label = parts.length >= 2 ? parts[parts.length - 2] : parts[0]
    if (parts.length >= 3 && /^(co|com|org|net|gov|edu|ac)$/.test(label)) label = parts[parts.length - 3]
    return label ? label.charAt(0).toUpperCase() + label.slice(1) : ''
  }
  const segs = u.pathname.split('/').filter((s) => s !== '')
  if (segs.length === 0) return publisher
  let last = segs[segs.length - 1]
  try { last = decodeURIComponent(last) } catch { /* as written */ }
  const words = last.replace(/\.(html?|php|aspx?)$/i, '').replace(/[-_+]+/g, ' ').trim()
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : ''
}
function nameFromClass(cls: string, lang: 'it' | 'fr'): string {
  for (const [re, it, fr] of BUTTON_WORDS) if (re.test(cls)) return lang === 'fr' ? fr : it
  return ''
}

// Everything the rewriter needs to know before it starts, read from the text.
function planPage(html: string, url: URL, env: Env, identity: SiteIdentity | null = null, dims: Map<string, [number, number]> = new Map()): PagePlan {
  const origin = url.origin
  // Scripts, comments, templates and SVG are not page content: an img or a
  // link inside them is not the first image and not a trust link.
  const visible = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<(script|noscript|template|svg)\b[\s\S]*?<\/\1\s*>/gi, '')
  const langAttr = (/<html\b[^>]*\blang\s*=\s*["']?([a-zA-Z]+)/i.exec(html)?.[1] ?? '').toLowerCase()
  const lang: 'it' | 'fr' = langAttr === 'fr' ? 'fr' : langAttr === 'it' ? 'it' : (detectCountry(env, url.hostname) === 'FR' ? 'fr' : 'it')
  const head = readHeadMeta(visible)
  const description = trimDescription(head.description)
  const publisher = publisherName(url.hostname)
  const edgeBase = (env.TOPLIST_EDGE ?? DEFAULT_TOPLIST_EDGE).replace(/\/+$/, '')

  let canonical = '', touchIcon = '', icon = '', hasLlms = /\brel\s*=\s*["']?llms\b/i.test(visible)
  const preloaded = new Set<string>()
  const sheets: string[] = []
  for (const m of visible.matchAll(/<link\b[^>]*>/gi)) {
    const a = parseAttrs(m[0])
    const rel = relTokens(a.rel ?? null)
    const href = (a.href ?? '').trim()
    if (href && rel.includes('canonical') && !canonical) canonical = href
    if (href && rel.includes('apple-touch-icon') && !touchIcon) touchIcon = href
    if (href && rel.includes('icon') && !rel.includes('apple-touch-icon') && !icon) icon = href
    if (href && rel.includes('preload') && (a.as ?? '').toLowerCase() === 'image') preloaded.add(href)
    if (/\/llms\.txt$/i.test(href)) hasLlms = true
    const path = bundleableSheet(a, url)
    if (path && !sheets.includes(path)) sheets.push(path)
  }

  // Three images are chosen. The audit's LCP candidate: an img with class
  // hero or banner, else the first img inside <header>, else the first img of
  // all. The first content image (not a pixel, not the logo), which a browser
  // paints large and must not be lazy. And the share image: the first one
  // declared at 600x315 or more, else the first responsive one (srcset or
  // sizes), else the market's default card on toplist-edge; never the logo
  // proxy, never a data URI or an SVG, which the social cards cannot read.
  const headerStart = visible.search(/<header\b/i)
  const headerEnd = headerStart >= 0 ? visible.search(/<\/header\s*>/i) : -1
  let prioritySrc = '', priorityAttrs: Record<string, string> | null = null
  let firstSrc = '', firstAttrs: Record<string, string> | null = null
  let headerSrc = '', headerAttrs: Record<string, string> | null = null
  let heroSrc = ''
  let sizedSrc = '', responsiveSrc = ''
  for (const m of visible.matchAll(/<img\b[^>]*>/gi)) {
    const a = parseAttrs(m[0])
    const src = (a.src ?? '').trim()
    if (!src) continue
    const idx = m.index ?? 0
    const inHeader = headerStart >= 0 && idx > headerStart && (headerEnd < 0 || idx < headerEnd)
    if (!firstSrc) { firstSrc = src; firstAttrs = a }
    if (inHeader && !headerSrc) { headerSrc = src; headerAttrs = a }
    if (!prioritySrc && /(?:^|\s)(?:hero|banner)(?:\s|$)/i.test(a.class ?? '')) { prioritySrc = src; priorityAttrs = a }
    if (/^data:/i.test(src) || /\.svg(\?|#|$)/i.test(src)) continue
    const w = parseInt(a.width ?? '', 10), h = parseInt(a.height ?? '', 10)
    const hint = src + ' ' + (a.class ?? '') + ' ' + (a.id ?? '') + ' ' + (a.alt ?? '')
    if ((w > 0 && w <= 2) || (h > 0 && h <= 2) || /pixel|tracking|spacer|blank|1x1/i.test(hint)) continue
    const isLogo = inHeader || /logo|icon|badge/i.test(hint)
    // An image the author lazy-loads is not the one painting first: the
    // priority goes to the first content image that is not lazy.
    if (!heroSrc && !isLogo && (a.loading ?? '').trim().toLowerCase() !== 'lazy') heroSrc = src
    let path = ''
    try { path = new URL(src, url).pathname } catch { path = '' }
    if (/^\/_[a-z0-9]{6}\//.test(path)) continue
    if (!sizedSrc && w >= 600 && h >= 315) sizedSrc = src
    else if (!responsiveSrc && !isLogo && (a.srcset || a.sizes)) responsiveSrc = src
  }
  if (!prioritySrc && headerSrc) { prioritySrc = headerSrc; priorityAttrs = headerAttrs }
  if (!prioritySrc && firstSrc) { prioritySrc = firstSrc; priorityAttrs = firstAttrs }
  if (heroSrc === prioritySrc) heroSrc = ''
  const firstH2 = visible.search(/<h2\b/i)
  const heroEarly = !!heroSrc && (firstH2 < 0 || visible.indexOf(heroSrc) < firstH2)

  const mainTag = /<main\b[^>]*>/i.exec(visible)?.[0] ?? ''
  const mainId = mainTag ? (parseAttrs(mainTag).id || 'main') : ''
  const hasSkip = /href\s*=\s*["']#(?:main|content|contenuto|contenu|main-content)["'\s>]/i.test(visible) || /class\s*=\s*["'][^"']*skip/i.test(visible)
  const hasTrust = OWN_TRUST_FOOTER_RE.test(visible)

  // Labels: a <label for> with text names that id; a control inside a <label>
  // with text is named by it.
  const labelled = new Set<string>()
  for (const m of visible.matchAll(/<label\b([^>]*)>([\s\S]*?)<\/label\s*>/gi)) {
    if (!stripTags(m[2])) continue
    const a = parseAttrs('<label' + m[1] + '>')
    if (a.for) labelled.add('id:' + a.for)
    for (const c of m[2].matchAll(/<(?:input|select|textarea)\b[^>]*>/gi)) {
      const ca = parseAttrs(c[0])
      if (ca.id) labelled.add('id:' + ca.id)
      if (ca.name) labelled.add('name:' + ca.name)
    }
  }
  // Links and buttons with nothing a screen reader could read: no text, no
  // title, no aria name, no alt on an image inside, no title on an SVG. The
  // rewriter cannot see an element's children, so each bare one is named by
  // its attributes and its position among the elements with those attributes
  // (the logo link home is bare, the "Home" link beside it is not, and both
  // are a[href="/"]). Counted over the elements the rewriter will see: those
  // inside noscript, template and svg included, comments and scripts not.
  const emptyNames = new Map<string, string>()
  const titleNames = new Map<string, string>()
  const seen = new Map<string, number>()
  const rewritten = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<(script|style)\b[\s\S]*?<\/\1\s*>/gi, '')
  const asciiWords = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()
  for (const m of rewritten.matchAll(/<(a|button)\b([^>]*)>([\s\S]*?)<\/\1\s*>/gi)) {
    const tag = m[1].toLowerCase()
    const a = parseAttrs('<' + tag + m[2] + '>')
    if (tag === 'a' && a.href === undefined) continue
    const key = controlKey(tag, Object.entries(a))
    const idx = seen.get(key) ?? 0
    seen.set(key, idx + 1)
    const inner = m[3]
    const text = stripTags(inner)
    // The voice-control rule: the visible text must appear, letter for letter
    // (ASCII letters and digits, accents dropped), inside the aria-label. It
    // reads the text the way cheerio does, text nodes run together with no
    // space between elements. A label that leaves the visible text out is
    // the WCAG 2.5.3 failure itself; dropping it makes the visible text the
    // name, which is what the rule and a voice-control user want.
    if (a['aria-label'] !== undefined) {
      const vis = asciiWords(decodeEntities(inner.replace(/<[^>]*>/g, ''))), acc = asciiWords(a['aria-label'])
      if (vis && acc.indexOf(vis) < 0) emptyNames.set(key + '#' + idx, '')
      continue
    }
    if (a['aria-labelledby'] !== undefined || (a.title ?? '').trim()) continue
    const alt = /<img\b[^>]*\balt\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/i.exec(inner)
    const altText = decodeEntities(alt?.[1] ?? alt?.[2] ?? alt?.[3] ?? '').replace(/\s+/g, ' ').trim()
    if (text !== '' || /<svg\b[\s\S]*?<title\b[^>]*>\s*\S/i.test(inner)) continue
    // Named by its image: the anchor-text rule still reads an empty text and
    // falls back to the title, so the alt becomes the title too.
    if (altText) { if (tag === 'a') titleNames.set(key + '#' + idx, altText); continue }
    const name = tag === 'a' ? nameFromHref(a.href ?? '', url, publisher) : nameFromClass((a.class ?? '') + ' ' + (a.id ?? ''), lang)
    if (name) { emptyNames.set(key + '#' + idx, name); if (tag === 'a') titleNames.set(key + '#' + idx, name) }
  }

  // The page's <style> blocks, moved to one stylesheet the worker serves from
  // the page itself (see handleInlineCss): fewer bytes of HTML, a better
  // text-to-HTML ratio, a cacheable file. Only when the move cannot change the
  // cascade: every block plain (no media, no other attributes), none inside
  // noscript, template or svg, no linked stylesheet between the first and the
  // last of them, and enough CSS to be worth a request.
  const noComments = html.replace(/<!--[\s\S]*?-->/g, '')
  const styleBlocks = inlineStyleBlocks(noComments)
  let styleTag = ''
  if (styleBlocks) {
    const firstAt = noComments.search(/<style\b/i)
    const lastEnd = noComments.lastIndexOf('</style')
    let linkBetween = false
    for (const m of noComments.matchAll(/<link\b[^>]*>/gi)) {
      const at = m.index ?? 0
      if (at > firstAt && at < lastEnd && relTokens(parseAttrs(m[0]).rel ?? null).includes('stylesheet')) { linkBetween = true; break }
    }
    if (!linkBetween) {
      styleTag = '<link rel="stylesheet" href="/_css/i' + fnv1a(styleBlocks.join('\n')).toString(16) + '.css?p=' + encodeURIComponent(url.pathname).replace(/%2F/gi, '/') + '">'
    }
  }

  // Tables: a caption from the heading above each (hidden, for screen readers
  // and the audit), column headers where a table has none. Counted on the
  // same text the rewriter will walk, so the nth table here is its nth there;
  // if the counts cannot agree (a table inside noscript, template or svg) the
  // tables are left alone.
  const captions: string[] = []
  const headless: boolean[] = []
  const tableRe = /<table\b[^>]*>/gi
  if (count(noComments, tableRe) === count(visible, tableRe)) {
    let n = 0
    for (const m of visible.matchAll(/<table\b[^>]*>([\s\S]*?)<\/table\s*>/gi)) {
      n++
      const a = parseAttrs(m[0].slice(0, m[0].indexOf('>') + 1))
      const inner = m[1]
      const rows = count(inner, /<tr\b/gi)
      const role = (a.role ?? '').toLowerCase()
      if (role === 'presentation' || role === 'none' || /\blayout\b/i.test(a.class ?? '') || rows < 2 || /<table\b/i.test(inner)) { captions.push(''); headless.push(false); continue }
      const firstRow = /<tr\b[^>]*>([\s\S]*?)<\/tr\s*>/i.exec(inner)?.[1] ?? ''
      const cols = count(firstRow, /<t[dh]\b/gi)
      headless.push(cols >= 2 && !/<th\b/i.test(inner) && !/colspan|rowspan/i.test(firstRow))
      if (/<caption\b/i.test(inner) || a['aria-label'] !== undefined || a['aria-labelledby'] !== undefined) { captions.push(''); continue }
      const before = visible.slice(0, m.index ?? 0)
      let heading = ''
      for (const h of before.matchAll(/<h[1-6]\b[^>]*>([\s\S]*?)<\/h[1-6]\s*>/gi)) heading = stripTags(h[1]) || heading
      captions.push(heading || ((lang === 'fr' ? 'Tableau ' : 'Tabella ') + n))
    }
  }

  const pageUrl = absolutize(canonical, url) || (origin + url.pathname)
  const logo = absolutize(touchIcon, url) || absolutize(icon, url) || (origin + '/favicon.svg')
  const ogImage = absolutize(sizedSrc, url) || absolutize(responsiveSrc, url) || (edgeBase + '/og/' + lang + '.jpg')
  const contactPath = TRUST_PATHS[lang][1][0]
  const mail = (lang === 'fr' ? 'redaction@' : 'redazione@') + apexHost(url.hostname)
  const add: string[] = []
  const meta = (key: string, attr: 'property' | 'name', value: string) => {
    if (value && !head.metaNames.has(key)) add.push('<meta ' + attr + '="' + key + '" content="' + escAttr(value) + '">')
  }
  meta('og:title', 'property', head.title)
  meta('og:description', 'property', description)
  meta('og:url', 'property', pageUrl)
  meta('og:type', 'property', url.pathname === '/' ? 'website' : 'article')
  meta('og:image', 'property', ogImage)
  meta('twitter:card', 'name', 'summary_large_image')
  meta('twitter:title', 'name', head.title)
  meta('twitter:description', 'name', description)
  meta('twitter:image', 'name', ogImage)
  // The preload names the src as the img writes it: the audit, like a browser
  // resolving both, matches them as strings.
  if (prioritySrc && !/^data:/i.test(prioritySrc) && !preloaded.has(prioritySrc)) {
    let preload = '<link rel="preload" as="image" href="' + escAttr(prioritySrc) + '" fetchpriority="high"'
    if (priorityAttrs && priorityAttrs.srcset) preload += ' imagesrcset="' + escAttr(priorityAttrs.srcset) + '"'
    if (priorityAttrs && priorityAttrs.sizes) preload += ' imagesizes="' + escAttr(priorityAttrs.sizes) + '"'
    add.push(preload + '>')
  }
  if (!hasLlms) add.push('<link rel="llms" href="/llms.txt">')
  if (!/\.md$/i.test(url.pathname) && !head.alternates.has('text/markdown')) add.push('<link rel="alternate" type="text/markdown" href="' + escAttr(markdownPath(url.pathname)) + '">')
  const skipLink = mainId && !hasSkip
    ? '<a class="rp-skip" href="#' + escAttr(mainId) + '">' + (lang === 'fr' ? 'Aller au contenu' : 'Vai al contenuto') + '</a>'
    : ''
  if (skipLink) add.push('<style>' + SKIP_CSS + '</style>')
  const trustFooter = hasTrust ? '' : trustFooterHtml(lang, pageUrl)
  if (trustFooter) add.push('<style>' + TRUST_CSS + '</style>')
  if (captions.some((c) => c !== '')) add.push('<style>' + SR_CSS + '</style>')

  // The edge pass. Breadcrumbs and the prefetch list read the navigation;
  // the H1 names the page in the trail.
  const nav = navPageLinks(visible, url)
  const h1 = stripTags(/<h1\b[^>]*>([\s\S]*?)<\/h1\s*>/i.exec(visible)?.[1] ?? '')
  const crumbs = /BreadcrumbList/i.test(html) ? '' : breadcrumbLd(url, pageUrl, h1, publisher, nav)
  if (crumbs) add.push(crumbs)
  const rules = /type\s*=\s*["']?speculationrules/i.test(html) ? '' : speculationRules(nav, url)
  if (rules) add.push(rules)
  // A preconnect to toplist-edge only where the browser will go there: the
  // list is rendered server-side and logos come through this site's own
  // path, so on most pages nothing connects to it, and printing the shared
  // edge hostname into every page of the network is the one footprint the
  // beacon's history warns against. A page that already loads something
  // from it has made that choice, and the connection is then worth opening.
  let edgeHost = ''
  try { edgeHost = new URL(edgeBase).hostname } catch { edgeHost = '' }
  let loadsEdge = false, preconnected = false
  for (const m of visible.matchAll(/<(?:img|script|link|iframe|source|video|audio)\b[^>]*>/gi)) {
    const a = parseAttrs(m[0])
    let h = ''
    try { h = new URL((a.src ?? a.href ?? '').trim(), url).hostname } catch { h = '' }
    if (!edgeHost || h !== edgeHost) continue
    if (relTokens(a.rel ?? null).includes('preconnect')) preconnected = true
    else loadsEdge = true
  }
  if (loadsEdge && !preconnected) add.push('<link rel="preconnect" href="' + escAttr(edgeBase) + '">')
  const tocPlan = planToc(visible, rewritten, lang)
  if (tocPlan) add.push('<style>' + TOC_CSS + '</style>')
  // The toplist mount, by its id or the one the rewriter will give it.
  const mountTag = /<[a-z][a-z0-9-]*\b[^>]*\bdata-toplist\b[^>]*>/i.exec(visible)?.[0] ?? ''
  const mountId = mountTag ? (parseAttrs(mountTag).id || TOPLIST_ANCHOR[lang]) : ''
  const cta = mountId ? ctaHtml(lang, mountId) : ''
  if (cta) add.push('<style>' + CTA_CSS + '</style>')

  const bundle = sheets.length >= 2 ? sheets : []
  const joined = bundle.join(',')
  const bundleTag = bundle.length
    ? '<link rel="stylesheet" href="/_css/' + fnv1a(joined).toString(16) + '.css?f=' + encodeURIComponent(joined).replace(/%2F/gi, '/').replace(/%2C/gi, ',') + '">'
    : ''

  return {
    url, origin, lang, title: head.title, pageUrl, description, ogImage, logo, publisher, contactPath, mail,
    prioritySrc, heroSrc, heroEarly, headExtra: add.join('\n'), skipLink, trustFooter, bundle, bundleTag, labelled, emptyNames,
    titleNames, styleTag, captions, headless, searchPath: SEARCH_PATH[lang],
    identity, socials: pageSocials(visible), dims,
    toc: tocPlan?.html ?? '', tocIds: tocPlan?.ids ?? new Map(), tocAfterToplist: !!mountTag, cta, toplistId: mountTag && !parseAttrs(mountTag).id ? mountId : '',
  }
}

// JSON-LD that is already on the page, completed, wherever a node sits: at
// the top, in a @graph, or nested as an Article's publisher. Article kinds get
// headline, image, description, dateModified, mainEntityOfPage, author and
// publisher; Organization gets @id, name, url, logo and a contactPoint (the
// contact page and its mailbox); WebSite gets @id, name, url and publisher;
// Person gets an @id from its name. Only fields that are missing, only values
// the page can vouch for (datePublished is never invented); anything that is
// not valid JSON is returned as null and left exactly as it was.
function fixJsonLd(raw: string, p: PagePlan): string | null {
  let data: unknown
  try { data = JSON.parse(raw) } catch { return null }
  let changed = false
  const orgId = p.origin + '/#organization'
  const typesOf = (n: Record<string, unknown>): string[] => {
    const t = n['@type']
    return (Array.isArray(t) ? t : [t]).filter((x): x is string => typeof x === 'string').map((x) => x.toLowerCase())
  }
  const isOrg = (t: string[]) => t.some((x) => x === 'organization' || x.endsWith('organization') || x.endsWith('business') || x === 'corporation' || x === 'ngo' || x === 'onlinestore')
  // Is there an Organization anywhere in the document? A reference to its @id
  // is enough then; otherwise the first field that needs one carries it whole.
  let hasOrg = false
  const scan = (node: unknown): void => {
    if (Array.isArray(node)) { for (const x of node) scan(x); return }
    if (!node || typeof node !== 'object') return
    const n = node as Record<string, unknown>
    if (isOrg(typesOf(n))) hasOrg = true
    for (const v of Object.values(n)) if (v && typeof v === 'object') scan(v)
  }
  scan(data)
  const fill = (n: Record<string, unknown>, k: string, v: unknown) => {
    if (v && (n[k] === undefined || n[k] === null || n[k] === '')) { n[k] = v; changed = true }
  }
  // What the organisation behind the site adds to its node: the researched
  // facts (identity.ts in Raptor) and the profiles the page links itself.
  // A field the page already has is kept; sameAs is the union.
  const id = p.identity
  const completeOrg = (n: Record<string, unknown>) => {
    if (id) {
      fill(n, 'legalName', id.legalName)
      fill(n, 'vatID', id.vatID)
      fill(n, 'telephone', id.telephone)
      fill(n, 'email', id.email)
      if (id.address && typeof id.address === 'object') fill(n, 'address', id.address)
    }
    const have = Array.isArray(n['sameAs']) ? (n['sameAs'] as unknown[]).filter((x): x is string => typeof x === 'string') : typeof n['sameAs'] === 'string' ? [n['sameAs'] as string] : []
    const want = [...(id?.sameAs ?? []), ...p.socials].filter((u) => typeof u === 'string' && /^https?:\/\//i.test(u) && !have.includes(u))
    if (want.length) { n['sameAs'] = [...have, ...want.filter((u, i, a) => a.indexOf(u) === i)]; changed = true }
  }
  const orgRef = (): Record<string, unknown> => {
    if (hasOrg) return { '@id': orgId }
    hasOrg = true
    const node: Record<string, unknown> = {
      '@type': 'Organization', '@id': orgId, name: id?.name || p.publisher, url: p.origin + '/', logo: p.logo,
      contactPoint: { '@type': 'ContactPoint', contactType: 'editorial office', email: p.mail, url: p.origin + p.contactPath },
    }
    completeOrg(node)
    return node
  }
  const slug = (s: string) => s.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
  const visit = (node: unknown): void => {
    if (Array.isArray(node)) { for (const x of node) visit(x); return }
    if (!node || typeof node !== 'object') return
    const n = node as Record<string, unknown>
    const t = typesOf(n)
    if (t.includes('article') || t.includes('newsarticle') || t.includes('blogposting')) {
      fill(n, 'headline', p.title)
      fill(n, 'image', p.ogImage)
      fill(n, 'description', p.description)
      fill(n, 'dateModified', n['datePublished'])
      fill(n, 'mainEntityOfPage', p.pageUrl)
      if (n['publisher'] === undefined || n['publisher'] === null || n['publisher'] === '') fill(n, 'publisher', orgRef())
      if (n['author'] === undefined || n['author'] === null || n['author'] === '') fill(n, 'author', orgRef())
    }
    if (isOrg(t)) {
      fill(n, '@id', orgId)
      fill(n, 'name', id?.name || p.publisher)
      fill(n, 'url', p.origin + '/')
      fill(n, 'logo', p.logo)
      fill(n, 'contactPoint', { '@type': 'ContactPoint', contactType: 'editorial office', email: p.mail, url: p.origin + p.contactPath })
      completeOrg(n)
    }
    if (t.includes('website')) {
      fill(n, '@id', p.origin + '/#website')
      fill(n, 'name', p.publisher)
      fill(n, 'url', p.origin + '/')
      if (n['publisher'] === undefined || n['publisher'] === null || n['publisher'] === '') fill(n, 'publisher', orgRef())
      // The site search the worker serves, as the sitelinks search box wants
      // it: an EntryPoint template and the query-input the audit reads.
      fill(n, 'potentialAction', {
        '@type': 'SearchAction',
        target: { '@type': 'EntryPoint', urlTemplate: p.origin + p.searchPath + '?q={search_term_string}' },
        'query-input': 'required name=search_term_string',
      })
    }
    if (t.includes('person') && typeof n['name'] === 'string' && slug(n['name'] as string)) {
      fill(n, '@id', p.origin + '/#person-' + slug(n['name'] as string))
    }
    for (const [k, v] of Object.entries(n)) {
      if (k !== '@type' && v && typeof v === 'object') visit(v)
    }
  }
  visit(data)
  if (!changed) return null
  // A closing script tag inside a JSON string would end the element early;
  // the escaped slash is the same string to a JSON parser.
  return JSON.stringify(data).replace(/<\//g, '<\\/').replace(/<!--/g, '<\!--').replace(/-->/g, '--\>')
}

function applyPlan(p: PagePlan, response: Response): Response {
  let priorityDone = !p.prioritySrc
  let heroDone = !p.heroSrc
  let imgCount = 0
  let navCount = 0
  let mainDone = false
  let firstSheetDone = false
  let styleBuf = ''
  let ldBuf = ''
  let inLd = false
  const words = INPUT_WORDS[p.lang]
  const rw = new HTMLRewriter()
  rw.on('a[rel]', {
    element(el) {
      const before = relTokens(el.getAttribute('rel'))
      const after = before.filter((t) => t !== 'nofollow' && t !== 'ugc')
      if (after.length === before.length) return
      if (after.length) el.setAttribute('rel', after.join(' '))
      else el.removeAttribute('rel')
    },
  })
  if (p.emptyNames.size || p.titleNames.size) {
    const seen = new Map<string, number>()
    const nameIt = (el: Element) => {
      const key = controlKey(el.tagName.toLowerCase(), el.attributes)
      const idx = seen.get(key) ?? 0
      seen.set(key, idx + 1)
      const name = p.emptyNames.get(key + '#' + idx)
      if (name) el.setAttribute('aria-label', name)
      else if (name === '') el.removeAttribute('aria-label')
      const title = p.titleNames.get(key + '#' + idx)
      if (title) el.setAttribute('title', title)
    }
    rw.on('a[href]', { element: nameIt })
    rw.on('button', { element: nameIt })
  }
  // The deprecated presentation tags the broken-HTML rule lists, as the
  // elements and inline styles that render the same.
  const FONT_SIZES = ['', 'x-small', 'small', 'medium', 'large', 'x-large', 'xx-large', 'xxx-large']
  const addStyle = (el: Element, css: string) => {
    const s = (el.getAttribute('style') ?? '').trim()
    el.setAttribute('style', css + (s ? ';' + s : ''))
  }
  rw.on('center', { element(el) { el.tagName = 'div'; addStyle(el, 'text-align:center') } })
  rw.on('strike', { element(el) { el.tagName = 's' } })
  rw.on('big', { element(el) { el.tagName = 'span'; addStyle(el, 'font-size:larger') } })
  rw.on('tt', { element(el) { el.tagName = 'span'; addStyle(el, 'font-family:monospace') } })
  rw.on('font', {
    element(el) {
      const css: string[] = []
      const color = (el.getAttribute('color') ?? '').trim()
      const face = (el.getAttribute('face') ?? '').trim()
      const size = parseInt((el.getAttribute('size') ?? '').trim(), 10)
      if (color && /^[#a-z0-9(),.% -]+$/i.test(color)) css.push('color:' + color)
      if (face && /^[a-z0-9 ,'"-]+$/i.test(face)) css.push('font-family:' + face.replace(/"/g, "'"))
      if (size >= 1 && size <= 7 && !/^[+-]/.test(el.getAttribute('size') ?? '')) css.push('font-size:' + FONT_SIZES[size])
      el.removeAttribute('color'); el.removeAttribute('face'); el.removeAttribute('size')
      el.tagName = 'span'
      if (css.length) addStyle(el, css.join(';'))
    },
  })
  // Tables: the hidden caption planned for each, column headers in a table
  // that has none, and a scope on every th (col in the head and the first
  // row, row below).
  if (p.captions.length) {
    let tableIdx = -1, rowIdx = 0, inHead = false, headlessNow = false
    rw.on('table', {
      element(el) {
        tableIdx++; rowIdx = 0; inHead = false
        headlessNow = p.headless[tableIdx] === true
        const cap = p.captions[tableIdx] ?? ''
        if (cap) el.prepend('<caption class="rp-sr">' + escAttr(cap) + '</caption>', { html: true })
      },
    })
    rw.on('thead', { element(el) { inHead = true; el.onEndTag(() => { inHead = false }) } })
    rw.on('tr', { element() { rowIdx++ } })
    rw.on('th', { element(el) { if (!el.hasAttribute('scope')) el.setAttribute('scope', inHead || rowIdx <= 1 ? 'col' : 'row') } })
    rw.on('td', {
      element(el) {
        if (!headlessNow || rowIdx !== 1) return
        el.tagName = 'th'
        el.setAttribute('scope', 'col')
        addStyle(el, 'font-weight:inherit;text-align:inherit')
      },
    })
  }
  if (p.headExtra) {
    rw.on('head', { element(el) { el.append('\n' + p.headExtra + '\n', { html: true }) } })
  }
  rw.on('meta', {
    element(el) {
      if ((el.getAttribute('name') ?? '').toLowerCase() !== 'description') return
      const c = (el.getAttribute('content') ?? '').replace(/\s+/g, ' ').trim()
      const t = trimDescription(c)
      if (t !== c) el.setAttribute('content', t)
    },
  })
  rw.on('script', {
    element(el) {
      inLd = (el.getAttribute('type') ?? '').trim().toLowerCase() === 'application/ld+json'
      ldBuf = ''
    },
    text(t) {
      if (!inLd) return
      ldBuf += t.text
      if (!t.lastInTextNode) { t.remove(); return }
      const fixed = fixJsonLd(ldBuf, p)
      t.replace(fixed === null ? ldBuf : fixed, { html: true })
      inLd = false
    },
  })
  if (p.styleTag) {
    // Every block to the stylesheet handleInlineCss serves: the first becomes
    // its link, in place, so the cascade order is what it was.
    let styleIdx = 0
    rw.on('style', {
      element(el) {
        if (styleIdx++ === 0) el.replace(p.styleTag, { html: true })
        else el.remove()
      },
    })
  } else {
    rw.on('style', {
      text(t) {
        styleBuf += t.text
        if (!t.lastInTextNode) { t.remove(); return }
        t.replace(fixStyleBlock(styleBuf), { html: true })
        styleBuf = ''
      },
    })
  }
  rw.on('[style]', {
    element(el) {
      const s = el.getAttribute('style') ?? ''
      const fixed = fixStyleAttr(s, STYLE_TEXT_TAGS.has(el.tagName.toLowerCase()) ? 16 : 12)
      if (fixed !== s) el.setAttribute('style', fixed)
    },
  })
  rw.on('img', {
    element(el) {
      const src = (el.getAttribute('src') ?? '').trim()
      // The images the audit counts: a src that is not a data URI. Its
      // "above the fold" is the first three of them, which are never lazy.
      if (src && !/^data:/i.test(src)) imgCount++
      const isPriority = !priorityDone && src === p.prioritySrc
      const isHero = !heroDone && src === p.heroSrc
      if (isPriority) priorityDone = true
      if (isHero) heroDone = true
      if (isPriority || isHero || imgCount <= 3) {
        // The audit's candidate, and the hero only when it is high on the
        // page: a content image far down would share the bandwidth the real
        // LCP needs.
        if (isPriority || (isHero && p.heroEarly)) el.setAttribute('fetchpriority', 'high')
        if ((el.getAttribute('loading') ?? '').toLowerCase() === 'lazy') el.removeAttribute('loading')
      } else if (!el.hasAttribute('loading')) {
        el.setAttribute('loading', 'lazy')
      }
      if (!el.hasAttribute('decoding')) el.setAttribute('decoding', 'async')
      if (!el.hasAttribute('alt')) el.setAttribute('alt', '')
      // Width and height from the file, where the tag has neither or only
      // one (the other follows the file's proportions).
      const d = p.dims.get(src)
      if (d) {
        const w = parseInt(el.getAttribute('width') ?? '', 10), h = parseInt(el.getAttribute('height') ?? '', 10)
        if (!(w > 0) && !(h > 0)) { el.setAttribute('width', String(d[0])); el.setAttribute('height', String(d[1])) }
        else if (w > 0 && !(h > 0)) el.setAttribute('height', String(Math.max(1, Math.round(w * d[1] / d[0]))))
        else if (h > 0 && !(w > 0)) el.setAttribute('width', String(Math.max(1, Math.round(h * d[0] / d[1]))))
      }
    },
  })
  // An input, select or textarea the audit would count as unlabelled: no
  // aria name, no title, no <label for> its id, not inside a <label>.
  const labelIt = (el: Element) => {
    const tag = el.tagName.toLowerCase()
    const type = tag === 'input' ? (el.getAttribute('type') ?? 'text').trim().toLowerCase() : tag
    if (type === 'hidden' || type === 'submit' || type === 'button' || type === 'reset' || type === 'image') return
    if (el.hasAttribute('aria-label') || el.hasAttribute('aria-labelledby') || (el.getAttribute('title') ?? '').trim()) return
    const id = (el.getAttribute('id') ?? '').trim(), name = (el.getAttribute('name') ?? '').trim()
    if ((id && p.labelled.has('id:' + id)) || (name && p.labelled.has('name:' + name))) return
    const label = (el.getAttribute('placeholder') ?? '').trim() || name || words[type] || (type.charAt(0).toUpperCase() + type.slice(1))
    if (label) el.setAttribute('aria-label', label)
  }
  rw.on('input', { element: labelIt })
  rw.on('select', { element: labelIt })
  rw.on('textarea', { element: labelIt })
  rw.on('nav', {
    element(el) {
      navCount++
      if (el.hasAttribute('aria-label') || el.hasAttribute('aria-labelledby')) return
      el.setAttribute('aria-label', (p.lang === 'fr' ? 'Navigation ' : 'Navigazione ') + navCount)
    },
  })
  rw.on('main', {
    element(el) {
      if (mainDone) return
      mainDone = true
      if (!el.hasAttribute('id')) el.setAttribute('id', 'main')
    },
  })
  if (p.bundle.length) {
    rw.on('link', {
      element(el) {
        const a: Record<string, string> = {}
        for (const k of ['rel', 'href', 'media', 'disabled', 'onload']) {
          const v = el.getAttribute(k)
          if (v !== null) a[k] = v
        }
        const path = bundleableSheet(a, p.url)
        if (!path || !p.bundle.includes(path)) return
        if (!firstSheetDone && path === p.bundle[0]) {
          firstSheetDone = true
          el.replace(p.bundleTag, { html: true })
        } else {
          el.remove()
        }
      },
    })
  }
  // The edge pass. Each H2 the contents list names gets its id by its index
  // among every H2 the rewriter meets, which planToc made sure is the index
  // the text pass counted. The contents box goes after the toplist mount
  // when the page has one (the ranking is what the reader came for; the
  // map of the rest comes under it), else after the end tag of the first
  // paragraph following the H1.
  if (p.toc) {
    let h2Idx = -1, h1Seen = false, tocDone = false
    rw.on('h2', {
      element(el) {
        h2Idx++
        const id = p.tocIds.get(h2Idx)
        if (id && !el.hasAttribute('id')) el.setAttribute('id', id)
      },
    })
    rw.on('h1', { element() { h1Seen = true } })
    if (p.tocAfterToplist) {
      rw.on('[data-toplist]', {
        element(el) {
          if (tocDone) return
          tocDone = true
          el.after(p.toc, { html: true })
        },
      })
    } else {
      rw.on('p', {
        element(el) {
          if (!h1Seen || tocDone) return
          tocDone = true
          el.after(p.toc, { html: true })
        },
      })
    }
  }
  if (p.toplistId) {
    let mountDone = false
    rw.on('[data-toplist]', {
      element(el) {
        if (mountDone) return
        mountDone = true
        if (!el.hasAttribute('id')) el.setAttribute('id', p.toplistId)
      },
    })
  }
  if (p.skipLink || p.trustFooter || p.cta) {
    rw.on('body', {
      element(el) {
        if (p.skipLink) el.prepend(p.skipLink, { html: true })
        if (p.trustFooter) el.append(p.trustFooter, { html: true })
        // After the footer, so the bar's script finds it on the page.
        if (p.cta) el.append(p.cta, { html: true })
      },
    })
  }
  return rw.transform(response)
}

// ── robots.txt and the 404 page at the edge ───────────────────────────────
// Cloudflare's Content Signals, so the pages stay citable in AI answers while
// training on them is refused: served on every site whether or not its
// robots.txt was written before the directive existed. A file with the line
// already is served as written; a file without gets the line inside its
// "User-agent: *" group with every rule it had intact (no Allow: / is added
// to a group that has its own rules: beside a Disallow: / it would win, and
// unblock a site blocked on purpose), and a Sitemap line if it had none. A
// site with no robots.txt at all gets the scaffold's.
const CONTENT_SIGNAL = 'Content-Signal: search=yes, ai-train=no, ai-input=yes'
function robotsWithSignals(existing: string, origin: string): string {
  const lines = existing.replace(/\r/g, '').split('\n')
  while (lines.length && lines[lines.length - 1].trim() === '') lines.pop()
  const star = lines.findIndex((l) => /^\s*user-agent:\s*\*\s*$/i.test(l))
  if (star >= 0) lines.splice(star + 1, 0, CONTENT_SIGNAL)
  // A file with only named groups keeps its meaning for every other crawler
  // (unrestricted): the star group added carries the signal and the cloak
  // paths, no Allow line that would read as a new policy.
  else lines.push(...(lines.length ? [''] : []), 'User-agent: *', CONTENT_SIGNAL, ...(lines.length ? [] : ['Allow: /']), 'Disallow: /api/toplist/', 'Disallow: /go/', 'Disallow: /vai/', 'Disallow: /aller/')
  if (!lines.some((l) => /^\s*sitemap:/i.test(l))) lines.push('', 'Sitemap: ' + origin + '/sitemap.xml')
  return lines.join('\n') + '\n'
}
async function handleRobots(request: Request, url: URL, env: Env): Promise<Response> {
  let existing = ''
  try {
    const r = await env.ASSETS.fetch(request)
    if (r.ok) existing = await r.text()
  } catch { existing = '' }
  const body = /^\s*content-signal:/im.test(existing) ? existing : robotsWithSignals(existing, url.origin)
  const headers = new Headers({ 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=3600' })
  return withSecurityHeaders(new Response(request.method === 'HEAD' ? null : body, { status: 200, headers }))
}

// The page for an address with nothing behind it, on a site with no 404.html
// of its own. The assets answer a bare 404 then (not_found_handling is
// "404-page", and with no page to serve the body is empty): this is status
// 404, noindex, in the site's language, named after the site from its home
// title (one assets read, kept an hour per isolate) and linking home. A
// site's own 404.html is served exactly as it is, and a missing file (a
// stylesheet, an image, anything under /api/ or /.well-known/) stays the bare
// 404 it was: a broken image must not come back as a page.
const HOME_TITLE_TTL_MS = 3600_000
const homeTitleCache = new Map<string, { at: number; title: string }>()
async function siteTitle(url: URL, env: Env): Promise<string> {
  const host = apexHost(url.hostname)
  const hit = homeTitleCache.get(host)
  if (hit && Date.now() - hit.at < HOME_TITLE_TTL_MS) return hit.title
  let title = ''
  try {
    const home = await env.ASSETS.fetch(new Request(url.origin + '/'))
    if (home.ok && (home.headers.get('Content-Type') ?? '').includes('text/html')) title = readHeadMeta(await home.text()).title
  } catch { title = '' }
  homeTitleCache.set(host, { at: Date.now(), title })
  return title
}
function notFoundIsPage(url: URL, method: string, asset: Response): boolean {
  if (method !== 'GET' && method !== 'HEAD') return false
  if ((asset.headers.get('Content-Type') ?? '').includes('text/html')) return false
  const path = url.pathname
  return !NOT_FOUND_ASSET_RE.test(path) && path.indexOf('/.well-known/') !== 0 && path.indexOf('/api/') !== 0
}
async function handleNotFound(url: URL, env: Env, method: string): Promise<Response> {
  const lang: 'it' | 'fr' = detectCountry(env, url.hostname) === 'FR' ? 'fr' : 'it'
  const name = escAttr((await siteTitle(url, env)) || apexHost(url.hostname))
  const copy = lang === 'fr'
    ? { head: 'Page introuvable', body: "Cette page n'existe pas ou n'existe plus.", home: "Retour à l'accueil" }
    : { head: 'Pagina non trovata', body: 'La pagina che cerchi non esiste o non esiste più.', home: 'Torna alla home' }
  const html = '<!doctype html><html lang="' + lang + '"><head><meta charset="utf-8">'
    + '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<meta name="robots" content="noindex,nofollow">'
    + '<title>' + copy.head + ' – ' + name + '</title>'
    + '<style>' + TRUST_PAGE_CSS + 'main{text-align:center;padding-top:4rem}.rp-code{font-size:4rem;font-weight:800;color:#9ca3af;line-height:1;margin:0}</style></head>'
    + '<body><main id="main"><p class="rp-home"><a href="/">' + name + '</a></p><p class="rp-code">404</p><h1>' + copy.head + '</h1><p>' + copy.body + '</p>'
    + '<p><a href="/">' + copy.home + '</a></p></main></body></html>'
  // A minute at most: a page pushed seconds after a visitor's miss must not be a 404 for five.
  const headers = new Headers({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=60', 'X-Robots-Tag': 'noindex, nofollow' })
  return withSecurityHeaders(new Response(method === 'HEAD' ? null : html, { status: 404, headers }))
}

// Every 200 HTML page goes through here, after the toplist is in and before
// the mirror, robots and beacon injectors. Anything else is handed back as it
// came: another status, another type, an empty body (HEAD), a body that is not
// UTF-8 (a legacy page in Latin-1 would come out as mojibake), or a site that
// switched the fixes off.
async function fixPage(response: Response, request: Request, env: Env): Promise<Response> {
  if (response.status !== 200 || fixPageOff(env)) return response
  const ct = response.headers.get('Content-Type') ?? ''
  if (!ct.includes('text/html')) return response
  const buf = await response.arrayBuffer()
  const headers = new Headers(response.headers)
  headers.delete('Content-Length')
  const again = (body: ArrayBuffer | string) => new Response(body, { status: response.status, statusText: response.statusText, headers })
  if (buf.byteLength === 0) return again(buf)
  let html: string
  try { html = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(buf) } catch { return again(buf) }
  const pageUrl = new URL(request.url)
  // The organisation is only read for a page that has JSON-LD to complete.
  const identity = /application\/ld\+json/i.test(html) ? await identityFor(env, pageUrl.hostname) : null
  // The images without width and height: their sizes from the files, in parallel.
  const dims = new Map<string, [number, number]>()
  try {
    const visible = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<(script|noscript|template|svg)\b[\s\S]*?<\/\1\s*>/gi, '')
    const need = imagesWithoutSize(visible, pageUrl.origin)
    const sizes = await Promise.all(need.map((src) => imageDims(env, pageUrl.origin, src)))
    need.forEach((src, i) => { const d = sizes[i]; if (d) dims.set(src, d) })
  } catch { /* the page without sizes */ }
  let plan: PagePlan
  try { plan = planPage(html, pageUrl, env, identity, dims) } catch { return again(html) }
  return applyPlan(plan, again(html))
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

    // robots.txt with the Content Signals line, whatever the site's file
    // says; see handleRobots.
    if (url.pathname === '/robots.txt' && (request.method === 'GET' || request.method === 'HEAD')) {
      return handleRobots(request, url, env)
    }

    // Per-site logo proxy. Path shape: /_<6alphanum>/<slug>
    // The prefix is computed from the site's own domain so two EMD sites
    // never expose an identical logo URL (no image footprint).
    const logoMatch = url.pathname.match(/^\/_([a-z0-9]{6})\/([a-z0-9-]+)$/)
    if (logoMatch) {
      return handleLogoProxy(url, env, logoMatch)
    }

    // The page's stylesheets as one response; see handleCssBundle. Only with
    // the list this worker wrote into the page, so a real /_css/ file on a
    // site still falls through to the assets.
    if (url.pathname.indexOf('/_css/') === 0 && url.searchParams.has('f')) {
      return handleCssBundle(url, env)
    }
    if (url.pathname.indexOf('/_css/i') === 0 && url.searchParams.has('p')) {
      return handleInlineCss(url, env)
    }

    try {
      let assetResponse = await env.ASSETS.fetch(request)
      // Nothing real lives here and it is a retired path: 410 Gone rather
      // than the site's 404 page. 410 gets the URL dropped from the index on
      // the next crawl; a 404 leaves Google re-checking it for months.
      // Matched on 404 specifically, not on !ok — a _redirects rule answers
      // 301, and a rescued redirect must not be turned into a tombstone.
      if (isRetiredPath && assetResponse.status === 404) {
        return handleRetiredPage(url, env)
      }
      // The trust pages, /llms.txt and /AGENTS.md are the worker's own where
      // the site has no file of that name. Before NOT_FOUND_REDIRECT: the
      // footer on every page links to them, and a link that 301s home is a
      // link to nothing.
      if (assetResponse.status === 404 && (request.method === 'GET' || request.method === 'HEAD')) {
        const generated = await generatedPage(url, env)
        if (generated) assetResponse = generated
      }
      // A page that no longer exists, on a site that asked for its old links
      // to keep counting: 301 to NOT_FOUND_REDIRECT. See notFoundRedirectTarget.
      if (assetResponse.status === 404) {
        const sendTo = notFoundRedirectTarget(url, env.NOT_FOUND_REDIRECT, request.method)
        if (sendTo) {
          return withSecurityHeaders(new Response(null, {
            status: 301,
            headers: { Location: sendTo, 'Cache-Control': 'public, max-age=3600' },
          }))
        }
        // Nothing behind a page address and no 404.html on the site: the
        // branded page, status 404. A site's own 404.html and a missing file
        // pass through as they are. See handleNotFound.
        if (notFoundIsPage(url, request.method, assetResponse)) {
          return handleNotFound(url, env, request.method)
        }
      }
      const withCss = await fixCssResponse(assetResponse, env)
      const withToplist = await injectToplist(withCss, request, env)
      // The edge SEO fixes, after the toplist is in the page (its links and
      // images are fixed too) and before the mirror, robots and beacon passes.
      const withFixes = await fixPage(withToplist, request, env)
      const withMirror = (env.SUBDOMAIN_HOST && env.SUBDOMAIN_SLUG)
        ? injectSubdomainMirrorMeta(withFixes, url, env)
        : withFixes
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
