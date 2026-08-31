/**
 * site-branding.test.js — Admin -> Settings -> Logo URL actually reaches a page.
 *
 * The setting round-tripped perfectly and rendered nowhere. It was written to
 * cybercore_site_settings, served by /api/site-config, and read straight back
 * into the admin form's own input -- and that was the complete list of things
 * in the product that referenced site_logo_url. An admin pasting a URL saw the
 * field save and the header keep its shield, with no error anywhere to explain
 * it. A second, independent blocker sat behind that one: helmet's CSP allowed
 * imgSrc 'self'/data:/blob: only, so even a rendered <img> pointing off-origin
 * was refused by the browser.
 *
 * These lock in both halves, plus the related bug that surfaced with them --
 * the branding fetch used the ADMIN settings endpoint, which 403s for students
 * and instructors, so branding only ever reached admins.
 *
 * Run: node --test front-end/test/site-branding.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const LAYOUT_SRC = fs.readFileSync(
  path.join(__dirname, '..', 'public', 'js', 'layout.js'), 'utf8'
);

// ── A DOM stub just big enough for the branding path ────────────────────────
// Deliberately hand-rolled rather than jsdom: the rest of this suite runs on
// node:test with no browser dependency, and the code under test touches five
// DOM methods.
class El {
  constructor(tag, className = '') {
    this.tagName = tag;
    this.className = className;
    this.children = [];
    this.style = {};
    this.attrs = {};
    this.parent = null;
    this.textContent = '';
  }
  get src() { return this.attrs.src; }
  set src(v) { this.attrs.src = v; }
  get href() { return this.attrs.href; }
  set href(v) { this.attrs.href = v; }
  getAttribute(name) { return name in this.attrs ? this.attrs[name] : null; }
  insertBefore(node, ref) {
    const i = ref ? this.children.indexOf(ref) : this.children.length;
    this.children.splice(i < 0 ? this.children.length : i, 0, node);
    node.parent = this;
    return node;
  }
  appendChild(node) { this.children.push(node); node.parent = this; return node; }
  remove() {
    if (!this.parent) return;
    const i = this.parent.children.indexOf(this);
    if (i >= 0) this.parent.children.splice(i, 1);
    this.parent = null;
  }
  get firstChild() { return this.children[0] || null; }
  querySelector(sel) {
    const want = sel.replace(/^\./, '');
    for (const child of this.children) {
      if (String(child.className).split(/\s+/).includes(want)) return child;
      const deep = child.querySelector(sel);
      if (deep) return deep;
    }
    return null;
  }
}

/** Build the sidebar brand anchor the way getSidebarHTML() renders it. */
function makeAnchor() {
  const anchor = new El('a', 'sidebar-logo');
  anchor.appendChild(new El('span', 'icon'));   // the default shield emoji
  anchor.appendChild(new El('span', ''));       // #sidebarSiteName
  return anchor;
}

/** Evaluate layout.js against the stub and hand back Layout plus the fixtures. */
function loadLayout({ store = {}, pathname = '/hub', fetchImpl = null } = {}) {
  const anchor = makeAnchor();
  const head = new El('head');
  const calls = [];

  const document = {
    head,
    title: '',
    addEventListener: () => {},
    getElementById: () => null,
    createElement: tag => new El(tag),
    documentElement: { getAttribute: () => null },
    querySelector(sel) {
      if (sel === '.sidebar-logo') return anchor;
      if (sel === "link[rel='icon']") return head.children.find(c => c.rel === 'icon') || null;
      return null;
    }
  };

  const ctx = {
    console: { log: () => {}, warn: () => {}, debug: () => {}, error: () => {} },
    URLSearchParams,
    setTimeout: () => {},
    requestAnimationFrame: () => {},
    window: { location: { pathname, search: '' }, addEventListener: () => {} },
    document,
    localStorage: {
      getItem: k => (k in store ? store[k] : null),
      setItem: (k, v) => { store[k] = String(v); },
      removeItem: k => { delete store[k]; }
    },
    sessionStorage: { getItem: () => null, setItem: () => {} },
    Auth: { getUser: () => ({ role: 'student', email: 'a@b.c' }) },
    API: {},
    fetch: (url, opts) => {
      calls.push({ url, opts });
      return fetchImpl ? fetchImpl(url, opts) : Promise.reject(new Error('no fetch stub'));
    }
  };
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(LAYOUT_SRC + ';globalThis.__Layout = Layout;', ctx);

  return { Layout: ctx.__Layout, anchor, head, store, calls, document };
}

const logoOf = anchor => anchor.querySelector('.sidebar-logo-img');
const iconOf = anchor => anchor.querySelector('.icon');

// ── The bug itself ──────────────────────────────────────────────────────────

test('THE BUG: a configured logo URL is rendered into the sidebar brand', () => {
  const { Layout, anchor } = loadLayout({
    store: { site_logo_url: 'https://example.edu/logo.png' }
  });

  Layout.applySiteBranding();

  const img = logoOf(anchor);
  assert.ok(img, 'an <img> must exist — this is the assertion that was missing');
  assert.strictEqual(img.getAttribute('src'), 'https://example.edu/logo.png');
  assert.strictEqual(iconOf(anchor).style.display, 'none', 'the shield gives way to it');
});

test('the logo goes FIRST, so it reads as a logo and not a trailing image', () => {
  const { Layout, anchor } = loadLayout({ store: { site_logo_url: '/img/seal.svg' } });
  Layout.applySiteBranding();
  assert.strictEqual(anchor.children[0], logoOf(anchor));
});

test('clearing the field brings the shield back', () => {
  const { Layout, anchor, store } = loadLayout({
    store: { site_logo_url: 'https://example.edu/logo.png' }
  });
  Layout.applySiteBranding();
  assert.ok(logoOf(anchor));

  // What saveSiteSettings() caches when the admin empties the input.
  store.site_logo_url = '';
  Layout.applySiteBranding();

  assert.strictEqual(logoOf(anchor), null, 'the <img> is removed, not just hidden');
  assert.strictEqual(iconOf(anchor).style.display, '', 'the emoji is visible again');
});

test('repainting does not stack duplicate <img> elements', () => {
  const { Layout, anchor } = loadLayout({ store: { site_logo_url: '/img/seal.svg' } });
  Layout.applySiteBranding();
  Layout.applySiteBranding();
  Layout.applySiteBranding();
  assert.strictEqual(anchor.children.filter(c => c.className === 'sidebar-logo-img').length, 1);
});

test('a dead or hotlink-blocked URL falls back to the shield, not a broken image', () => {
  // Most free clip-art hosts serve the file to curl and 403 a browser Referer,
  // so this is the failure an admin is most likely to actually hit.
  const { Layout, anchor } = loadLayout({
    store: { site_logo_url: 'https://hotlink-blocked.example/logo.png' }
  });
  Layout.applySiteBranding();

  const img = logoOf(anchor);
  assert.ok(typeof img.onerror === 'function', 'an onerror handler must be wired');
  img.onerror();

  assert.strictEqual(logoOf(anchor), null);
  assert.strictEqual(iconOf(anchor).style.display, '');
});

// ── URL validation ──────────────────────────────────────────────────────────

test('only http(s) and same-origin absolute paths are accepted', () => {
  const { Layout } = loadLayout();
  for (const good of ['https://a.example/l.png', 'http://a.example/l.png', '/img/l.png']) {
    assert.strictEqual(Layout.isSafeAssetUrl(good), true, good);
  }
  const bad = ['javascript:alert(1)', 'data:image/svg+xml,<svg onload=alert(1)>',
               '//evil.example/l.png', '', '   ', null, undefined, 42];
  for (const value of bad) {
    assert.strictEqual(Layout.isSafeAssetUrl(value), false, String(value));
  }
});

test('an unsafe URL never reaches the DOM', () => {
  const { Layout, anchor } = loadLayout({ store: { site_logo_url: 'javascript:alert(1)' } });
  Layout.applySiteBranding();
  assert.strictEqual(logoOf(anchor), null);
});

// ── The endpoint, which is why students never saw any branding ──────────────

test('branding is fetched from the PUBLIC endpoint, not the admin one', async () => {
  const config = {
    site_name: 'CyberHub AZ',
    site_logo_url: 'https://example.edu/logo.png',
    site_favicon_url: 'https://example.edu/fav.ico'
  };
  const { Layout, anchor, store, calls } = loadLayout({
    fetchImpl: () => Promise.resolve({ ok: true, json: () => Promise.resolve(config) })
  });

  await Layout.loadSiteBranding();

  assert.deepStrictEqual(calls.map(c => c.url), ['/api/site-config']);
  assert.ok(!calls.some(c => String(c.url).includes('/admin/')),
    '/api/admin/settings 403s for every student and instructor');
  assert.strictEqual(store.site_logo_url, 'https://example.edu/logo.png');
  assert.strictEqual(logoOf(anchor).getAttribute('src'), 'https://example.edu/logo.png');
});

test('a logo cleared server-side overwrites the cache rather than leaving it stale', async () => {
  const { Layout, store } = loadLayout({
    store: { site_logo_url: 'https://old.example/logo.png' },
    fetchImpl: () => Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ site_name: 'CyberHub', site_logo_url: null })
    })
  });

  await Layout.loadSiteBranding();
  assert.strictEqual(store.site_logo_url, '', 'null must land as "", never be skipped');
});

test('the admin page is left alone — it paints its own name and would be clobbered', async () => {
  const { Layout, calls } = loadLayout({ pathname: '/admin' });
  await Layout.loadSiteBranding();
  assert.strictEqual(calls.length, 0);
});

test('a failed fetch leaves the cached branding painted', async () => {
  const { Layout, anchor } = loadLayout({
    store: { site_logo_url: '/img/seal.svg' },
    fetchImpl: () => Promise.reject(new Error('offline'))
  });
  Layout.applySiteBranding();
  await Layout.loadSiteBranding();
  assert.strictEqual(logoOf(anchor).getAttribute('src'), '/img/seal.svg');
});

// ── The favicon shares the path ─────────────────────────────────────────────

test('a configured favicon is applied, and an unsafe one is not', () => {
  const { Layout, head } = loadLayout({ store: { site_favicon_url: 'https://example.edu/f.ico' } });
  Layout.applySiteBranding();
  const link = head.children.find(c => c.rel === 'icon');
  assert.ok(link, 'a <link rel=icon> is appended to <head>');
  assert.strictEqual(link.getAttribute('href'), 'https://example.edu/f.ico');

  const unsafe = loadLayout({ store: { site_favicon_url: 'javascript:alert(1)' } });
  unsafe.Layout.applySiteBranding();
  assert.strictEqual(unsafe.head.children.length, 0);
});

// ── The second blocker: the browser has to be allowed to fetch it ───────────

test('the CSP permits an off-origin https logo', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'server.js'), 'utf8');
  const line = src.split('\n').find(l => l.includes('imgSrc:'));
  assert.ok(line, 'helmet still sets an imgSrc directive');
  assert.ok(/["']https:["']/.test(line),
    'imgSrc must allow https:, or every off-origin Logo URL is silently blocked ' +
    'by the browser with nothing but a console violation to show for it');
});

test('the CSP is not loosened beyond images', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'server.js'), 'utf8');
  for (const key of ['defaultSrc', 'connectSrc', 'scriptSrc']) {
    const line = src.split('\n').find(l => l.includes(key + ':'));
    if (!line) continue;
    assert.ok(!/["']https:["']/.test(line),
      key + ' must not carry a blanket https: — only imgSrc needs it');
  }
});

// ── The setting is no longer write-only anywhere in the product ─────────────

test('every brand-bearing page that fetches site-config also renders the logo', () => {
  const pub = path.join(__dirname, '..', 'public');
  // hub.html and module-placeholder.html are excluded on purpose: they draw the
  // sidebar, so Layout.applySiteBranding() is what renders their logo.
  for (const page of ['login.html', 'register.html', 'activate.html']) {
    const src = fs.readFileSync(path.join(pub, page), 'utf8');
    assert.ok(src.includes('/api/site-config'), page + ' fetches the config');
    assert.ok(src.includes('Branding.applyLogo'),
      page + ' fetches site_logo_url and must actually render it');
  }
});
