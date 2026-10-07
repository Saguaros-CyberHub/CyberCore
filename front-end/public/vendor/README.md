# Vendored browser libraries

CyberCore's frontend has **no build step** — `public/js/**` is hand-written ES5/ES2017
loaded by `<script>` tags. Third-party browser libraries therefore live here as
prebuilt UMD bundles, committed to the repo.

They are **not** loaded from a CDN, for two reasons:

1. **CSP.** `src/server.js` sets `scriptSrc: ["'self'", …]`, so any off-origin
   script is blocked outright.
2. **Offline mode.** CyberCore is deployed to air-gapped and LAN-only sites
   (see the Offline Mode doc). Anything fetched at runtime is unavailable there.

## Contents

| File | Package | Version | License |
|---|---|---|---|
| `cytoscape.min.js` | [cytoscape](https://www.npmjs.com/package/cytoscape) | 3.34.1 | MIT (`LICENSE.cytoscape`) |
| `cytoscape-edgehandles.js` | [cytoscape-edgehandles](https://www.npmjs.com/package/cytoscape-edgehandles) | 4.0.1 | MIT (`LICENSE.cytoscape-edgehandles`) |
| `lodash.min.js` | [lodash](https://www.npmjs.com/package/lodash) | 4.18.1 | MIT (`LICENSE.lodash`) |

## Load order matters

```html
<script src="/vendor/lodash.min.js"></script>          <!-- must precede edgehandles -->
<script src="/vendor/cytoscape.min.js"></script>       <!-- must precede edgehandles -->
<script src="/vendor/cytoscape-edgehandles.js"></script>
```

`cytoscape-edgehandles` ships a webpack UMD bundle whose browser branch resolves
its two dependencies as `root["_"]["memoize"]` and `root["_"]["throttle"]` — i.e.
it expects a global lodash. That is why full lodash is here for what looks like
two small functions: it is the dependency form upstream actually builds against,
and a hand-written `_` shim would be an unversioned reimplementation of code we
do not own.

The edgehandles bundle self-registers against the global `cytoscape` when it
loads, so an explicit `cytoscape.use(cytoscapeEdgehandles)` is redundant (and
logs a harmless "already exists in the prototype" warning if you call it).

## Refreshing a library

```bash
npm pack cytoscape                       # or cytoscape-edgehandles / lodash
tar xzf cytoscape-<version>.tgz
cp package/dist/cytoscape.min.js  front-end/public/vendor/
cp package/LICENSE                front-end/public/vendor/LICENSE.cytoscape
```

Then update the version in the table above. `npm pack` is used rather than
`npm install` deliberately — these are not runtime dependencies of the Node
server and must not enter `package.json`.
