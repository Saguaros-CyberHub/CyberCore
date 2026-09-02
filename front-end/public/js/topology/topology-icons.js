/**
 * topology-icons.js — glyphs for topology nodes.
 *
 * Cytoscape draws to canvas, so node artwork has to be an image. These are
 * inline SVGs encoded as `data:` URIs at runtime, which:
 *   - needs no image files and no extra requests (offline mode is a supported
 *     deployment, see the Offline Mode doc)
 *   - satisfies the CSP in src/server.js, which allows `imgSrc: data:` but only
 *     `scriptSrc: 'self'`
 *   - lets the stroke colour follow the active theme, because the colour is
 *     baked in when the URI is built rather than fixed in a checked-in asset
 *
 * Icons are stroke-only on a transparent ground and are drawn inside a 24×24
 * viewBox, so they stay crisp at any node size.
 *
 * Global: window.CyberCoreTopologyIcons
 */
(function (global) {
  'use strict';

  // Each entry is the inner markup of a 24×24 SVG. `currentColor` is substituted
  // for the requested colour when the data URI is built.
  var GLYPHS = {
    // Four-pane window.
    windows_client:
      '<rect x="3" y="4" width="18" height="16" rx="1.5"/><path d="M3 11h18M11 4v16"/>',
    // Stacked rack units.
    windows_server:
      '<rect x="3" y="4" width="18" height="5.5" rx="1"/><rect x="3" y="14.5" width="18" height="5.5" rx="1"/>' +
      '<path d="M6.5 6.75h.01M6.5 17.25h.01"/>',
    // Terminal prompt.
    linux:
      '<rect x="3" y="4" width="18" height="16" rx="1.5"/><path d="M7 9.5l2.5 2.5L7 14.5M12.5 15.5h4"/>',
    macos:
      '<rect x="2.5" y="4.5" width="19" height="12" rx="1.5"/><path d="M9 20h6M12 16.5V20"/>',
    // Router: a box with traffic crossing it.
    network:
      '<rect x="3" y="9" width="18" height="10" rx="1.5"/><path d="M8 6.5l-2-2 2-2M6 4.5h6M16 2.5l2 2-2 2M18 4.5h-6"/>',
    // Shield — the dual-homed DMZ pivot host.
    dmz:
      '<path d="M12 3l7.5 3v5.5c0 4.2-3.1 7.6-7.5 9.5-4.4-1.9-7.5-5.3-7.5-9.5V6z"/><path d="M12 9v5"/>',
    // Crosshair — the attacker box.
    attacker:
      '<circle cx="12" cy="12" r="6.5"/><path d="M12 1.5v4M12 18.5v4M1.5 12h4M18.5 12h4"/>',
    // Domain controller: server with a key.
    dc:
      '<rect x="3" y="4" width="18" height="5.5" rx="1"/><path d="M6.5 6.75h.01"/>' +
      '<circle cx="8.5" cy="16.5" r="2.5"/><path d="M11 16.5h9M17.5 16.5v3M20 16.5v2.5"/>',
    // SIEM (ELK / Wazuh): a magnifying glass over stacked log lines — the box
    // that is READ rather than attacked. Deliberately not the server rack:
    // `siem` and `windows_server` sitting side by side on a blue-team canvas is
    // exactly where an author needs to see at a glance which one is the console
    // and which one is the evidence store.
    siem:
      '<rect x="3" y="4" width="18" height="16" rx="1.5"/><path d="M6.5 8h7M6.5 11h4"/>' +
      '<circle cx="14" cy="14.5" r="3"/><path d="M16.3 16.8L19 19.5"/>',
    // Lane gateway LXC: shield with a through-path.
    gateway:
      '<path d="M12 2.5l7 2.8v5.2c0 4-2.9 7.2-7 9-4.1-1.8-7-5-7-9V5.3z"/><path d="M8.5 11.5h7M12.5 8.5l3 3-3 3"/>',
    // Network segment: a bus with three taps.
    segment:
      '<path d="M2.5 15.5h19M7 15.5v-4M12 15.5v-4M17 15.5v-4"/>' +
      '<rect x="5" y="6" width="4" height="5" rx="1"/><rect x="10" y="6" width="4" height="5" rx="1"/>' +
      '<rect x="15" y="6" width="4" height="5" rx="1"/>',
    unknown:
      '<rect x="3" y="4" width="18" height="16" rx="1.5"/><path d="M9.5 9.5a2.5 2.5 0 113.2 2.4c-.5.2-.7.6-.7 1.1v.5M12 16.5h.01"/>'
  };

  /**
   * Pick a glyph for a machine. Role wins over OS family, because "this is the
   * attacker box" or "this is the pivot host" is what an author is scanning the
   * canvas for — a Kali box reads better as a crosshair than as a terminal.
   */
  function glyphKey(node) {
    if (!node) return 'unknown';
    if (node.kind === 'segment') return 'segment';
    if (node.kind === 'gateway') return 'gateway';

    var role = String(node.role || '').toLowerCase();
    if (role === 'dmz') return 'dmz';
    if (role === 'attacker') return 'attacker';
    if (role === 'dc') return 'dc';
    // Before this entry existed a SIEM fell through to the OS sniff and drew as
    // a generic Linux terminal — indistinguishable from the sensor, the pivot
    // and every other Debian box on a blue-team lane.
    if (role === 'siem') return 'siem';

    var family = String(node.os_family || '').toLowerCase();
    if (GLYPHS[family]) return family;

    // No catalog family (hand-typed VM rows have only a free-text `os`), so
    // fall back to sniffing the OS string.
    var os = String(node.os || '').toLowerCase();
    if (/kali|parrot/.test(os)) return 'attacker';
    if (/windows\s*server|server\s*(2016|2019|2022|2025)/.test(os)) return 'windows_server';
    if (/windows/.test(os)) return 'windows_client';
    if (/mac|darwin|osx/.test(os)) return 'macos';
    if (/linux|debian|ubuntu|rocky|centos|alpine|rhel|fedora/.test(os)) return 'linux';
    if (/router|switch|firewall|pfsense|opnsense/.test(os)) return 'network';
    return 'unknown';
  }

  var cache = Object.create(null);

  /**
   * Build a `data:` URI for a node's glyph in the given colour.
   * Encoded with encodeURIComponent rather than btoa — the markup is ASCII, and
   * a percent-encoded SVG stays readable in devtools.
   */
  function dataUri(key, color) {
    var cacheKey = key + '|' + color;
    if (cache[cacheKey]) return cache[cacheKey];

    var inner = GLYPHS[key] || GLYPHS.unknown;
    var svg =
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" ' +
      'fill="none" stroke="' + color + '" stroke-width="1.6" ' +
      'stroke-linecap="round" stroke-linejoin="round">' + inner + '</svg>';

    cache[cacheKey] = 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
    return cache[cacheKey];
  }

  global.CyberCoreTopologyIcons = {
    glyphKey: glyphKey,
    /** for({ kind, role, os_family, os }, '#fff') → data URI */
    for: function (node, color) { return dataUri(glyphKey(node), color || '#000'); },
    /** Available keys, for the palette legend. */
    keys: function () { return Object.keys(GLYPHS); }
  };
})(window);
