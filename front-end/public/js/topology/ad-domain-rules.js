/**
 * ad-domain-rules.js (browser) — the field-side mirror of the AD naming rules.
 *
 * The AUTHORITY is src/utils/ad-domain-rules.js, which the create handler runs
 * server-side; Track G's plugin compiler (goad-lab-compile.js) is the third
 * copy. This one exists so the author sees "that is not a DNS name" in the GOAD
 * card rather than in a 400 after clicking Create, which is the same reason
 * topology-editor.deriveSegments mirrors lane-networking.resolveVmSegments.
 *
 * The duplication is deliberate and pinned: test/ad-domain-rules.test.js runs
 * one corpus through all three copies and asserts they agree, so a rule changed
 * here and nowhere else fails there.
 *
 * KEEP THIS FILE IN LOCKSTEP WITH src/utils/ad-domain-rules.js. Every comment
 * explaining WHY a rule exists lives there; this file carries only the rule.
 *
 * Global: window.CyberCoreAdDomainRules
 */
(function (global) {
  'use strict';

  var MAX_NETBIOS_HOSTNAME = 15;

  var RESERVED_TLDS = ['local', 'invalid', 'test', 'example', 'localhost',
    'internal', 'lan', 'home', 'arpa', 'onion'];

  var FQDN_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
  var LABEL_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

  function isReservedTld(tld) { return RESERVED_TLDS.indexOf(tld) !== -1; }

  function str(v) { return v === null || v === undefined ? '' : String(v).trim(); }

  function normaliseFqdn(raw) {
    return str(raw)
      .toLowerCase()
      .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
      .replace(/\/.*$/, '')
      .replace(/\.$/, '')
      .replace(/^www\./, '');
  }

  function publicDomainOf(raw) {
    var name = normaliseFqdn(raw);
    if (!name || name.length > 200) return null;
    if (!FQDN_RE.test(name)) return null;
    var labels = name.split('.');
    if (labels.length < 2) return null;
    for (var i = 0; i < labels.length; i++) if (labels[i].length > 63) return null;
    var tld = labels[labels.length - 1];
    if (!/^[a-z]{2,}$/.test(tld) || isReservedTld(tld)) return null;
    return name;
  }

  function suffixRelated(a, b) {
    return a === b || a.slice(-(b.length + 1)) === '.' + b || b.slice(-(a.length + 1)) === '.' + a;
  }

  function netbiosCandidate(seed) {
    var cleaned = str(seed).toUpperCase().replace(/[^A-Z0-9-]/g, '').replace(/^-+|-+$/g, '');
    if (!cleaned || /^[0-9-]+$/.test(cleaned)) return 'CORP';
    return cleaned.slice(0, MAX_NETBIOS_HOSTNAME);
  }

  function netbiosForDomain(fqdn) {
    return netbiosCandidate(normaliseFqdn(fqdn).split('.')[0]);
  }

  function checkForestRoot(raw, opts) {
    var label = (opts && opts.label) || 'Forest domain';
    var name = normaliseFqdn(raw);
    var errors = [];
    var warnings = [];

    if (!name) {
      errors.push(label + ' is required.');
      return { value: null, errors: errors, warnings: warnings };
    }
    if (name.length > 200) {
      errors.push(label + ' is ' + name.length + ' characters; a DNS name tops out well before 200.');
      return { value: null, errors: errors, warnings: warnings };
    }
    if (!FQDN_RE.test(name)) {
      errors.push(label + ' "' + name + '" is not a DNS name. Use at least two lowercase labels separated ' +
        'by dots — letters, digits and internal hyphens only (a label may not start or end with a hyphen).');
      return { value: null, errors: errors, warnings: warnings };
    }
    var labels = name.split('.');
    var tooLong = labels.filter(function (l) { return l.length > 63; });
    if (tooLong.length) {
      errors.push(label + ': the label "' + tooLong[0] + '" is ' + tooLong[0].length +
        ' characters; DNS caps a label at 63.');
      return { value: null, errors: errors, warnings: warnings };
    }
    var tld = labels[labels.length - 1];
    if (!/^[a-z]{2,}$/.test(tld)) {
      errors.push(label + ': "' + tld + '" is not a usable top-level label — it must be two or more ' +
        'letters, no digits.');
      return { value: null, errors: errors, warnings: warnings };
    }
    if (isReservedTld(tld)) {
      warnings.push(label + ' "' + name + '" ends in .' + tld + ', which is a reserved TLD. ' +
        (tld === 'local'
          ? '.local is mDNS-reserved (RFC 6762) and blackholed by the platform mail relay, so anything '
          : 'It is an RFC 2606 / RFC 8375 reserved name, so anything ') +
        'sent to it inside the lane goes nowhere. Track G\'s lab compiler refuses .' + tld +
        ' outright — this lab will author, but a generated one with the same name would not.');
    }
    return { value: name, errors: errors, warnings: warnings };
  }

  function checkChild(raw, parentFqdn, opts) {
    var fieldLabel = (opts && opts.label) || 'Child subdomain';
    var errors = [];
    var warnings = [];
    var value = normaliseFqdn(raw);
    var parent = normaliseFqdn(parentFqdn);

    if (!value) return { label: null, fqdn: null, errors: errors, warnings: warnings };

    if (!parent) {
      errors.push(fieldLabel + ' "' + value + '" has no parent — fix the forest domain first.');
      return { label: null, fqdn: null, errors: errors, warnings: warnings };
    }

    var label = value;
    if (value.indexOf('.') !== -1) {
      if (value.slice(-(parent.length + 1)) !== '.' + parent) {
        errors.push(fieldLabel + ' "' + value + '" is not inside "' + parent + '". GOAD\'s ' +
          'ad-child_domain.yml derives the parent by dropping the first label and then looks that domain ' +
          'up with no fallback, so a child that is not literally <label>.' + parent + ' resolves a domain ' +
          'that does not exist and the play dies.');
        return { label: null, fqdn: null, errors: errors, warnings: warnings };
      }
      label = value.slice(0, -(parent.length + 1));
      if (label.indexOf('.') !== -1) {
        errors.push(fieldLabel + ' "' + value + '" is a grandchild of "' + parent + '" (' +
          label.split('.').length + ' labels below it). ad-child_domain.yml drops exactly ONE label to ' +
          'find the parent, so only a direct child works. Use "' + label.split('.').pop() + '.' + parent +
          '", or create the intermediate domain as its own child.');
        return { label: null, fqdn: null, errors: errors, warnings: warnings };
      }
    }

    if (!LABEL_RE.test(label)) {
      errors.push(fieldLabel + ' "' + label + '" is not a DNS label — letters, digits and internal ' +
        'hyphens only (it may not start or end with a hyphen).');
      return { label: null, fqdn: null, errors: errors, warnings: warnings };
    }
    if (label.length > 63) {
      errors.push(fieldLabel + ' "' + label + '" is ' + label.length + ' characters; DNS caps a label at 63.');
      return { label: null, fqdn: null, errors: errors, warnings: warnings };
    }

    if (netbiosCandidate(label) !== label.toUpperCase().replace(/[^A-Z0-9-]/g, '')) {
      warnings.push(fieldLabel + ' "' + label + '" becomes NetBIOS name ' + netbiosCandidate(label) +
        ' — Windows caps that name at ' + MAX_NETBIOS_HOSTNAME + ' characters, so the domain is known by ' +
        'the truncation everywhere it is typed.');
    }
    return { label: label, fqdn: label + '.' + parent, errors: errors, warnings: warnings };
  }

  function validateGoadDomains(goad) {
    var g = goad || {};
    var root = checkForestRoot(g.domain, { label: 'Forest domain' });
    var child = root.value
      ? checkChild(g.child_subdomain, root.value, { label: 'Child subdomain' })
      : { label: null, fqdn: null, errors: [], warnings: [] };

    return {
      errors: root.errors.concat(child.errors),
      warnings: root.warnings.concat(child.warnings),
      domain: root.value,
      child_label: child.label,
      child_fqdn: child.fqdn
    };
  }

  global.CyberCoreAdDomainRules = {
    MAX_NETBIOS_HOSTNAME: MAX_NETBIOS_HOSTNAME,
    RESERVED_TLDS: RESERVED_TLDS,
    normaliseFqdn: normaliseFqdn,
    publicDomainOf: publicDomainOf,
    suffixRelated: suffixRelated,
    netbiosCandidate: netbiosCandidate,
    netbiosForDomain: netbiosForDomain,
    checkForestRoot: checkForestRoot,
    checkChild: checkChild,
    validateGoadDomains: validateGoadDomains
  };
})(window);
