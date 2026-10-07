/**
 * ai/profile/reconcile-workstations.js
 * ============================================================================
 * Rebuilds the workstation asset list so it matches the IT branch's declared
 * endpoint counts (windows_desktops/windows_laptops/shared_kiosks/macos/
 * mobile), distributed across the network branch's actual subnets by
 * industry-aware purpose (a library's public-access lab looks different from
 * a law firm's staff subnet).
 *
 * This used to live inline in render.js and only ran at HTML-render time —
 * meaning the HTML report would self-correct for display, but that correction
 * was never saved back into the profile JSON. Every other consumer (intake
 * form pre-fill, policy generation, the interview simulator, the admin
 * deploy console) reads the JSON directly, so they'd disagree with what the
 * HTML showed. Extracted here so profile generation can run it once, save
 * the result into the JSON, and render.js can just reuse that same result —
 * one reconciliation, not two independently-drifting ones.
 *
 * Pure function: no I/O, no LLM calls, deterministic given the same inputs.
 *
 * @param {object} args
 * @param {object} args.endpoints   IT branch's { windows_laptops, windows_desktops, shared_kiosks, macos, mobile }
 * @param {Array}  args.assets      network branch's asset list (servers, network gear, workstations, etc.)
 * @param {Array}  args.subnets     network branch's subnet list ({ name, purpose, range|cidr })
 * @param {string} [args.industry]
 * @param {string} [args.clientType]
 * @returns {{ endpoints: object, assets: Array }}
 */
function reconcileWorkstations({ endpoints, assets, subnets, industry, clientType }) {
  const ep = { ...(endpoints || {}) };
  assets = Array.isArray(assets) ? assets : [];
  subnets = Array.isArray(subnets) ? subnets : [];

  let wsAssets = assets.filter(a => a.role === 'workstation');
  const nonWsAssets = assets.filter(a => a.role !== 'workstation');

  // ── Industry-aware endpoint filtering ──
  // Filter out device types that aren't realistic for this organization type.
  // Mobile devices and kiosks are only included for industries that actually use them.
  const orgContext = (industry || '').toLowerCase() + ' ' + (clientType || '').toLowerCase();

  const includeMobile = /\b(healthcare|hospital|clinic|medical|pharma|field.?service|logistics|construction|utilities|energy|emergency|law.?enforcement|government.?agency)\b/.test(orgContext);
  const includeKiosk = /\b(retail|hospitality|hotel|restaurant|hospital|clinic|library|museum|airport|transit|warehouse|manufacturing|bank)\b/.test(orgContext);
  const includeMacOS = /\b(creative|design|media|marketing.?agency|tech|software|startup|university|architecture|video|music|advertising)\b/.test(orgContext);

  // Build assignment queue with industry-appropriate device types only
  const assignmentQueue = [];
  if (ep.windows_laptops > 0)   assignmentQueue.push({ os: 'Windows 11 Pro', type: 'laptop', count: ep.windows_laptops, fn: 'Employee Laptop' });
  if (ep.windows_desktops > 0)  assignmentQueue.push({ os: 'Windows 11 Pro', type: 'desktop', count: ep.windows_desktops, fn: 'Employee Desktop' });
  if (ep.shared_kiosks > 0 && includeKiosk)  assignmentQueue.push({ os: 'Windows 10 Enterprise LTSC', type: 'kiosk', count: ep.shared_kiosks, fn: 'Shared Kiosk Terminal' });
  if (ep.macos > 0 && includeMacOS)          assignmentQueue.push({ os: 'macOS Sonoma 14', type: 'laptop', count: ep.macos, fn: 'Employee MacBook' });
  if (ep.mobile > 0 && includeMobile)        assignmentQueue.push({ os: 'iOS 17 / Android 14', type: 'mobile', count: ep.mobile, fn: 'Mobile Device (MDM)' });

  // If filtering removed devices, redistribute those counts to laptops/desktops
  const filteredOut = (ep.shared_kiosks || 0) * (!includeKiosk ? 1 : 0) +
                      (ep.macos || 0) * (!includeMacOS ? 1 : 0) +
                      (ep.mobile || 0) * (!includeMobile ? 1 : 0);
  if (filteredOut > 0) {
    // Add filtered counts back as desktops (most common fallback)
    const desktopEntry = assignmentQueue.find(q => q.type === 'desktop');
    if (desktopEntry) {
      desktopEntry.count += filteredOut;
    } else if (assignmentQueue.length > 0) {
      assignmentQueue[0].count += filteredOut; // add to whatever exists
    }
    // Update the endpoints display counts too
    if (!includeKiosk && ep.shared_kiosks) { ep.windows_desktops = (ep.windows_desktops || 0) + ep.shared_kiosks; delete ep.shared_kiosks; }
    if (!includeMacOS && ep.macos) { ep.windows_laptops = (ep.windows_laptops || 0) + ep.macos; delete ep.macos; }
    if (!includeMobile && ep.mobile) { ep.windows_desktops = (ep.windows_desktops || 0) + ep.mobile; delete ep.mobile; }
  }

  // Calculate the authoritative endpoint total from IT env
  const endpointTotal = assignmentQueue.reduce((sum, b) => sum + b.count, 0);

  // Reconcile workstation count to match endpoint total AND distribute across subnets
  if (endpointTotal > 0) {
    // Identify workstation-eligible subnets (exclude server/infrastructure/management subnets)
    const wsSubnets = subnets.filter(s => {
      const n = ((s.name || '') + ' ' + (s.purpose || '')).toLowerCase();
      // Exclude subnets meant for servers, infrastructure, or network management
      const isInfraOnly = /\b(server|datacenter|data.?center|server.?room|infrastructure|management|mgmt|network.?management|backbone|transit)\b/.test(n) &&
                          !/\b(staff|user|employee|workstation|desktop|laptop|student|classroom|admin|office)\b/.test(n);
      return !isInfraOnly && (s.range || s.cidr);
    });

    // Assign distribution weights based on subnet purpose/name
    // Works across all company types: corporate, healthcare, education, manufacturing, retail, government, etc.
    const subnetWeights = wsSubnets.map(s => {
      const n = ((s.name || '') + ' ' + (s.purpose || '')).toLowerCase();
      // ── Very high density: a library's public-access computer lab is the
      //    densest part of the network — more machines than staff. Must be
      //    checked BEFORE the generic guest/public rule below (which is for
      //    corporate BYOD lobbies and is low-density). ──
      if (/\b(public.?access|patron|public.?computer|public.?pc|public.?lab)\b/.test(n)) return { subnet: s, weight: 55 };
      // ── High density (35-45): primary user subnets where most endpoints live ──
      if (/\b(staff|employee|corporate|office|workstation|user|desktop|internal)\b/.test(n)) return { subnet: s, weight: 40 };
      if (/\b(clinical|nursing|medical|patient.care|ward)\b/.test(n)) return { subnet: s, weight: 40 }; // healthcare
      if (/\b(production|shop.?floor|warehouse|manufacturing|plant)\b/.test(n)) return { subnet: s, weight: 35 }; // manufacturing
      if (/\b(trading|operations|call.?center)\b/.test(n)) return { subnet: s, weight: 40 }; // finance

      // ── Medium density (15-25): department/functional subnets ──
      if (/\b(admin|administration|executive|front.?desk|reception)\b/.test(n)) return { subnet: s, weight: 20 };
      if (/\b(student|classroom|lab|library|learning|academic|faculty|teacher)\b/.test(n)) return { subnet: s, weight: 25 }; // education
      if (/\b(engineering|development|r&d|research|design|dev)\b/.test(n)) return { subnet: s, weight: 20 };
      if (/\b(sales|marketing|retail|store|pos|point.of.sale)\b/.test(n)) return { subnet: s, weight: 20 };
      if (/\b(hr|human.resource|finance|accounting|legal|compliance)\b/.test(n)) return { subnet: s, weight: 15 };
      if (/\b(pharmacy|radiology|imaging|diagnostic)\b/.test(n)) return { subnet: s, weight: 15 }; // healthcare

      // ── Low density (3-10): restricted/special purpose subnets ──
      if (/\b(guest|visitor|public|lobby|waiting|open)\b/.test(n)) return { subnet: s, weight: 5 };
      if (/\b(wireless|wifi|byod|mobile)\b/.test(n)) return { subnet: s, weight: 8 };
      if (/\b(dmz|external|perimeter)\b/.test(n)) return { subnet: s, weight: 2 };
      if (/\b(iot|scada|ot|hvac|camera|security|building)\b/.test(n)) return { subnet: s, weight: 3 };
      if (/\b(voice|voip|phone|telephony)\b/.test(n)) return { subnet: s, weight: 3 };
      if (/\b(printer|print)\b/.test(n)) return { subnet: s, weight: 2 };
      if (/\b(backup|storage|san|nas)\b/.test(n)) return { subnet: s, weight: 1 };

      // ── Default: moderate allocation for unrecognized subnets ──
      return { subnet: s, weight: 15 };
    });

    const totalWeight = subnetWeights.reduce((s, w) => s + w.weight, 0) || 1;

    // ── Determine preferred device types per subnet based on purpose ──
    // Each subnet gets a preference order: which device types belong here?
    // The system pulls from the available endpoint pool accordingly.
    const getSubnetDevicePrefs = (subnetName) => {
      const n = subnetName.toLowerCase();
      // Library public-access lab: rows of public computers (desktops) plus a
      // few catalog/self-check kiosks. Checked before the generic guest/public
      // rule (which is BYOD/mobile-only).
      if (/\b(public.?access|patron|public.?computer|public.?pc|public.?lab)\b/.test(n))
        return ['desktop', 'kiosk'];
      // Education
      if (/\b(student|classroom|lab|library|learning|academic)\b/.test(n))
        return ['desktop', 'kiosk', 'laptop']; // shared desktops, kiosks, some laptops
      if (/\b(faculty|teacher|staff)\b/.test(n))
        return ['laptop', 'desktop']; // teacher laptops, some desktops
      // Healthcare
      if (/\b(clinical|nursing|patient|ward|medical)\b/.test(n))
        return ['desktop', 'mobile', 'laptop']; // workstations, tablets, carts
      if (/\b(pharmacy|radiology|imaging)\b/.test(n))
        return ['desktop', 'kiosk'];
      // Manufacturing / Retail
      if (/\b(production|shop.?floor|warehouse|plant)\b/.test(n))
        return ['kiosk', 'desktop', 'mobile'];
      if (/\b(pos|point.of.sale|store|retail|sales.?floor)\b/.test(n))
        return ['kiosk', 'desktop'];
      // Office / Corporate
      if (/\b(admin|administration|executive|front.?desk|reception|office)\b/.test(n))
        return ['laptop', 'desktop'];
      if (/\b(engineering|development|r&d|research|design|dev)\b/.test(n))
        return ['laptop', 'desktop'];
      if (/\b(hr|human.resource|finance|accounting|legal|compliance)\b/.test(n))
        return ['laptop', 'desktop'];
      if (/\b(trading|operations|call.?center)\b/.test(n))
        return ['desktop', 'laptop'];
      // General user subnets
      if (/\b(staff|employee|corporate|workstation|user|internal)\b/.test(n))
        return ['laptop', 'desktop', 'mobile'];
      // Restricted
      if (/\b(guest|visitor|public|lobby)\b/.test(n))
        return ['mobile']; // guest = BYOD/mobile only
      if (/\b(wireless|wifi|byod)\b/.test(n))
        return ['mobile', 'laptop'];
      // Default
      return ['laptop', 'desktop'];
    };

    // Build remaining pool of each device type
    const devicePool = {};
    for (const q of assignmentQueue) {
      devicePool[q.type] = (devicePool[q.type] || 0) + q.count;
    }
    // Map for lookup
    const deviceInfo = {};
    for (const q of assignmentQueue) {
      if (!deviceInfo[q.type]) deviceInfo[q.type] = { os: q.os, fn: q.fn };
    }

    // Generate workstations per subnet, pulling from the device pool by preference
    wsAssets = [];
    let globalIdx = 0;

    // Sort subnets by weight descending so high-priority subnets get first pick
    const sortedWeights = [...subnetWeights].sort((a, b) => b.weight - a.weight);

    for (const sw of sortedWeights) {
      const subRange = sw.subnet.range || sw.subnet.cidr || '';
      const subnetBase = subRange.replace(/\/\d+$/, '').split('.').slice(0, 3).join('.');
      const subnetName = (sw.subnet.name || '') + ' ' + (sw.subnet.purpose || '');
      const targetCount = Math.round((sw.weight / totalWeight) * endpointTotal);
      const prefs = getSubnetDevicePrefs(subnetName);

      let subnetAssigned = 0;

      // Pull devices in preference order
      for (const prefType of prefs) {
        if (subnetAssigned >= targetCount) break;
        const available = devicePool[prefType] || 0;
        if (available <= 0) continue;

        // How many of this type to assign? Proportional to remaining need
        const remaining = targetCount - subnetAssigned;
        const toAssign = Math.min(available, remaining);

        for (let i = 0; i < toAssign; i++) {
          const ipHost = 50 + subnetAssigned + i;
          const info = deviceInfo[prefType] || { os: 'Windows 11 Pro', fn: 'Workstation' };
          wsAssets.push({
            hostname: `ws-${String(globalIdx + 1).padStart(3, '0')}`,
            ip: subnetBase ? `${subnetBase}.${Math.min(ipHost, 254)}` : '',
            subnet: subRange,
            role: 'workstation',
            function: info.fn,
            os: info.os,
            _asset_type: prefType,
            critical: false
          });
          globalIdx++;
        }
        devicePool[prefType] -= toAssign;
        subnetAssigned += toAssign;
      }

      // If still need more and pool has remaining devices of any type, fill
      if (subnetAssigned < targetCount) {
        for (const type of Object.keys(devicePool)) {
          if (subnetAssigned >= targetCount) break;
          const available = devicePool[type] || 0;
          if (available <= 0) continue;
          const toAssign = Math.min(available, targetCount - subnetAssigned);
          for (let i = 0; i < toAssign; i++) {
            const ipHost = 50 + subnetAssigned + i;
            const info = deviceInfo[type] || { os: 'Windows 11 Pro', fn: 'Workstation' };
            wsAssets.push({
              hostname: `ws-${String(globalIdx + 1).padStart(3, '0')}`,
              ip: subnetBase ? `${subnetBase}.${Math.min(ipHost, 254)}` : '',
              subnet: subRange,
              role: 'workstation',
              function: info.fn,
              os: info.os,
              _asset_type: type,
              critical: false
            });
            globalIdx++;
          }
          devicePool[type] -= toAssign;
          subnetAssigned += toAssign;
        }
      }
    }

    // Any remaining devices that didn't fit (rounding) go to the largest subnet
    const remainingTotal = Object.values(devicePool).reduce((s, v) => s + v, 0);
    if (remainingTotal > 0 && sortedWeights.length > 0) {
      const bigSub = sortedWeights[0].subnet;
      const subRange = bigSub.range || bigSub.cidr || '';
      const subnetBase = subRange.replace(/\/\d+$/, '').split('.').slice(0, 3).join('.');
      for (const type of Object.keys(devicePool)) {
        while (devicePool[type] > 0) {
          const info = deviceInfo[type] || { os: 'Windows 11 Pro', fn: 'Workstation' };
          wsAssets.push({
            hostname: `ws-${String(globalIdx + 1).padStart(3, '0')}`,
            ip: subnetBase ? `${subnetBase}.${Math.min(200 + (globalIdx % 54), 254)}` : '',
            subnet: subRange,
            role: 'workstation',
            function: info.fn,
            os: info.os,
            _asset_type: type,
            critical: false
          });
          globalIdx++;
          devicePool[type]--;
        }
      }
    }
  }

  let outAssets = [...nonWsAssets, ...wsAssets];

  // ── Always clean up: remove workstations from infrastructure subnets ──
  // This catches LLM-generated workstations that were placed in server/management ranges
  {
    const infraSubnets = subnets.filter(s => {
      const n = ((s.name || '') + ' ' + (s.purpose || '')).toLowerCase();
      return /\b(server|datacenter|data.?center|server.?room|infrastructure|management|mgmt|network.?management|backbone|transit)\b/.test(n) &&
             !/\b(staff|user|employee|workstation|desktop|laptop|student|classroom|admin|office)\b/.test(n);
    });
    if (infraSubnets.length > 0) {
      const infraPrefixes = infraSubnets.map(s => {
        const r = s.range || s.cidr || '';
        return r.replace(/\/\d+$/, '').split('.').slice(0, 3).join('.');
      }).filter(Boolean);

      const beforeCount = outAssets.length;
      outAssets = outAssets.filter(a => {
        if (a.role !== 'workstation') return true; // keep non-workstations
        if (!a.ip) return true; // keep if no IP to check
        const assetPrefix = a.ip.split('.').slice(0, 3).join('.');
        return !infraPrefixes.includes(assetPrefix); // remove if IP is in infra subnet
      });
      const removed = beforeCount - outAssets.length;
      if (removed > 0) {
        // Redistribute removed workstations to the largest eligible subnet
        const eligibleSubnets = subnets.filter(s => {
          const n = ((s.name || '') + ' ' + (s.purpose || '')).toLowerCase();
          return !/\b(server|datacenter|data.?center|server.?room|infrastructure|management|mgmt|network.?management|backbone|transit)\b/.test(n) ||
                 /\b(staff|user|employee|workstation|desktop|laptop|student|classroom|admin|office)\b/.test(n);
        });
        if (eligibleSubnets.length > 0) {
          // Pick the first eligible subnet (typically the largest user subnet)
          const targetSub = eligibleSubnets[0];
          const subRange = targetSub.range || targetSub.cidr || '';
          const subBase = subRange.replace(/\/\d+$/, '').split('.').slice(0, 3).join('.');
          for (let i = 0; i < removed; i++) {
            outAssets.push({
              hostname: `ws-relocated-${String(i + 1).padStart(3, '0')}`,
              ip: subBase ? `${subBase}.${Math.min(200 + i, 254)}` : '',
              subnet: subRange,
              role: 'workstation',
              function: 'Employee Desktop',
              os: 'Windows 11 Pro',
              _asset_type: 'desktop',
              critical: false
            });
          }
        }
      }
    }
  }

  return { endpoints: ep, assets: outAssets };
}

module.exports = { reconcileWorkstations };
