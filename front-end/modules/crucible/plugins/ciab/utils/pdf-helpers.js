/**
 * Shared PDFKit primitives for CIAB report renderers (intake form, Clinic
 * Risk Assessment deliverable, future report types).
 *
 * Pure function module — no DB, no IO. All renderers take a PDFDocument and
 * mutate it in place; doc.y is locked at the end of each helper to prevent
 * drift from PDFKit's variable text-height behavior.
 */

const PDF_COLORS = {
  primary:      '#1e40af',
  primaryLight: '#dbeafe',
  headerBg:     '#1e3a5f',
  headerText:   '#ffffff',
  sectionBg:    '#f0f4f8',
  border:       '#cbd5e1',
  text:         '#1e293b',
  textLight:    '#64748b',
  yes:          '#16a34a',
  no:           '#dc2626',
  unknown:      '#d97706',
  checkOn:      '#1e40af',
  checkOff:     '#cbd5e1',
};

/**
 * Add a page break if `needed` points wouldn't fit before the bottom margin.
 */
function ensureSpace(doc, needed) {
  if (doc.y + needed > doc.page.height - 60) doc.addPage();
}

function labelOf(field, labels) {
  return (labels && labels[field]) || field.replace(/_/g, ' ');
}

/**
 * Two-column section header bar (filled rectangle with white title text).
 */
function renderSectionHeader(doc, title) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftMargin = doc.page.margins.left;
  ensureSpace(doc, 30);
  const headerY = doc.y;
  doc.rect(leftMargin, headerY, pageWidth, 22).fill(PDF_COLORS.headerBg);
  doc.fontSize(11).font('Helvetica-Bold').fillColor(PDF_COLORS.headerText)
    .text(title, leftMargin + 10, headerY + 5, { width: pageWidth - 20 });
  doc.y = headerY + 26;
}

/**
 * Three-column checklist of boolean fields, with on/off boxes.
 * `data` is a flat object; `fields` lists which keys to render.
 */
function renderChecklist(doc, data, fields, labels) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftMargin = doc.page.margins.left;
  const colWidth = (pageWidth - 6) / 3;
  const ROW_H = 12;
  let col = 0;
  let rowY = doc.y;

  fields.forEach(f => {
    if (col === 0 && rowY + ROW_H > doc.page.height - 60) {
      doc.addPage();
      rowY = doc.y;
    }

    const isChecked = data[f] === true || data[f] === 'true';
    const x = leftMargin + col * colWidth;
    const label = labelOf(f, labels);
    const color = isChecked ? PDF_COLORS.text : PDF_COLORS.textLight;

    if (isChecked) {
      doc.rect(x, rowY + 1, 7, 7).fill(PDF_COLORS.checkOn);
    } else {
      doc.rect(x, rowY + 1, 7, 7).lineWidth(0.5).strokeColor(PDF_COLORS.checkOff).stroke();
    }

    doc.fontSize(8).font('Helvetica').fillColor(color)
      .text(label, x + 10, rowY, { width: colWidth - 12 });
    doc.y = rowY + ROW_H;

    col++;
    if (col >= 3) { col = 0; rowY += ROW_H; }
  });
  if (col > 0) rowY += ROW_H;
  doc.y = rowY;
}

/**
 * Yes/No/Unknown rows with right-aligned colored badges.
 */
function renderYesNo(doc, data, fields, labels) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftMargin = doc.page.margins.left;

  fields.forEach(f => {
    const val = data[f];
    if (!val) return;

    const label = labelOf(f, labels);
    let display, color;
    if (val === 'yes')      { display = 'YES';     color = PDF_COLORS.yes; }
    else if (val === 'no')  { display = 'NO';      color = PDF_COLORS.no; }
    else                    { display = 'UNKNOWN'; color = PDF_COLORS.unknown; }

    if (doc.y + 15 > doc.page.height - 60) doc.addPage();

    const rowY = doc.y;
    doc.fontSize(8.5).font('Helvetica').fillColor(PDF_COLORS.text)
      .text(label, leftMargin, rowY, { width: pageWidth - 70 });

    const badgeX = leftMargin + pageWidth - 50;
    doc.roundedRect(badgeX, rowY - 1, 42, 12, 3).fill(color);
    doc.fontSize(7).font('Helvetica-Bold').fillColor('#ffffff')
      .text(display, badgeX, rowY + 1, { width: 42, align: 'center' });

    doc.y = rowY + 15;
  });
}

/**
 * Numeric score rows (0–4) with progress-bar visualization.
 */
function renderScores(doc, data, fields, labels) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftMargin = doc.page.margins.left;
  const barMaxWidth = 80;
  const barX = leftMargin + pageWidth - barMaxWidth - 30;

  fields.forEach(f => {
    const val = parseInt(data[f]);
    if (isNaN(val)) return;
    const label = labelOf(f, labels);

    if (doc.y + 14 > doc.page.height - 60) doc.addPage();

    const rowY = doc.y;
    doc.fontSize(8).font('Helvetica').fillColor(PDF_COLORS.text)
      .text(label, leftMargin, rowY, { width: pageWidth - barMaxWidth - 50 });

    doc.roundedRect(barX, rowY + 1, barMaxWidth, 7, 2).fill('#e2e8f0');
    const fillWidth = (val / 4) * barMaxWidth;
    if (fillWidth > 0) {
      const fillColor = val <= 1 ? PDF_COLORS.no : val <= 2 ? PDF_COLORS.unknown : PDF_COLORS.yes;
      doc.roundedRect(barX, rowY + 1, fillWidth, 7, 2).fill(fillColor);
    }
    doc.fontSize(7.5).font('Helvetica-Bold').fillColor(PDF_COLORS.text)
      .text(`${val}/4`, barX + barMaxWidth + 5, rowY, { width: 30 });

    doc.y = rowY + 14;
  });
}

/**
 * IG1 safeguard responses — keys of form ig1_X.X with values yes|partial|no|unknown.
 * Optional sibling key `${key}_notes` is rendered as small grey text below the row.
 */
function renderIG1(doc, data) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftMargin = doc.page.margins.left;

  const keys = Object.keys(data || {})
    .filter(k => /^ig1_\d+\.\d+$/.test(k))
    .sort((a, b) => parseFloat(a.replace('ig1_', '')) - parseFloat(b.replace('ig1_', '')));

  if (keys.length === 0) {
    doc.fontSize(9).font('Helvetica').fillColor(PDF_COLORS.textLight)
      .text('No IG1 safeguard responses recorded.', leftMargin, doc.y);
    doc.moveDown(0.3);
    return;
  }

  keys.forEach(key => {
    const num = key.replace('ig1_', '');
    const val = data[key];
    const notes = data[`${key}_notes`] || '';
    if (!val) return;

    ensureSpace(doc, 20);
    const rowY = doc.y;

    doc.fontSize(8).font('Helvetica-Bold').fillColor(PDF_COLORS.textLight)
      .text(num, leftMargin, rowY, { width: 30 });

    let display, color;
    if (val === 'yes')          { display = 'YES';        color = PDF_COLORS.yes; }
    else if (val === 'partial') { display = 'PARTIAL';    color = PDF_COLORS.unknown; }
    else if (val === 'no')      { display = 'NO';         color = PDF_COLORS.no; }
    else                        { display = "DON'T KNOW"; color = PDF_COLORS.textLight; }

    const badgeX = leftMargin + pageWidth - 60;
    doc.roundedRect(badgeX, rowY - 1, 52, 12, 3).fill(color);
    doc.fontSize(6.5).font('Helvetica-Bold').fillColor('#ffffff')
      .text(display, badgeX, rowY + 1, { width: 52, align: 'center' });

    doc.y = rowY + 14;

    if (notes) {
      ensureSpace(doc, 16);
      doc.fontSize(7.5).font('Helvetica').fillColor(PDF_COLORS.textLight)
        .text(`Notes: ${notes}`, leftMargin + 30, doc.y, { width: pageWidth - 90 });
      doc.moveDown(0.1);
    }
  });
}

/**
 * Cover page with title, optional subtitle, company name, and key/value meta rows.
 * Resets to a fresh page if the current page already has content.
 *
 * @param {Object} opts
 * @param {string} opts.title         e.g. "Client Intake Form"
 * @param {string} [opts.subtitle]    e.g. "Cybersecurity Risk Assessment"
 * @param {string} opts.companyName
 * @param {Array<[string,string]>} [opts.meta]  rows of [label, value]
 * @param {string} [opts.watermark]   optional banner text (e.g. "TRAINING SAMPLE")
 */
function renderCoverPage(doc, opts) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftMargin = doc.page.margins.left;

  if (doc.y > doc.page.margins.top + 5) doc.addPage();

  if (opts.watermark) {
    const wmY = doc.y;
    doc.rect(leftMargin, wmY, pageWidth, 18).fill(PDF_COLORS.unknown);
    doc.fontSize(10).font('Helvetica-Bold').fillColor('#ffffff')
      .text(opts.watermark, leftMargin, wmY + 4, { width: pageWidth, align: 'center' });
    doc.y = wmY + 24;
  }

  doc.moveDown(2);

  doc.rect(leftMargin, doc.y, pageWidth, 3).fill(PDF_COLORS.primary);
  doc.y += 10;
  doc.fontSize(26).font('Helvetica-Bold').fillColor(PDF_COLORS.headerBg)
    .text(opts.title, { align: 'center' });
  doc.moveDown(0.15);
  if (opts.subtitle) {
    doc.fontSize(10).font('Helvetica').fillColor(PDF_COLORS.textLight)
      .text(opts.subtitle, { align: 'center' });
  }
  doc.moveDown(0.6);
  doc.rect(leftMargin + pageWidth * 0.3, doc.y, pageWidth * 0.4, 1).fill(PDF_COLORS.border);
  doc.moveDown(0.6);

  doc.fontSize(18).font('Helvetica-Bold').fillColor(PDF_COLORS.text)
    .text(opts.companyName, { align: 'center' });
  doc.moveDown(0.8);

  if (Array.isArray(opts.meta) && opts.meta.length > 0) {
    const metaCol = pageWidth / 2;
    let metaY = doc.y;
    opts.meta.forEach((pair, i) => {
      const x = leftMargin + (i % 2) * metaCol;
      if (i % 2 === 0 && i > 0) metaY += 13;
      doc.fontSize(9).font('Helvetica-Bold').fillColor(PDF_COLORS.textLight)
        .text(pair[0] + ':', x, metaY);
      doc.font('Helvetica').fillColor(PDF_COLORS.text)
        .text(String(pair[1] ?? ''), x + 90, metaY);
    });
    doc.y = metaY + 18;
  }
}

/**
 * Render a labeled paragraph value inside a thin bordered box. Used for free-text fields.
 */
function renderTextarea(doc, label, value) {
  if (!value) return;
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const leftMargin = doc.page.margins.left;

  ensureSpace(doc, 30);
  doc.fontSize(8.5).font('Helvetica-Bold').fillColor(PDF_COLORS.text)
    .text(label, leftMargin);
  doc.moveDown(0.1);
  const textHeight = doc.heightOfString(String(value), { width: pageWidth - 16, fontSize: 8.5 }) + 10;
  ensureSpace(doc, textHeight + 4);
  const boxY = doc.y;
  doc.rect(leftMargin, boxY, pageWidth, textHeight).lineWidth(0.5).strokeColor(PDF_COLORS.border).stroke();
  doc.fontSize(8.5).font('Helvetica').fillColor(PDF_COLORS.text)
    .text(String(value), leftMargin + 6, boxY + 5, { width: pageWidth - 12 });
  doc.y = boxY + textHeight + 4;
}

/**
 * Hero-style cover page with a colored top block and large title.
 * Renders on the CURRENT page (caller should pass a fresh document).
 */
function renderHeroCover(doc, opts) {
  const pageWidth  = doc.page.width;
  const pageHeight = doc.page.height;
  const left       = doc.page.margins.left;
  const contentW   = pageWidth - left - doc.page.margins.right;

  // ── Top hero block (40% of page height, full-bleed) ──
  const heroH = Math.round(pageHeight * 0.42);
  // base color
  doc.rect(0, 0, pageWidth, heroH).fill(opts.heroColor || PDF_COLORS.headerBg);
  // subtle 2-band gradient effect using a lighter stripe
  doc.rect(0, heroH - 40, pageWidth, 40).fill('#264971');
  doc.rect(0, heroH - 4, pageWidth, 4).fill(opts.accentColor || PDF_COLORS.primary);

  // Watermark badge top-right (e.g. TRAINING)
  if (opts.watermark) {
    const wmText = opts.watermark.toUpperCase();
    doc.fontSize(8).font('Helvetica-Bold');
    const wmW = doc.widthOfString(wmText) + 16;
    const wmX = pageWidth - wmW - 30;
    const wmY = 24;
    doc.roundedRect(wmX, wmY, wmW, 18, 4).fill('#facc15');
    doc.fillColor('#1e1e1e').text(wmText, wmX, wmY + 5, { width: wmW, align: 'center' });
  }

  // Eyebrow label
  doc.fontSize(10).font('Helvetica-Bold').fillColor('#cbd5e1')
    .text((opts.eyebrow || 'CYBERSECURITY ASSESSMENT').toUpperCase(),
      40, 70, { characterSpacing: 4 });

  // Main title
  doc.fontSize(34).font('Helvetica-Bold').fillColor('#ffffff')
    .text(opts.title || 'Risk Assessment Report', 40, 100, { width: pageWidth - 80 });

  // Subtitle / company
  doc.fontSize(20).font('Helvetica').fillColor('#e2e8f0')
    .text(opts.companyName || '', 40, 160, { width: pageWidth - 80 });
  if (opts.subtitle) {
    doc.fontSize(11).font('Helvetica-Oblique').fillColor('#bfdbfe')
      .text(opts.subtitle, 40, 200, { width: pageWidth - 80 });
  }

  // ── Bottom meta block ──
  doc.fillColor(PDF_COLORS.text);
  const metaTop = heroH + 60;
  if (Array.isArray(opts.meta) && opts.meta.length) {
    const col1 = left;
    const col2 = left + contentW / 2;
    let row = 0;
    opts.meta.forEach((pair, i) => {
      const x = (i % 2 === 0) ? col1 : col2;
      const y = metaTop + row * 36;
      doc.fontSize(8).font('Helvetica-Bold').fillColor(PDF_COLORS.textLight)
        .text((pair[0] || '').toUpperCase(), x, y, { characterSpacing: 1.5 });
      doc.fontSize(12).font('Helvetica').fillColor(PDF_COLORS.text)
        .text(String(pair[1] ?? '—'), x, y + 12, { width: contentW / 2 - 10 });
      if (i % 2 === 1) row++;
    });
  }

  // Bottom-of-page brand strip
  doc.rect(0, pageHeight - 26, pageWidth, 26).fill(PDF_COLORS.headerBg);
  doc.fontSize(8).font('Helvetica').fillColor('#cbd5e1')
    .text(opts.footerLeft || 'Clinic-in-a-Box · Cybersecurity Risk Assessment Platform',
      left, pageHeight - 18, { width: contentW / 2 });
  if (opts.footerRight) {
    doc.fillColor('#cbd5e1')
      .text(opts.footerRight, left, pageHeight - 18, { width: contentW, align: 'right' });
  }

  // Done with cover — give caller a fresh page
  doc.addPage();
  doc.fillColor(PDF_COLORS.text);
}

/**
 * KPI tile grid — row of equal-width tiles each showing a label + big value.
 * Used on the executive-summary page.
 *
 *   tiles: [{ label, value, sub?, color? }, ...]
 *   minHeight defaults to 80pt; cols defaults to tiles.length.
 */
function renderKpiTiles(doc, tiles, opts = {}) {
  const pageWidth  = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const left       = doc.page.margins.left;
  const cols       = opts.cols || tiles.length;
  const gap        = opts.gap || 10;
  const height     = opts.height || 84;
  const tileW      = Math.floor((pageWidth - (cols - 1) * gap) / cols);

  ensureSpace(doc, height + 8);
  const top = doc.y;
  tiles.forEach((t, i) => {
    const x = left + i * (tileW + gap);
    // Card
    doc.roundedRect(x, top, tileW, height, 6).lineWidth(0.5).strokeColor(PDF_COLORS.border).stroke();
    // Left accent stripe
    doc.rect(x, top, 4, height).fill(t.color || PDF_COLORS.primary);
    // Label
    doc.fontSize(7.5).font('Helvetica-Bold').fillColor(PDF_COLORS.textLight)
      .text(String(t.label || '').toUpperCase(), x + 14, top + 12,
        { width: tileW - 22, characterSpacing: 1 });
    // Value (big)
    doc.fontSize(24).font('Helvetica-Bold').fillColor(PDF_COLORS.text)
      .text(String(t.value ?? '—'), x + 14, top + 28, { width: tileW - 22 });
    // Sub line
    if (t.sub) {
      doc.fontSize(8).font('Helvetica').fillColor(PDF_COLORS.textLight)
        .text(t.sub, x + 14, top + 60, { width: tileW - 22 });
    }
  });
  doc.y = top + height + 12;
}

/**
 * Severity color for a numeric risk score 0–9 (CIS RAM-style).
 */
function severityColorFor(risk) {
  const r = Number(risk) || 0;
  if (r >= 7) return '#dc2626';     // critical / high — red
  if (r >= 5) return '#ea580c';     // medium-high — orange
  if (r >= 3) return '#d97706';     // medium — amber
  if (r >= 1) return '#0891b2';     // low — cyan
  return PDF_COLORS.textLight;      // unscored
}

function severityLabelFor(risk) {
  const r = Number(risk) || 0;
  if (r >= 7) return 'CRITICAL';
  if (r >= 5) return 'HIGH';
  if (r >= 3) return 'MEDIUM';
  if (r >= 1) return 'LOW';
  return 'UNSCORED';
}

/**
 * Render a pill-style severity badge inline at (x, y).
 */
function renderSeverityBadge(doc, x, y, risk, width = 56) {
  const color = severityColorFor(risk);
  const label = severityLabelFor(risk);
  doc.roundedRect(x, y - 1, width, 13, 3).fill(color);
  doc.fontSize(7).font('Helvetica-Bold').fillColor('#ffffff')
    .text(label, x, y + 2, { width, align: 'center' });
}

/**
 * Render a callout / banner box for archetype, recommendation header, etc.
 */
function renderCallout(doc, opts) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const left = doc.page.margins.left;
  const padding = 10;

  const titleStr = opts.title || '';
  const bodyStr  = opts.body || '';
  const color = opts.color || PDF_COLORS.primary;

  doc.fontSize(8).font('Helvetica-Bold');
  const titleH = titleStr ? 14 : 0;
  doc.fontSize(9).font('Helvetica');
  const bodyH = bodyStr
    ? doc.heightOfString(bodyStr, { width: pageWidth - padding * 2 - 6 }) + 4
    : 0;
  const boxH = padding * 2 + titleH + bodyH;

  ensureSpace(doc, boxH + 6);
  const top = doc.y;
  doc.roundedRect(left, top, pageWidth, boxH, 4).fillOpacity(0.06).fill(color).fillOpacity(1);
  doc.rect(left, top, 4, boxH).fill(color);
  if (titleStr) {
    doc.fontSize(8).font('Helvetica-Bold').fillColor(color)
      .text(titleStr.toUpperCase(), left + padding + 4, top + padding,
        { width: pageWidth - padding * 2, characterSpacing: 1 });
  }
  if (bodyStr) {
    doc.fontSize(9).font('Helvetica').fillColor(PDF_COLORS.text)
      .text(bodyStr, left + padding + 4, top + padding + titleH,
        { width: pageWidth - padding * 2 - 6 });
  }
  doc.y = top + boxH + 8;
}

/**
 * Render section header with a left accent stripe and optional kicker label.
 * Cleaner alternative to the original renderSectionHeader (kept for compat).
 */
function renderSectionHeaderModern(doc, title, kicker) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const left = doc.page.margins.left;
  ensureSpace(doc, 36);
  const top = doc.y;
  // Accent
  doc.rect(left, top + 4, 4, 22).fill(PDF_COLORS.primary);
  if (kicker) {
    doc.fontSize(7).font('Helvetica-Bold').fillColor(PDF_COLORS.primary)
      .text(kicker.toUpperCase(), left + 12, top, { characterSpacing: 2 });
  }
  doc.fontSize(16).font('Helvetica-Bold').fillColor(PDF_COLORS.headerBg)
    .text(title, left + 12, top + 8, { width: pageWidth - 20 });
  doc.y = top + 34;
  // Thin underline
  doc.rect(left, doc.y, pageWidth, 0.5).fill(PDF_COLORS.border);
  doc.y += 8;
}

/**
 * Render a bullet list with hanging-indent.
 */
function renderBulletList(doc, items, opts = {}) {
  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const left = doc.page.margins.left;
  const fontSize = opts.fontSize || 9.5;
  items.forEach(it => {
    ensureSpace(doc, fontSize + 6);
    const top = doc.y;
    doc.fontSize(fontSize).font('Helvetica-Bold').fillColor(opts.bulletColor || PDF_COLORS.primary)
      .text('●', left + 4, top, { width: 10 });
    doc.fontSize(fontSize).font('Helvetica').fillColor(PDF_COLORS.text)
      .text(String(it), left + 18, top, { width: pageWidth - 22 });
    doc.moveDown(0.15);
  });
}

/**
 * Render a footer on every page in the buffered document.
 * Call AFTER all content has been drawn but BEFORE doc.end().
 */
function renderPageFooters(doc, opts = {}) {
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    // Don't draw footer on the cover page (page 0) since the cover has its own.
    if (i === 0 && opts.skipFirstPage !== false) continue;
    const w = doc.page.width;
    const h = doc.page.height;
    const left = doc.page.margins.left;
    const right = w - doc.page.margins.right;
    const y = h - 30;
    // Hairline
    doc.rect(left, y - 4, right - left, 0.5).fill(PDF_COLORS.border);
    doc.fontSize(7.5).font('Helvetica').fillColor(PDF_COLORS.textLight)
      .text(opts.left || 'Clinic-in-a-Box · Risk Assessment Report',
        left, y, { width: (right - left) / 2 });
    doc.fontSize(7.5).font('Helvetica').fillColor(PDF_COLORS.textLight)
      .text(`Page ${i - range.start + 1} of ${range.count}` +
        (opts.right ? `  ·  ${opts.right}` : ''),
        left, y, { width: right - left, align: 'right' });
  }
}

module.exports = {
  PDF_COLORS,
  ensureSpace,
  labelOf,
  renderSectionHeader,
  renderSectionHeaderModern,
  renderChecklist,
  renderYesNo,
  renderScores,
  renderIG1,
  renderCoverPage,
  renderHeroCover,
  renderKpiTiles,
  renderSeverityBadge,
  severityColorFor,
  severityLabelFor,
  renderCallout,
  renderBulletList,
  renderPageFooters,
  renderTextarea,
};
