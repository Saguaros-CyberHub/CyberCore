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

module.exports = {
  PDF_COLORS,
  ensureSpace,
  labelOf,
  renderSectionHeader,
  renderChecklist,
  renderYesNo,
  renderScores,
  renderIG1,
  renderCoverPage,
  renderTextarea,
};
