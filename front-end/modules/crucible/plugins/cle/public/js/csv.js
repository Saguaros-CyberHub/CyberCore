/**
 * ============================================================================
 * CSV / delimited roster parser
 * ============================================================================
 * Written because the existing paste-a-roster parser (public/js/admin/
 * admin-users.js parseRoster) splits on comma-or-tab with no quote handling, so
 * a row like
 *
 *     ada@x.edu,"Lovelace, Ada",Ada
 *
 * silently becomes four cells and the name lands in the wrong column. Canvas,
 * Blackboard and Excel all quote by default, so that is not an edge case — it
 * is the normal export.
 *
 * RFC 4180 with the pragmatic extensions every real-world file needs: a UTF-8
 * BOM (Excel always writes one), CRLF, blank lines mid-file, a trailing
 * delimiter, and tab/semicolon delimiters.
 *
 * Dual-mode: loaded as a <script> in the browser and require()'d by
 * test/csv-parser.test.js under plain node. That one line at the bottom is why
 * this lives in its own file rather than inline in courses.html.
 */

(function (root) {
  'use strict';

  const DELIMITERS = [',', '\t', ';'];

  /**
   * Guess the delimiter from the first line.
   *
   * Counts only characters OUTSIDE quotes — a header of
   * `"Last, First",Email` has more commas inside the quoted cell than
   * structural ones, and naive counting picks the wrong separator.
   */
  function detectDelimiter(text) {
    const firstLine = String(text).split(/\r?\n/, 1)[0] || '';
    let best = ',';
    let bestCount = 0;

    for (const delim of DELIMITERS) {
      let count = 0;
      let inQuotes = false;
      for (let i = 0; i < firstLine.length; i++) {
        const ch = firstLine[i];
        if (ch === '"') {
          if (inQuotes && firstLine[i + 1] === '"') { i++; continue; }
          inQuotes = !inQuotes;
        } else if (ch === delim && !inQuotes) {
          count++;
        }
      }
      if (count > bestCount) { best = delim; bestCount = count; }
    }
    return best;
  }

  /**
   * Parse delimited text into a matrix of rows of cells.
   *
   * @param {string} text
   * @param {string} [delimiter] auto-detected when omitted
   * @returns {string[][]}
   */
  function parseDelimited(text, delimiter) {
    let input = String(text == null ? '' : text);

    // Excel writes a UTF-8 BOM. Left in place it becomes part of the first
    // header cell, so "email" stops matching and column mapping falls back to
    // positional — which is exactly the kind of failure nobody notices.
    if (input.charCodeAt(0) === 0xfeff) input = input.slice(1);

    const delim = delimiter || detectDelimiter(input);
    const rows = [];
    let row = [];
    let field = '';
    let inQuotes = false;
    let fieldWasQuoted = false;

    const endField = () => {
      row.push(fieldWasQuoted ? field : field.trim());
      field = '';
      fieldWasQuoted = false;
    };
    const endRow = () => {
      endField();
      // A trailing newline would otherwise produce a spurious [''] row.
      if (!(row.length === 1 && row[0] === '')) rows.push(row);
      row = [];
    };

    for (let i = 0; i < input.length; i++) {
      const ch = input[i];

      if (inQuotes) {
        if (ch === '"') {
          if (input[i + 1] === '"') { field += '"'; i++; }   // "" escape
          else inQuotes = false;
        } else {
          field += ch;                                       // includes newlines
        }
        continue;
      }

      if (ch === '"' && field.trim() === '') {
        // Only opens a quoted field at the start of one; a stray quote mid-cell
        // is literal (O'Brien "Bob" Smith).
        inQuotes = true;
        fieldWasQuoted = true;
        field = '';
      } else if (ch === delim) {
        endField();
      } else if (ch === '\r') {
        if (input[i + 1] === '\n') i++;
        endRow();
      } else if (ch === '\n') {
        endRow();
      } else {
        field += ch;
      }
    }

    // Flush whatever the last line left behind (no trailing newline).
    if (field !== '' || row.length > 0) endRow();

    // Drop entirely blank lines — common mid-file and at the end.
    return rows.filter(r => r.some(cell => cell !== ''));
  }

  // Header spellings seen in the wild from Canvas, Blackboard, and hand-rolled
  // spreadsheets.
  const EMAIL_HEADERS = /^(e-?mail|e-?mail\s*address|login\s*id|sis\s*login\s*id)$/i;
  const FIRST_HEADERS = /^(first|first\s*name|given\s*name|forename)$/i;
  const LAST_HEADERS = /^(last|last\s*name|surname|family\s*name)$/i;
  // A single combined name column. Deliberately NOT parsed into first/last —
  // see toRosterRows.
  const FULL_NAME_HEADERS = /^(name|full\s*name|student|student\s*name)$/i;

  function findHeader(cells, pattern) {
    return cells.findIndex(c => pattern.test(String(c).trim()));
  }

  /**
   * Map a parsed matrix to roster records.
   *
   * When a header row is present, columns are mapped BY NAME — Canvas puts the
   * email in column 3, not column 1, so positional mapping on a Canvas export
   * would import a roster of names as email addresses. Falls back to positional
   * email,first,last only when there is no recognizable header.
   *
   * @returns {{rows: Array<{line:number,email:string,first_name:?string,last_name:?string}>,
   *            problems: Array<{line:number,message:string}>,
   *            hasHeader: boolean}}
   */
  function toRosterRows(matrix) {
    const problems = [];
    const out = [];

    if (!matrix || matrix.length === 0) {
      return { rows: out, problems: [{ line: 0, message: 'The file is empty.' }], hasHeader: false };
    }

    const header = matrix[0];
    const emailCol = findHeader(header, EMAIL_HEADERS);
    const hasHeader = emailCol >= 0;

    let idx;
    if (hasHeader) {
      idx = {
        email: emailCol,
        first: findHeader(header, FIRST_HEADERS),
        last: findHeader(header, LAST_HEADERS),
        full: findHeader(header, FULL_NAME_HEADERS),
      };
    } else {
      idx = { email: 0, first: 1, last: 2, full: -1 };
    }

    // A combined name column is reported, never guessed at. "Lovelace, Ada" and
    // "Ada Lovelace" are both common and a splitter cannot tell them apart, so
    // silently guessing would put surnames in the first-name field for a whole
    // class — visible to every one of those students in the greeting of their
    // invitation email.
    if (hasHeader && idx.first < 0 && idx.last < 0 && idx.full >= 0) {
      problems.push({
        line: 1,
        message: 'This file has a single "name" column. Split it into first and last name columns, or the roster will be imported without names.',
      });
    }

    const startRow = hasHeader ? 1 : 0;
    for (let r = startRow; r < matrix.length; r++) {
      const cells = matrix[r];
      // Line numbers are 1-based and count the header, so they match what the
      // instructor sees in their spreadsheet.
      const line = r + 1;

      const email = String(cells[idx.email] ?? '').trim();
      if (!email) {
        problems.push({ line, message: 'No email address in this row.' });
        continue;
      }

      out.push({
        line,
        email,
        first_name: idx.first >= 0 ? (String(cells[idx.first] ?? '').trim() || null) : null,
        last_name: idx.last >= 0 ? (String(cells[idx.last] ?? '').trim() || null) : null,
      });
    }

    return { rows: out, problems, hasHeader };
  }

  /** Parse raw text straight to roster records. */
  function parseRoster(text) {
    return toRosterRows(parseDelimited(text));
  }

  const api = { parseDelimited, detectDelimiter, toRosterRows, parseRoster };

  // Browser
  if (root) root.CleCsv = api;
  // Node, for the tests
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : null);
