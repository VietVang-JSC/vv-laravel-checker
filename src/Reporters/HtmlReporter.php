<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Reporters;

use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;

final class HtmlReporter implements ReporterInterface
{
    private const CSS = <<<'CSS'
    :root {
        --critical: #b91c1c;
        --error: #dc2626;
        --warning: #d97706;
        --info: #2563eb;
        --pass: #16a34a;
        --border: #e5e7eb;
        --bg: #ffffff;
        --page: #f9fafb;
        --text: #111827;
        --muted: #6b7280;
        --hover: #f3f4f6;
        --code-bg: #0f172a;
        --code-text: #e2e8f0;
        --code-ln: #64748b;
        --code-cur: rgba(220, 38, 38, 0.18);
        color-scheme: light;
    }
    html[data-theme="dark"] {
        --border: #1f2937;
        --bg: #111827;
        --page: #0b1220;
        --text: #e5e7eb;
        --muted: #9ca3af;
        --hover: #1f2937;
        --critical: #f87171;
        --error: #f87171;
        --warning: #fbbf24;
        --info: #60a5fa;
        --pass: #4ade80;
        color-scheme: dark;
    }
    * { box-sizing: border-box; }
    body {
        margin: 0;
        padding: 24px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: var(--text);
        background: var(--page);
        line-height: 1.5;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 12px;
        padding: 20px 24px;
        background: var(--bg);
        border: 1px solid var(--border);
        border-radius: 8px;
        margin-bottom: 24px;
    }
    h1 { margin: 0; font-size: 22px; }
    .meta { color: var(--muted); font-size: 13px; }
    .meta span { margin-right: 16px; }
    .badge {
        display: inline-block;
        padding: 6px 14px;
        border-radius: 9999px;
        color: #fff;
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .badge.passed { background: var(--pass); }
    .badge.warning { background: var(--warning); }
    .badge.failed { background: var(--error); }
    h2 { font-size: 18px; margin: 0 0 12px; }
    h3 { font-size: 13px; margin: 0 0 8px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
    .card {
        background: var(--bg);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 20px 24px;
        margin-bottom: 24px;
    }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); }
    th { background: var(--hover); font-weight: 600; }
    th[data-sortable] { cursor: pointer; user-select: none; white-space: nowrap; }
    th[data-sortable]:hover { color: var(--info); }
    th.sort-asc::after { content: " \25B2"; font-size: 10px; }
    th.sort-desc::after { content: " \25BC"; font-size: 10px; }
    .status { font-weight: 600; }
    .status.passed { color: var(--pass); }
    .status.warning { color: var(--warning); }
    .status.failed { color: var(--error); }
    .status.skipped, .status.error { color: var(--muted); }
    .severity { font-weight: 600; }
    .severity.critical { color: var(--critical); }
    .severity.error { color: var(--error); }
    .severity.warning { color: var(--warning); }
    .severity.info { color: var(--info); }
    .rule { font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; }
    .file { font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; color: var(--muted); }
    .summary-grid { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 8px; }
    .stat {
        flex: 1 1 120px;
        padding: 14px;
        border: 1px solid var(--border);
        border-radius: 8px;
        text-align: center;
        background: var(--page);
    }
    .stat .value { font-size: 26px; font-weight: 700; }
    .stat .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
    .charts { display: flex; flex-wrap: wrap; gap: 24px; margin-top: 16px; }
    .chart-block { flex: 1 1 320px; min-width: 0; }
    .stacked {
        display: flex;
        height: 18px;
        border-radius: 9999px;
        overflow: hidden;
        background: var(--page);
        border: 1px solid var(--border);
    }
    .stacked .seg { min-width: 2px; }
    .stacked .seg.critical { background: var(--critical); }
    .stacked .seg.error { background: var(--error); }
    .stacked .seg.warning { background: var(--warning); }
    .stacked .seg.info { background: var(--info); }
    .legend { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 8px; font-size: 12px; color: var(--muted); }
    .legend .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }
    .legend .dot.critical { background: var(--critical); }
    .legend .dot.error { background: var(--error); }
    .legend .dot.warning { background: var(--warning); }
    .legend .dot.info { background: var(--info); }
    .bars { display: flex; flex-direction: column; gap: 6px; }
    .bar-row { display: grid; grid-template-columns: minmax(120px, 220px) 1fr 48px; gap: 8px; align-items: center; font-size: 12px; }
    .bar-row .bar-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); }
    .bar-row .bar-track { background: var(--page); border: 1px solid var(--border); border-radius: 9999px; height: 12px; overflow: hidden; }
    .bar-row .bar-fill { height: 100%; background: linear-gradient(90deg, #6366f1, #8b5cf6); border-radius: 9999px; }
    .bar-row .bar-val { text-align: right; font-weight: 600; }
    .checker-section { margin-bottom: 32px; }
    .checker-head { margin-bottom: 12px; }
    .issue-group { border: 1px solid var(--border); border-radius: 8px; margin-bottom: 8px; background: var(--bg); overflow: hidden; }
    .issue-group > summary {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px 14px;
        cursor: pointer;
        list-style: none;
        font-size: 13px;
        background: var(--page);
    }
    .issue-group > summary::-webkit-details-marker { display: none; }
    .issue-group > summary:hover { background: var(--hover); }
    .issue-group[open] > summary { border-bottom: 1px solid var(--border); }
    .chev { display: inline-block; transition: transform 0.15s; color: var(--muted); font-size: 11px; }
    .issue-group[open] .chev { transform: rotate(90deg); }
    .issue-group .file-link {
        font-family: "SFMono-Regular", Consolas, monospace;
        font-size: 12px;
        color: var(--info);
        text-decoration: none;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        min-width: 0;
        flex: 1 1 auto;
    }
    .issue-group .file-link:hover { text-decoration: underline; }
    .pill {
        display: inline-block;
        padding: 1px 8px;
        border-radius: 9999px;
        font-size: 11px;
        font-weight: 600;
        background: var(--hover);
        color: var(--muted);
        border: 1px solid var(--border);
    }
    .pill.critical { background: color-mix(in srgb, var(--critical) 15%, transparent); color: var(--critical); }
    .pill.error { background: color-mix(in srgb, var(--error) 15%, transparent); color: var(--error); }
    .pill.warning { background: color-mix(in srgb, var(--warning) 15%, transparent); color: var(--warning); }
    .pill.info { background: color-mix(in srgb, var(--info) 15%, transparent); color: var(--info); }
    .issue-group table { margin: 0; }
    .issue-group tbody tr[data-search]:hover { background: var(--hover); }
    .skipped-hint { color: var(--muted); font-style: italic; }
    .empty { color: var(--muted); }
    .layout { display: flex; gap: 24px; align-items: flex-start; }
    .sidebar {
        position: sticky;
        top: 24px;
        flex: 0 0 240px;
        max-height: calc(100vh - 48px);
        overflow-y: auto;
        background: var(--bg);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 16px;
        font-size: 13px;
    }
    .sidebar h3 { margin: 0 0 8px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
    .sidebar nav ul { list-style: none; margin: 0 0 16px; padding: 0; }
    .sidebar nav li { margin: 0; padding: 0; }
    .sidebar nav a {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
        padding: 6px 8px;
        border-radius: 6px;
        color: var(--text);
        text-decoration: none;
    }
    .sidebar nav a:hover { background: var(--hover); }
    .sidebar nav a.active { background: #e0e7ff; color: #1e40af; font-weight: 600; }
    html[data-theme="dark"] .sidebar nav a.active { background: #1e3a8a; color: #c7d2fe; }
    .sidebar .count {
        background: var(--hover);
        border-radius: 9999px;
        padding: 0 8px;
        font-size: 11px;
        color: var(--muted);
    }
    .sidebar a.active .count { background: #c7d2fe; color: #1e40af; }
    .sidebar a.on { background: var(--hover); }
    .sidebar a.on.dimmed { background: transparent; }
    .sidebar a.dimmed { opacity: 0.45; }
    .sidebar .sev-dot { width: 8px; height: 8px; border-radius: 50%; flex: 0 0 8px; }
    .sidebar .sev-dot.critical { background: var(--critical); }
    .sidebar .sev-dot.error { background: var(--error); }
    .sidebar .sev-dot.warning { background: var(--warning); }
    .sidebar .sev-dot.info { background: var(--info); }
    .sidebar .count-critical { background: #fee2e2; color: var(--critical); }
    .sidebar .count-error { background: #fee2e2; color: var(--error); }
    .sidebar .count-warning { background: #fef3c7; color: var(--warning); }
    .sidebar .count-info { background: #dbeafe; color: var(--info); }
    html[data-theme="dark"] .sidebar .count-critical,
    html[data-theme="dark"] .sidebar .count-error { background: #451a1a; }
    html[data-theme="dark"] .sidebar .count-warning { background: #451a0a; }
    html[data-theme="dark"] .sidebar .count-info { background: #172554; }
    .sidebar .rule-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
    .sidebar .sub {
        list-style: none;
        margin: 2px 0 6px;
        padding: 0 0 0 12px;
        border-left: 1px solid var(--border);
        margin-left: 10px;
    }
    .sidebar .sub a { padding: 3px 8px; font-size: 12px; color: var(--muted); }
    .sidebar .sub a:hover { color: var(--text); }
    .sidebar .sub a.on { color: var(--text); font-weight: 600; }
    .issue-group .rule-name {
        font-family: "SFMono-Regular", Consolas, monospace;
        font-size: 13px;
        font-weight: 600;
        flex: 1 1 auto;
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .issue-group td a.file-link { display: block; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sidebar nav a[data-side-rule], .sidebar nav a[data-side-file], .sidebar nav a[data-side-sev] { cursor: pointer; }
    .main { flex: 1 1 auto; min-width: 0; }
    .main .container { max-width: none; margin: 0; }
    .toolbar {
        position: sticky;
        top: 0;
        z-index: 10;
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
        background: var(--page);
        padding: 12px 0;
        margin-bottom: 8px;
    }
    .toolbar input[type="search"] {
        flex: 1 1 220px;
        padding: 8px 12px;
        border: 1px solid var(--border);
        border-radius: 8px;
        font-size: 14px;
        background: var(--bg);
        color: var(--text);
    }
    .chip {
        border: 1px solid var(--border);
        background: var(--bg);
        color: var(--text);
        border-radius: 9999px;
        padding: 4px 12px;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
    }
    .chip:hover { background: var(--hover); }
    .chip[aria-pressed="true"] { background: #111827; color: #fff; border-color: #111827; }
    .chip[data-sev="critical"][aria-pressed="true"] { background: var(--critical); border-color: var(--critical); }
    .chip[data-sev="error"][aria-pressed="true"] { background: var(--error); border-color: var(--error); }
    .chip[data-sev="warning"][aria-pressed="true"] { background: var(--warning); border-color: var(--warning); }
    .chip[data-sev="info"][aria-pressed="true"] { background: var(--info); border-color: var(--info); }
    .match-count { font-size: 12px; color: var(--muted); }
    .toolbar .spacer { flex: 1 1 auto; }
    tr[hidden], .issue-group[hidden], .checker-section[hidden], .snippet-row[hidden] { display: none; }
    .no-match { padding: 16px; text-align: center; }
    .snip-btn {
        border: 1px solid var(--border);
        background: var(--bg);
        color: var(--muted);
        border-radius: 6px;
        font-size: 11px;
        padding: 1px 6px;
        margin-left: 8px;
        cursor: pointer;
        font-family: monospace;
    }
    .snip-btn:hover { color: var(--info); border-color: var(--info); }
    .snippet-row > td { padding: 0 12px 10px; background: var(--page); }
    pre.code {
        margin: 8px 0 0;
        padding: 10px 12px;
        background: var(--code-bg);
        color: var(--code-text);
        border-radius: 6px;
        overflow-x: auto;
        font-family: "SFMono-Regular", Consolas, monospace;
        font-size: 12px;
        line-height: 1.55;
    }
    pre.code .row { display: block; white-space: pre; }
    pre.code .row.cur { background: var(--code-cur); border-radius: 4px; }
    pre.code .cl { color: var(--code-ln); user-select: none; display: inline-block; min-width: 4ch; text-align: right; margin-right: 12px; }
    .owasp-rule { border: 1px solid var(--border); border-radius: 8px; margin-bottom: 8px; background: var(--bg); }
    .owasp-rule > summary {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px 14px;
        cursor: pointer;
        list-style: none;
        font-size: 13px;
        font-weight: 600;
    }
    .owasp-rule > summary::-webkit-details-marker { display: none; }
    .owasp-rule > summary:hover { background: var(--hover); }
    .owasp-rule ul { margin: 0; padding: 0 14px 12px 36px; font-size: 13px; }
    .owasp-rule li { margin: 4px 0; }
    .owasp-rule a { color: var(--info); text-decoration: none; font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; }
    .owasp-rule a:hover { text-decoration: underline; }
    .linkish { background: none; border: none; color: var(--info); cursor: pointer; font-size: 12px; padding: 0; text-decoration: underline; }
    html { scroll-behavior: smooth; }
    section[id], div[id], details[id] { scroll-margin-top: 70px; }
    @media (max-width: 860px) {
        .layout { flex-direction: column; }
        .sidebar { position: static; flex: none; width: 100%; max-height: none; }
    }
    @media print {
        .sidebar, .toolbar, .snip-btn, .chev { display: none !important; }
        body { background: #fff; padding: 0; color: #000; }
        .layout { display: block; }
        .card, .issue-group, header { border-color: #ccc; box-shadow: none; }
        details.issue-group > *, details.owasp-rule > * { display: block !important; }
        details.issue-group { break-inside: avoid; }
        .snippet-row { display: table-row !important; }
        a { color: inherit; }
        pre.code { background: #f1f5f9; color: #0f172a; border: 1px solid #cbd5e1; }
        pre.code .cl { color: #64748b; }
        pre.code .row.cur { background: #fee2e2; }
    }
    CSS;

    private const JS = <<<'JS'
    (function () {
        var search = document.getElementById('report-search');
        var matchCount = document.getElementById('match-count');
        var chips = Array.prototype.slice.call(document.querySelectorAll('.chip[data-sev]'));
        var rows = Array.prototype.slice.call(document.querySelectorAll('tr[data-search]'));
        var activeSevs = { critical: true, error: true, warning: true, info: true };

        function applyFilters() {
            var q = search ? search.value.trim().toLowerCase() : '';
            var visible = 0;
            rows.forEach(function (row) {
                var sevOk = !!activeSevs[row.getAttribute('data-severity')];
                var textOk = q === '' || row.getAttribute('data-search').indexOf(q) !== -1;
                var show = sevOk && textOk;
                row.hidden = !show;
                var snip = row.nextElementSibling;
                if (snip && snip.classList.contains('snippet-row') && !show) {
                    snip.hidden = true;
                }
                if (show) {
                    visible++;
                }
            });
            document.querySelectorAll('.issue-group').forEach(function (group) {
                var anyVisible = Array.prototype.some.call(
                    group.querySelectorAll('tr[data-search]'),
                    function (r) { return !r.hidden; }
                );
                group.hidden = !anyVisible;
                if (q !== '' && anyVisible) {
                    group.open = true;
                }
            });
            document.querySelectorAll('.checker-section').forEach(function (section) {
                var groups = section.querySelectorAll('.issue-group');
                if (groups.length === 0) {
                    return;
                }
                var anyVisible = Array.prototype.some.call(groups, function (g) { return !g.hidden; });
                section.hidden = !anyVisible;
                var note = section.querySelector('.no-match');
                if (note) {
                    note.hidden = anyVisible;
                }
            });
            if (matchCount) {
                matchCount.textContent = visible + ' / ' + rows.length + ' issues';
            }
        }

        if (search) {
            search.addEventListener('input', applyFilters);
        }
        function syncSidebarSev() {
            document.querySelectorAll('[data-side-sev]').forEach(function (a) {
                var sev = a.getAttribute('data-side-sev');
                a.classList.toggle('on', !!activeSevs[sev]);
                a.classList.toggle('dimmed', !activeSevs[sev]);
            });
        }
        function toggleSev(sev) {
            activeSevs[sev] = !activeSevs[sev];
            chips.forEach(function (chip) {
                if (chip.getAttribute('data-sev') === sev) {
                    chip.setAttribute('aria-pressed', activeSevs[sev] ? 'true' : 'false');
                }
            });
            syncSidebarSev();
            applyFilters();
        }
        chips.forEach(function (chip) {
            chip.addEventListener('click', function () {
                toggleSev(chip.getAttribute('data-sev'));
            });
        });
        document.querySelectorAll('[data-side-sev]').forEach(function (a) {
            a.addEventListener('click', function (e) {
                e.preventDefault();
                toggleSev(a.getAttribute('data-side-sev'));
            });
        });
        function filterByText(token) {
            if (!search) {
                return;
            }
            search.value = token;
            chips.forEach(function (chip) {
                activeSevs[chip.getAttribute('data-sev')] = true;
                chip.setAttribute('aria-pressed', 'true');
            });
            syncSidebarSev();
            applyFilters();
            var target = document.getElementById('checker-custom') || document.getElementById('top-rules');
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }
        document.querySelectorAll('[data-side-rule]').forEach(function (a) {
            a.addEventListener('click', function (e) {
                e.preventDefault();
                filterByText(a.getAttribute('data-side-rule'));
            });
        });
        document.querySelectorAll('[data-side-file]').forEach(function (a) {
            a.addEventListener('click', function (e) {
                e.preventDefault();
                filterByText(a.getAttribute('data-side-file'));
            });
        });
        document.querySelectorAll('.js-filter').forEach(function (b) {
            b.addEventListener('click', function () {
                filterByText(b.getAttribute('data-q') || '');
            });
        });
        syncSidebarSev();

        /* Expand / collapse all file groups. */
        var expandBtn = document.getElementById('expand-all');
        var collapseBtn = document.getElementById('collapse-all');
        if (expandBtn) {
            expandBtn.addEventListener('click', function () {
                document.querySelectorAll('details.issue-group, details.owasp-rule').forEach(function (d) { d.open = true; });
            });
        }
        if (collapseBtn) {
            collapseBtn.addEventListener('click', function () {
                document.querySelectorAll('details.issue-group, details.owasp-rule').forEach(function (d) { d.open = false; });
            });
        }

        /* Per-issue code snippet toggles. */
        document.querySelectorAll('.snip-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var row = document.getElementById(btn.getAttribute('data-for') || '');
                var snip = row && row.nextElementSibling;
                if (snip && snip.classList.contains('snippet-row')) {
                    snip.hidden = !snip.hidden;
                    btn.setAttribute('aria-expanded', snip.hidden ? 'false' : 'true');
                }
            });
        });

        /* Sortable tables. */
        var sevRank = { critical: 4, error: 3, warning: 2, info: 1 };
        function cellVal(row, idx, type) {
            var td = row.children[idx];
            if (!td) {
                return type === 'num' ? 0 : '';
            }
            var t = (td.getAttribute('data-sort-value') || td.textContent || '').trim();
            if (type === 'num') {
                var n = parseFloat(t);
                return isNaN(n) ? 0 : n;
            }
            if (type === 'sev') {
                return sevRank[t.toLowerCase()] || 0;
            }
            return t.toLowerCase();
        }
        function sortTable(th) {
            var table = th.closest('table');
            var tbody = table && table.querySelector('tbody');
            if (!tbody) {
                return;
            }
            var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
            var type = th.getAttribute('data-type') || 'str';
            var dir = th.getAttribute('data-dir') === 'asc' ? 'desc' : 'asc';
            table.querySelectorAll('th[data-sortable]').forEach(function (h) {
                h.removeAttribute('data-dir');
                h.classList.remove('sort-asc', 'sort-desc');
            });
            th.setAttribute('data-dir', dir);
            th.classList.add(dir === 'asc' ? 'sort-asc' : 'sort-desc');
            var all = Array.prototype.slice.call(tbody.rows);
            var issues = all.filter(function (r) { return r.hasAttribute('data-search'); });
            var plain = issues.length > 0 ? issues : all;
            var snipMap = {};
            if (issues.length > 0) {
                issues.forEach(function (r) {
                    var n = r.nextElementSibling;
                    if (n && n.classList.contains('snippet-row')) {
                        snipMap[r.id] = n;
                    }
                });
            }
            plain.sort(function (a, b) {
                var av = cellVal(a, idx, type);
                var bv = cellVal(b, idx, type);
                if (av < bv) { return dir === 'asc' ? -1 : 1; }
                if (av > bv) { return dir === 'asc' ? 1 : -1; }
                return 0;
            });
            if (issues.length > 0) {
                plain.forEach(function (r) {
                    tbody.appendChild(r);
                    if (snipMap[r.id]) {
                        tbody.appendChild(snipMap[r.id]);
                    }
                });
            } else {
                plain.forEach(function (r) { tbody.appendChild(r); });
            }
        }
        document.querySelectorAll('th[data-sortable]').forEach(function (th) {
            th.setAttribute('tabindex', '0');
            th.addEventListener('click', function () { sortTable(th); });
            th.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    sortTable(th);
                }
            });
        });

        /* Theme toggle. */
        var themeBtn = document.getElementById('theme-toggle');
        function applyTheme(theme) {
            if (theme === 'dark') {
                document.documentElement.setAttribute('data-theme', 'dark');
            } else {
                document.documentElement.removeAttribute('data-theme');
            }
            try { localStorage.setItem('qc-theme', theme); } catch (e) { /* ignore */ }
        }
        if (themeBtn) {
            themeBtn.addEventListener('click', function () {
                var isDark = document.documentElement.getAttribute('data-theme') === 'dark';
                applyTheme(isDark ? 'light' : 'dark');
            });
        }

        /* Scroll-spy sidebar TOC (navigation links only). */
        var links = Array.prototype.slice.call(
            document.querySelectorAll('.sidebar nav a[href^="#"]:not([data-side-sev]):not([data-side-rule]):not([data-side-file])')
        );

        /* Jumping to a checker section must reveal its issues: reset filters
           (the section may be hidden) and expand all file groups. */
        function revealSection(id) {
            var el = document.getElementById(id);
            if (!el) {
                return;
            }
            if (search) {
                search.value = '';
            }
            chips.forEach(function (chip) {
                activeSevs[chip.getAttribute('data-sev')] = true;
                chip.setAttribute('aria-pressed', 'true');
            });
            syncSidebarSev();
            applyFilters();
            if (el.classList.contains('checker-section')) {
                el.querySelectorAll('details.issue-group').forEach(function (d) { d.open = true; });
            }
            el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        document.querySelectorAll('.sidebar nav a[href^="#checker-"]').forEach(function (a) {
            a.addEventListener('click', function (e) {
                e.preventDefault();
                revealSection(a.getAttribute('href').slice(1));
            });
        });
        window.addEventListener('hashchange', function () {
            if (location.hash.length > 1) {
                revealSection(location.hash.slice(1));
            }
        });
        if (location.hash && location.hash.length > 1) {
            revealSection(location.hash.slice(1));
        }
        if ('IntersectionObserver' in window && links.length > 0) {
            var byId = {};
            links.forEach(function (a) {
                byId[a.getAttribute('href').slice(1)] = a;
            });
            var observer = new IntersectionObserver(function (entries) {
                entries.forEach(function (entry) {
                    if (entry.isIntersecting && byId[entry.target.id]) {
                        links.forEach(function (a) { a.classList.remove('active'); });
                        byId[entry.target.id].classList.add('active');
                    }
                });
            }, { rootMargin: '-30% 0px -60% 0px' });
            Object.keys(byId).forEach(function (id) {
                var el = document.getElementById(id);
                if (el) {
                    observer.observe(el);
                }
            });
        }
        applyFilters();
    })();
    JS;

    /** @var array<string, list<string>|null> */
    private array $lineCache = [];

    /**
     * @param CheckResult[] $results
     */
    public function render(array $results, CheckContext $ctx): void
    {
        $html = $this->buildDocument($results, $ctx);

        $outputDir = $ctx->outputDir;
        if (!is_dir($outputDir) && !@mkdir($outputDir, 0777, true) && !is_dir($outputDir)) {
            return;
        }

        file_put_contents($outputDir . DIRECTORY_SEPARATOR . 'quality-report.html', $html);
    }

    /**
     * @param CheckResult[] $results
     */
    private function buildDocument(array $results, CheckContext $ctx): string
    {
        $checkers = $this->buildCheckers($results);
        $summary = $this->buildSummary($results);
        $rules = IssueGrouper::byRule($results);
        $hotFiles = $this->hotFiles($results);
        $owasp = IssueGrouper::owaspByRule($results);
        $owaspIssues = $this->owaspIssues($results);

        return '<!DOCTYPE html>' . "\n"
            . '<html lang="en">' . "\n"
            . $this->buildHead()
            . '<body>' . "\n"
            . '<div class="layout">' . "\n"
            . $this->buildSidebar($checkers, $summary, $rules, $hotFiles)
            . '<div class="main"><div class="container">' . "\n"
            . $this->buildHeader($ctx, $this->overallStatus($results))
            . $this->buildToolbar()
            . $this->buildSummaryGrid($summary, $rules)
            . $this->buildRulesTable($rules)
            . $this->buildOwaspSection($owasp, $owaspIssues, $ctx)
            . $this->buildCheckerTable($checkers)
            . $this->buildIssueSections($checkers, $ctx)
            . '</div></div>' . "\n"
            . '</div>' . "\n"
            . '<script>' . "\n"
            . self::JS . "\n"
            . '</script>' . "\n"
            . '</body>' . "\n"
            . '</html>' . "\n";
    }

    private function buildHead(): string
    {
        $bootstrap = "try{var t=localStorage.getItem('qc-theme');"
            . "if(t==='dark'||(!t&&window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').matches))"
            . "document.documentElement.setAttribute('data-theme','dark')}catch(e){}";

        return '<head>' . "\n"
            . '<meta charset="utf-8">' . "\n"
            . '<meta name="viewport" content="width=device-width, initial-scale=1">' . "\n"
            . '<title>Laravel Quality Report</title>' . "\n"
            . '<script>' . $bootstrap . '</script>' . "\n"
            . '<style>' . "\n"
            . self::CSS . "\n"
            . '</style>' . "\n"
            . '</head>' . "\n";
    }

    private function buildHeader(CheckContext $ctx, string $status): string
    {
        return '<header>' . "\n"
            . '<div>' . "\n"
            . '<h1>Laravel Quality Report</h1>' . "\n"
            . '<div class="meta">' . "\n"
            . '<span>Generated: ' . $this->escape((new \DateTimeImmutable())->format('Y-m-d\TH:i:sP')) . '</span>' . "\n"
            . '<span>Package: v' . $this->escape($ctx->packageVersion) . '</span>' . "\n"
            . '<span>Tier: ' . $this->escape($ctx->tier) . '</span>' . "\n"
            . '<span>Exit code: ' . $this->escape((string) $ctx->exitCode) . '</span>' . "\n"
            . '<span>Output: ' . $this->escape($ctx->outputDir) . '</span>' . "\n"
            . '</div>' . "\n"
            . '</div>' . "\n"
            . '<span class="badge ' . $this->escape($status) . '">' . $this->escape($status) . '</span>' . "\n"
            . '</header>' . "\n";
    }

    /**
     * Dashboard-style sticky sidebar: section TOC + interactive severity
     * filters, top rules and hot files (click = prefill search + jump).
     *
     * @param array<int, array{name: string, status: string, duration: float, summary: string|null, counts: array{critical: int, error: int, warning: int, info: int}, rules: list<array{rule: string, count: int}>}> $checkers
     * @param array<string, int> $summary
     * @param list<array{rule: string, source: string, count: int, critical: int, error: int, warning: int, info: int}> $rules
     * @param list<array{file: string, count: int}> $hotFiles
     */
    private function buildSidebar(array $checkers, array $summary, array $rules, array $hotFiles): string
    {
        $html = '<aside class="sidebar" id="sidebar">' . "\n"
            . '<h3>Contents / Mục lục</h3>' . "\n"
            . '<nav aria-label="Report sections"><ul>' . "\n"
            . '<li><a href="#summary">Summary</a></li>' . "\n"
            . '<li><a href="#top-rules">Top Rules</a></li>' . "\n"
            . '<li><a href="#owasp">OWASP</a></li>' . "\n"
            . '<li><a href="#checkers">Per-Checker</a></li>' . "\n"
            . '</ul></nav>' . "\n";

        $html .= '<h3>Severity</h3>' . "\n"
            . '<nav aria-label="Severity filters"><ul>' . "\n";
        foreach (['critical', 'error', 'warning', 'info'] as $sev) {
            $count = (int) ($summary[$sev] ?? 0);
            $html .= '<li><a href="#checker-custom" data-side-sev="' . $sev . '" class="on" role="button">'
                . '<span class="sev-dot ' . $sev . '"></span><span>' . $this->escape(ucfirst($sev)) . '</span>'
                . '<span class="count count-' . $sev . '">' . (string) $count . '</span>'
                . '</a></li>' . "\n";
        }
        $html .= '</ul></nav>' . "\n";

        if (count($rules) > 0) {
            $html .= '<h3>Top Rules</h3>' . "\n"
                . '<nav aria-label="Top rules"><ul>' . "\n";
            foreach (array_slice($rules, 0, 12) as $r) {
                $html .= '<li><a href="#checker-custom" data-side-rule="'
                    . $this->escape(strtolower($r['rule'])) . '" role="button" title="Filter: '
                    . $this->escape($r['rule']) . '">'
                    . '<span class="rule-label">' . $this->escape($r['rule']) . '</span>'
                    . '<span class="count">' . (string) $r['count'] . '</span>'
                    . '</a></li>' . "\n";
            }
            $html .= '</ul></nav>' . "\n";
        }

        if (count($hotFiles) > 0) {
            $html .= '<h3>Hot Files</h3>' . "\n"
                . '<nav aria-label="Files with most issues"><ul>' . "\n";
            foreach ($hotFiles as $hot) {
                $html .= '<li><a href="#checker-custom" data-side-file="'
                    . $this->escape(strtolower($hot['file'])) . '" role="button" title="'
                    . $this->escape($hot['file']) . '">'
                    . '<span class="rule-label">' . $this->escape($this->shortPath($hot['file'])) . '</span>'
                    . '<span class="count">' . (string) $hot['count'] . '</span>'
                    . '</a></li>' . "\n";
            }
            $html .= '</ul></nav>' . "\n";
        }

        $html .= '<h3>Issues by checker</h3>' . "\n"
            . '<nav aria-label="Issues by checker"><ul>' . "\n";

        foreach ($checkers as $result) {
            $slug = $this->slug($result['name']);
            $total = $result['counts']['critical'] + $result['counts']['error']
                + $result['counts']['warning'] + $result['counts']['info'];
            $checkerHref = '#checker-' . $slug;
            $html .= '<li><a href="' . $this->escape($checkerHref) . '">'
                . '<span>' . $this->escape($result['name']) . '</span>'
                . '<span class="count">' . (string) $total . '</span>'
                . '</a>';

            if ($result['rules'] !== []) {
                $html .= '<ul class="sub">' . "\n";
                foreach (array_slice($result['rules'], 0, 20) as $r) {
                    $html .= '<li><a href="' . $this->escape($checkerHref) . '" data-side-rule="'
                        . $this->escape(strtolower($r['rule'])) . '" role="button" title="Filter: '
                        . $this->escape($r['rule']) . '">'
                        . '<span class="rule-label">' . $this->escape($r['rule']) . '</span>'
                        . '<span class="count">' . (string) $r['count'] . '</span>'
                        . '</a></li>' . "\n";
                }
                if (count($result['rules']) > 20) {
                    $html .= '<li><span class="rule-label empty">… '
                        . (string) (count($result['rules']) - 20) . ' more rules</span></li>' . "\n";
                }
                $html .= '</ul>' . "\n";
            }

            $html .= '</li>' . "\n";
        }

        return $html . '</ul></nav>' . "\n"
            . '</aside>' . "\n";
    }

    /**
     * Files with the most issues, descending, capped for the sidebar.
     *
     * @param CheckResult[] $results
     * @return list<array{file: string, count: int}>
     */
    private function hotFiles(array $results): array
    {
        $counts = [];
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            foreach ($result->issues as $issue) {
                $file = $issue->file ?? '(no file)';
                $counts[$file] = ($counts[$file] ?? 0) + 1;
            }
        }

        arsort($counts);
        $out = [];
        foreach (array_slice($counts, 0, 10, true) as $file => $count) {
            $out[] = ['file' => $file, 'count' => $count];
        }

        return $out;
    }

    private function shortPath(string $file): string
    {
        $normalized = str_replace('\\', '/', $file);
        $segments = explode('/', $normalized);

        return count($segments) > 3
            ? '…/' . implode('/', array_slice($segments, -3))
            : $normalized;
    }

    private function buildToolbar(): string
    {
        return '<div class="toolbar" role="search">' . "\n"
            . '<input type="search" id="report-search" placeholder="Search rule, file, message… / Tìm rule, file…" aria-label="Search issues">' . "\n"
            . '<button type="button" class="chip" data-sev="critical" aria-pressed="true">Critical</button>' . "\n"
            . '<button type="button" class="chip" data-sev="error" aria-pressed="true">Error</button>' . "\n"
            . '<button type="button" class="chip" data-sev="warning" aria-pressed="true">Warning</button>' . "\n"
            . '<button type="button" class="chip" data-sev="info" aria-pressed="true">Info</button>' . "\n"
            . '<span class="match-count" id="match-count" aria-live="polite"></span>' . "\n"
            . '<span class="spacer"></span>' . "\n"
            . '<button type="button" class="chip" id="expand-all">Expand files</button>' . "\n"
            . '<button type="button" class="chip" id="collapse-all">Collapse</button>' . "\n"
            . '<button type="button" class="chip" id="theme-toggle" aria-label="Toggle color theme">Theme</button>' . "\n"
            . '</div>' . "\n";
    }

    private function slug(string $name): string
    {
        $slug = strtolower($name);
        $slug = (string) preg_replace('/[^a-z0-9]+/', '-', $slug);

        return trim($slug, '-');
    }

    /**
     * @param array<string, int> $summary
     * @param list<array{rule: string, source: string, count: int, critical: int, error: int, warning: int, info: int}> $rules
     */
    private function buildSummaryGrid(array $summary, array $rules): string
    {
        return '<div class="card" id="summary">' . "\n"
            . '<h2>Summary</h2>' . "\n"
            . '<div class="summary-grid">' . "\n"
            . $this->stat('Checkers', (int) ($summary['checkers'] ?? 0))
            . $this->stat('Passed', (int) ($summary['passed'] ?? 0))
            . $this->stat('Failed', (int) ($summary['failed'] ?? 0))
            . $this->stat('Skipped', (int) ($summary['skipped'] ?? 0))
            . $this->stat('Total Issues', (int) ($summary['total_issues'] ?? 0))
            . $this->stat('Critical', (int) ($summary['critical'] ?? 0))
            . $this->stat('Error', (int) ($summary['error'] ?? 0))
            . $this->stat('Warning', (int) ($summary['warning'] ?? 0))
            . $this->stat('Info', (int) ($summary['info'] ?? 0))
            . '</div>' . "\n"
            . $this->charts($summary, $rules)
            . '</div>' . "\n";
    }

    /**
     * @param array<string, int> $summary
     * @param list<array{rule: string, source: string, count: int, critical: int, error: int, warning: int, info: int}> $rules
     */
    private function charts(array $summary, array $rules): string
    {
        $total = max(1, (int) ($summary['total_issues'] ?? 0));

        $segs = '';
        $legend = '';
        foreach (['critical', 'error', 'warning', 'info'] as $sev) {
            $count = (int) ($summary[$sev] ?? 0);
            $pct = $count > 0 ? ($count / $total) * 100 : 0.0;
            $segs .= '<span class="seg ' . $sev . '" style="width:' . $this->escape(number_format($pct, 2)) . '%" title="'
                . $this->escape(ucfirst($sev)) . ': ' . (string) $count . '"></span>';
            $legend .= '<span><span class="dot ' . $sev . '"></span>' . $this->escape(ucfirst($sev))
                . ' ' . (string) $count . '</span>';
        }

        $bars = '';
        $top = array_slice($rules, 0, 10);
        $max = $top !== [] ? max(array_column($top, 'count')) : 1;
        foreach ($top as $r) {
            $pct = $max > 0 ? ($r['count'] / $max) * 100 : 0.0;
            $bars .= '<div class="bar-row">'
                . '<span class="bar-label" title="' . $this->escape($r['rule']) . '">' . $this->escape($r['rule']) . '</span>'
                . '<span class="bar-track"><span class="bar-fill" style="width:' . $this->escape(number_format($pct, 1)) . '%"></span></span>'
                . '<span class="bar-val">' . (string) $r['count'] . '</span>'
                . '</div>';
        }
        if ($bars === '') {
            $bars = '<p class="empty">No issues to chart.</p>';
        }

        return '<div class="charts">' . "\n"
            . '<div class="chart-block"><h3>Severity distribution</h3>'
            . '<div class="stacked" aria-hidden="true">' . $segs . '</div>'
            . '<div class="legend">' . $legend . '</div></div>' . "\n"
            . '<div class="chart-block"><h3>Top rules</h3><div class="bars">' . $bars . '</div></div>' . "\n"
            . '</div>' . "\n";
    }

    private function stat(string $label, int $value): string
    {
        return '<div class="stat"><div class="value">' . (string) $value . '</div>'
            . '<div class="label">' . $this->escape($label) . '</div></div>' . "\n";
    }

    /**
     * @param list<array{rule: string, source: string, count: int, critical: int, error: int, warning: int, info: int}> $rules
     */
    private function buildRulesTable(array $rules): string
    {
        if (count($rules) === 0) {
            return '';
        }

        $rows = '<thead><tr>'
            . '<th data-sortable data-type="str">Rule</th>'
            . '<th data-sortable data-type="str">Source</th>'
            . '<th data-sortable data-type="num">Critical</th>'
            . '<th data-sortable data-type="num">Error</th>'
            . '<th data-sortable data-type="num">Warning</th>'
            . '<th data-sortable data-type="num">Info</th>'
            . '<th data-sortable data-type="num">Total</th>'
            . '</tr></thead>' . "\n<tbody>\n";
        foreach (array_slice($rules, 0, 50) as $r) {
            $rows .= '<tr>'
                . '<td class="rule">' . $this->escape($r['rule']) . '</td>'
                . '<td>' . $this->escape($r['source']) . '</td>'
                . '<td>' . (int) $r['critical'] . '</td>'
                . '<td>' . (int) $r['error'] . '</td>'
                . '<td>' . (int) $r['warning'] . '</td>'
                . '<td>' . (int) $r['info'] . '</td>'
                . '<td><strong>' . (int) $r['count'] . '</strong></td>'
                . '</tr>' . "\n";
        }
        $rows .= '</tbody>';

        return '<div class="card" id="top-rules">' . "\n"
            . '<h2>Top Rules / Nhóm lỗi theo rule</h2>' . "\n"
            . '<table>' . $rows . '</table>' . "\n"
            . '</div>' . "\n";
    }

    /**
     * OWASP drill-down: one collapsible block per rule listing concrete
     * findings (capped) with clickable file links + a filter shortcut.
     *
     * @param array<string, int> $counts rule => count
     * @param array<string, list<array{file: string, line: int|null, message: string}>> $issuesByRule
     */
    private function buildOwaspSection(array $counts, array $issuesByRule, CheckContext $ctx): string
    {
        $html = '<div class="card" id="owasp">' . "\n"
            . '<h2>OWASP</h2>' . "\n";

        if ($counts === []) {
            $html .= '<p class="empty">No OWASP findings.</p>' . "\n"
                . '</div>' . "\n";

            return $html;
        }

        foreach ($counts as $rule => $count) {
            $html .= '<details class="owasp-rule">' . "\n"
                . '<summary><span class="chev">&#9656;</span>'
                . '<span class="rule">' . $this->escape($rule) . '</span>'
                . '<span class="pill">' . (string) $count . '</span>'
                . '<button type="button" class="linkish js-filter" data-q="'
                . $this->escape(strtolower($rule)) . '">filter</button>'
                . '</summary>' . "\n";

            $items = $issuesByRule[$rule] ?? [];
            $shown = array_slice($items, 0, 50);
            $html .= '<ul>' . "\n";
            foreach ($shown as $item) {
                $line = $item['line'] !== null ? ':' . (string) $item['line'] : '';
                $html .= '<li><a href="' . $this->escape($this->fileLink($item['file'], $item['line'], $ctx)) . '">'
                    . $this->escape($this->shortPath($item['file']) . $line) . '</a>'
                    . ' &mdash; ' . $this->escape($item['message']) . '</li>' . "\n";
            }
            if (count($items) > count($shown)) {
                $html .= '<li class="empty">… ' . (string) (count($items) - count($shown))
                    . ' more — use the filter button.</li>' . "\n";
            }
            $html .= '</ul>' . "\n"
                . '</details>' . "\n";
        }

        return $html . '</div>' . "\n";
    }

    /**
     * @param array<int, array{name: string, status: string, duration: float, summary: string|null, counts: array{critical: int, error: int, warning: int, info: int}}> $checkers
     */
    private function buildCheckerTable(array $checkers): string
    {
        $html = '<div class="card" id="checkers">' . "\n"
            . '<h2>Per-Checker</h2>' . "\n"
            . '<table>' . "\n"
            . '<thead>' . "\n"
            . '<tr><th data-sortable data-type="str">Checker</th>'
            . '<th data-sortable data-type="str">Status</th>'
            . '<th data-sortable data-type="num">Critical</th>'
            . '<th data-sortable data-type="num">Error</th>'
            . '<th data-sortable data-type="num">Warning</th>'
            . '<th data-sortable data-type="num">Info</th>'
            . '<th data-sortable data-type="num">Duration</th></tr>' . "\n"
            . '</thead>' . "\n"
            . '<tbody>' . "\n";

        foreach ($checkers as $result) {
            $html .= '<tr>'
                . '<td>' . $this->escape($result['name']) . '</td>'
                . '<td class="status ' . $this->escape($result['status']) . '">' . $this->escape($result['status']) . '</td>'
                . '<td>' . (string) $result['counts']['critical'] . '</td>'
                . '<td>' . (string) $result['counts']['error'] . '</td>'
                . '<td>' . (string) $result['counts']['warning'] . '</td>'
                . '<td>' . (string) $result['counts']['info'] . '</td>'
                . '<td data-sort-value="' . $this->escape((string) $result['duration']) . '">'
                . number_format($result['duration'], 2) . 's</td>'
                . '</tr>' . "\n";
        }

        return $html . '</tbody>' . "\n"
            . '</table>' . "\n"
            . '</div>' . "\n";
    }

    /**
     * @param array<int, array{name: string, status: string, duration: float, summary: string|null, counts: array{critical: int, error: int, warning: int, info: int}, files: array<string, list<array{rule: string, severity: string, confidence: string, line: int|null, message: string}>>}> $checkers
     */
    private function buildIssueSections(array $checkers, CheckContext $ctx): string
    {
        $html = '';
        $issueSeq = 0;

        foreach ($checkers as $result) {
            $html .= '<div class="card checker-section" id="checker-' . $this->escape($this->slug($result['name'])) . '">' . "\n"
                . '<div class="checker-head">' . "\n"
                . '<h2>' . $this->escape($result['name']) . '</h2>' . "\n"
                . '<span class="status ' . $this->escape($result['status']) . '">' . $this->escape($result['status']) . '</span>' . "\n"
                . '</div>' . "\n"
                . '<p class="empty no-match" hidden>No issues match the current search / filter.</p>' . "\n";

            if ($result['summary'] !== null && $result['summary'] !== '') {
                $html .= '<p>' . $this->escape($result['summary']) . '</p>' . "\n";
            }

            if ($result['files'] === []) {
                $html .= '<p class="empty">No issues found.</p>' . "\n";
            } else {
                foreach ($this->groupByRule($result['files']) as $rule => $issues) {
                    $html .= $this->buildRuleGroup($rule, $issues, $ctx, $issueSeq);
                }
            }

            $html .= '</div>' . "\n";
        }

        return $html;
    }

    /**
     * Flatten the per-file map into rule => issues (each issue carries its
     * file), ordered by count descending — the checker section groups by
     * rule so a 1,200-issue checker stays navigable (12 groups, not 500+).
     *
     * @param array<string, list<array{rule: string, severity: string, confidence: string, line: int|null, message: string}>> $files
     * @return array<string, list<array{rule: string, severity: string, confidence: string, line: int|null, message: string, file: string}>>
     */
    private function groupByRule(array $files): array
    {
        $byRule = [];
        foreach ($files as $file => $issues) {
            foreach ($issues as $issue) {
                $issue['file'] = $file;
                $byRule[$issue['rule']][] = $issue;
            }
        }

        uksort($byRule, static function (string $a, string $b) use ($byRule): int {
            return count($byRule[$b]) <=> count($byRule[$a]);
        });

        return $byRule;
    }

    /**
     * Collapsible rule group: <details> with severity pills, a sortable
     * issue table (file / severity / confidence / line / message) and
     * inline code snippets.
     *
     * @param list<array{rule: string, severity: string, confidence: string, line: int|null, message: string, file: string}> $issues
     */
    private function buildRuleGroup(string $rule, array $issues, CheckContext $ctx, int &$issueSeq): string
    {
        $sevCounts = ['critical' => 0, 'error' => 0, 'warning' => 0, 'info' => 0];
        foreach ($issues as $issue) {
            $sevCounts[$issue['severity']] = ($sevCounts[$issue['severity']] ?? 0) + 1;
        }

        $pills = '';
        foreach ($sevCounts as $sev => $count) {
            if ($count > 0) {
                $pills .= '<span class="pill ' . $sev . '">' . (string) $count . '</span>';
            }
        }

        $html = '<details class="issue-group" data-rule="' . $this->escape($rule) . '">' . "\n"
            . '<summary>'
            . '<span class="chev">&#9656;</span>'
            . '<span class="rule-name">' . $this->escape($rule) . '</span>'
            . '<span class="pill">' . (string) count($issues) . '</span>' . $pills
            . '</summary>' . "\n"
            . '<table>' . "\n"
            . '<thead>' . "\n"
            . '<tr><th data-sortable data-type="str">File</th>'
            . '<th data-sortable data-type="sev">Severity</th>'
            . '<th data-sortable data-type="str">Confidence</th>'
            . '<th data-sortable data-type="num">Line</th>'
            . '<th data-sortable data-type="str">Message</th></tr>' . "\n"
            . '</thead>' . "\n"
            . '<tbody>' . "\n";

        foreach ($issues as $issue) {
            ++$issueSeq;
            $id = 'iss-' . $issueSeq;
            $file = $issue['file'];
            $searchHaystack = strtolower($issue['rule'] . ' ' . $file . ' '
                . ($issue['line'] !== null ? (string) $issue['line'] : '') . ' '
                . $issue['message'] . ' ' . $issue['severity'] . ' ' . $issue['confidence']);

            $snippet = $this->snippetHtml($ctx, $file, $issue['line']);
            $href = $this->fileLink($file, $issue['line'], $ctx);

            $html .= '<tr id="' . $id . '" data-severity="' . $this->escape($issue['severity']) . '"'
                . ' data-search="' . $this->escape($searchHaystack) . '">'
                . '<td><a class="file-link" href="' . $this->escape($href) . '" title="'
                . $this->escape($file) . '">' . $this->escape($this->shortPath($file)) . '</a></td>'
                . '<td class="severity ' . $this->escape($issue['severity']) . '">' . $this->escape($issue['severity']) . '</td>'
                . '<td>' . $this->escape($issue['confidence']) . '</td>'
                . '<td>' . $this->escape($issue['line'] !== null ? (string) $issue['line'] : '-') . '</td>'
                . '<td>' . $this->escape($issue['message'])
                . ($snippet !== ''
                    ? '<button type="button" class="snip-btn" data-for="' . $id . '" aria-expanded="false" title="Toggle code context">&lt;/&gt;</button>'
                    : '')
                . '</td>'
                . '</tr>' . "\n";

            if ($snippet !== '') {
                $html .= '<tr class="snippet-row" data-for="' . $id . '" hidden><td colspan="5">' . $snippet . '</td></tr>' . "\n";
            }
        }

        return $html . '</tbody>' . "\n"
            . '</table>' . "\n"
            . '</details>' . "\n";
    }

    private function escape(mixed $value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Clickable file link: GitHub blob URL when html.repo_url is configured,
     * otherwise a vscode:// deep link (absolute path + optional line).
     */
    private function fileLink(string $file, ?int $line, ?CheckContext $ctx): string
    {
        $repo = '';
        $branch = 'main';
        if ($ctx !== null) {
            $cfg = $ctx->configFor('html');
            $repo = trim((string) ($cfg['repo_url'] ?? ''));
            $branch = trim((string) ($cfg['branch'] ?? 'main'));
            if ($branch === '') {
                $branch = 'main';
            }
        }

        if ($repo !== '') {
            $rel = $this->relativeToBase($file, $ctx);
            $url = rtrim($repo, '/') . '/blob/' . rawurlencode($branch) . '/' . ltrim($rel, '/');
            if ($line !== null) {
                $url .= '#L' . (string) $line;
            }

            return $url;
        }

        $abs = $ctx !== null ? $ctx->resolvePath($file) : $file;
        $target = str_replace('\\', '/', $abs);
        if ($line !== null) {
            $target .= ':' . (string) $line;
        }

        return 'vscode://file/' . ltrim($target, '/');
    }

    private function relativeToBase(string $file, ?CheckContext $ctx): string
    {
        $normalized = str_replace('\\', '/', $file);
        if ($ctx === null) {
            return $normalized;
        }
        $base = rtrim(str_replace('\\', '/', $ctx->basePath), '/');
        if (str_starts_with($normalized, $base . '/')) {
            return substr($normalized, strlen($base) + 1);
        }

        return ltrim($normalized, '/');
    }

    /**
     * Render a code snippet with line numbers around the finding; returns
     * an empty string when snippets are disabled or the file is unreadable.
     */
    private function snippetHtml(CheckContext $ctx, string $file, ?int $line): string
    {
        $cfg = $ctx->configFor('html');
        $context = (int) ($cfg['code_context'] ?? 3);
        if ($context <= 0 || $line === null || $line < 1) {
            return '';
        }

        $abs = $ctx->resolvePath($file);
        if (!isset($this->lineCache[$abs])) {
            $this->lineCache[$abs] = null;
            if (is_file($abs) && @filesize($abs) < 1_048_576) {
                $lines = @file($abs, FILE_IGNORE_NEW_LINES);
                if (is_array($lines)) {
                    $this->lineCache[$abs] = $lines;
                }
            }
        }

        $lines = $this->lineCache[$abs];
        if ($lines === null || $line > count($lines)) {
            return '';
        }

        $from = max(1, $line - $context);
        $to = min(count($lines), $line + $context);
        $pad = strlen((string) $to);
        $out = '';
        for ($i = $from; $i <= $to; ++$i) {
            $cur = $i === $line ? ' cur' : '';
            $out .= '<span class="row' . $cur . '"><span class="cl">'
                . str_pad((string) $i, $pad, ' ', STR_PAD_LEFT) . '</span>'
                . $this->escape($lines[$i - 1]) . '</span>';
        }

        return '<pre class="code">' . $out . '</pre>';
    }

    /**
     * @param CheckResult[] $results
     * @return array<string, list<array{file: string, line: int|null, message: string}>>
     */
    private function owaspIssues(array $results): array
    {
        $out = [];
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            foreach ($result->issues as $issue) {
                if (str_starts_with($issue->rule, 'OWASP_')) {
                    $out[$issue->rule][] = [
                        'file' => $issue->file ?? '(no file)',
                        'line' => $issue->line,
                        'message' => $issue->message,
                    ];
                }
            }
        }

        return $out;
    }

    /**
     * @param CheckResult[] $results
     * @return array<int, array{name: string, status: string, duration: float, summary: string|null, counts: array{critical: int, error: int, warning: int, info: int}, files: array<string, list<array{rule: string, severity: string, confidence: string, line: int|null, message: string}>>, rules: list<array{rule: string, count: int}>}>
     */
    private function buildCheckers(array $results): array
    {
        $checkers = [];
        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }

            $checkers[] = [
                'name' => $result->name,
                'status' => $result->status,
                'duration' => $result->duration,
                'summary' => $result->summary,
                'counts' => [
                    'critical' => $this->countBySeverity($result, Severity::Critical),
                    'error' => $this->countBySeverity($result, Severity::Error),
                    'warning' => $this->countBySeverity($result, Severity::Warning),
                    'info' => $this->countBySeverity($result, Severity::Info),
                ],
                'files' => $this->groupByFile($result),
                'rules' => $this->ruleCounts($result),
            ];
        }

        return $checkers;
    }

    /**
     * Rule counts for one checker, descending — powers the sidebar sub-menu.
     *
     * @return list<array{rule: string, count: int}>
     */
    private function ruleCounts(CheckResult $result): array
    {
        $counts = [];
        foreach ($result->issues as $issue) {
            $counts[$issue->rule] = ($counts[$issue->rule] ?? 0) + 1;
        }
        arsort($counts);

        $out = [];
        foreach ($counts as $rule => $count) {
            $out[] = ['rule' => $rule, 'count' => $count];
        }

        return $out;
    }

    private function countBySeverity(CheckResult $result, Severity $severity): int
    {
        $count = 0;
        foreach ($result->issues as $issue) {
            if ($issue->severity === $severity) {
                ++$count;
            }
        }

        return $count;
    }

    /**
     * @return array<string, list<array{rule: string, severity: string, confidence: string, line: int|null, message: string}>>
     */
    private function groupByFile(CheckResult $result): array
    {
        $groups = [];
        foreach ($result->issues as $issue) {
            $file = $issue->file ?? '(no file)';
            $groups[$file][] = [
                'rule' => $issue->rule,
                'severity' => $issue->severity->value,
                'confidence' => $issue->confidence->value,
                'line' => $issue->line,
                'message' => $issue->message,
            ];
        }

        ksort($groups);

        return $groups;
    }

    /**
     * @param CheckResult[] $results
     * @return array<string, int>
     */
    private function buildSummary(array $results): array
    {
        $summary = [
            'checkers' => count($results),
            'passed' => 0,
            'failed' => 0,
            'skipped' => 0,
            'total_issues' => 0,
            'critical' => 0,
            'error' => 0,
            'warning' => 0,
            'info' => 0,
        ];

        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }

            $status = $result->status;
            if ($status === 'passed') {
                ++$summary['passed'];
            } elseif ($status === 'failed' || $status === 'error' || $status === 'warning') {
                ++$summary['failed'];
            } elseif ($status === 'skipped') {
                ++$summary['skipped'];
            }

            $summary['total_issues'] += count($result->issues);
            foreach ($result->issues as $issue) {
                $severity = $issue->severity;
                if ($severity === Severity::Critical) {
                    ++$summary['critical'];
                } elseif ($severity === Severity::Error) {
                    ++$summary['error'];
                } elseif ($severity === Severity::Warning) {
                    ++$summary['warning'];
                } else {
                    ++$summary['info'];
                }
            }
        }

        return $summary;
    }

    /**
     * @param CheckResult[] $results
     */
    private function overallStatus(array $results): string
    {
        $failed = false;
        $hasIssues = false;

        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            if ($result->status === 'failed' || $result->status === 'error') {
                $failed = true;
            }
            if (count($result->issues) > 0) {
                $hasIssues = true;
            }
        }

        if ($failed) {
            return 'failed';
        }
        if ($hasIssues) {
            return 'warning';
        }

        return 'passed';
    }
}
