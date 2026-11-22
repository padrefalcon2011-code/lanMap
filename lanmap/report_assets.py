"""Оформление отчёта: набор иконок (встроенный SVG), стили и скрипт. Без внешних файлов и шрифтов.

Строки сырые (r\"\"\"…\"\"\"): в JS и CSS не должно появиться случайных управляющих символов.
Числа в путях SVG — всегда через пробел и с ведущим нулём (тест-сторож ищет IP-адреса в пакете).
"""

from lanmap.report_icons import DEVICE_ICONS

# Служебные иконки 24×24, линия currentColor. Иконки типов устройств (i-<тип>, 32×32, двухтоновые) —
# в report_icons.py, подставляются в тот же набор.
ICONS = r"""<svg xmlns="http://www.w3.org/2000/svg" style="display:none">
<defs>
{DEVICE_ICONS}
<symbol id="i-devices" viewBox="0 0 24 24"><circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5 6.5 17M12 11.5 17.5 17"/></symbol>
<symbol id="i-globe" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/></symbol>
<symbol id="i-arrow" viewBox="0 0 24 24"><path d="M4 12h16M14 6l6 6-6 6"/></symbol>
<symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
<symbol id="i-minus" viewBox="0 0 24 24"><path d="M5 12h14"/></symbol>
<symbol id="i-delta" viewBox="0 0 24 24"><path d="M12 4 3 20h18z"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></symbol>
<symbol id="i-x" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></symbol>
<symbol id="i-chevron" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></symbol>
<symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/></symbol>
<symbol id="i-grid" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></symbol>
<symbol id="i-list" viewBox="0 0 24 24"><path d="M8 6h13M8 12h13M8 18h13M3.5 6h0.01M3.5 12h0.01M3.5 18h0.01"/></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></symbol>
<symbol id="i-open" viewBox="0 0 24 24"><path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/></symbol>
<symbol id="i-alert" viewBox="0 0 24 24"><path d="M12 3 2 21h20z"/><path d="M12 10v5M12 18h0.01"/></symbol>
<symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h0.01"/></symbol>
<symbol id="i-user" viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></symbol>
<symbol id="i-shuffle" viewBox="0 0 24 24"><path d="M16 3h5v5M4 20 21 3M21 16v5h-5M15 15l6 6M4 4l5 5"/></symbol>
<symbol id="i-link" viewBox="0 0 24 24"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></symbol>
<symbol id="i-pencil" viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16z"/></symbol>
<symbol id="i-chip" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/></symbol>
<symbol id="i-barcode" viewBox="0 0 24 24"><path d="M4 5v14M7 5v14M11 5v14M14 5v14M18 5v14M20 5v14"/></symbol>
<symbol id="i-wifi3" viewBox="0 0 24 24"><path d="M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M12 19.5h0.01"/></symbol>
<symbol id="i-wifi2" viewBox="0 0 24 24"><path d="M2 9a15 15 0 0 1 20 0" opacity="0.25"/><path d="M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M12 19.5h0.01"/></symbol>
<symbol id="i-wifi1" viewBox="0 0 24 24"><path d="M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0" opacity="0.25"/><path d="M8.5 16a5 5 0 0 1 7 0M12 19.5h0.01"/></symbol>
<symbol id="i-cable" viewBox="0 0 24 24"><path d="M12 22v-4M9 8V3M15 8V3M6 8h12v4a6 6 0 0 1-12 0z"/></symbol>
<symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M5 19l1.5-1.5M17.5 6.5 19 5"/></symbol>
<symbol id="i-moon" viewBox="0 0 24 24"><path d="M20 15A8 8 0 1 1 9 4a6 6 0 0 0 11 11z"/></symbol>
<symbol id="i-expand" viewBox="0 0 24 24"><path d="M7 9l5-5 5 5M7 15l5 5 5-5"/></symbol>
<symbol id="i-question" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.4 2.3c-0.6 0.3-0.9 0.9-0.9 1.5V14M12 17.5h0.01"/></symbol>
<symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-0.7 8-4.5 8-9V6z"/><path d="M12 8v5M12 16h0.01"/></symbol>
<symbol id="i-key" viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3M14 9l2 2"/></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></symbol>
<symbol id="i-home" viewBox="0 0 24 24"><path d="M3 11 12 4l9 7"/><path d="M5 10v10h14V10M10 20v-6h4v6"/></symbol>
<symbol id="i-folder" viewBox="0 0 24 24"><path d="M3 6a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/></symbol>
<symbol id="i-eye" viewBox="0 0 24 24"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></symbol>
<symbol id="i-wrench" viewBox="0 0 24 24"><path d="M14.5 6.5a4 4 0 0 0 5 5L21 13l-8 8-3-3 0.5-1.5a4 4 0 0 0-5-5L4 13 3 10l8-8 3 3z"/></symbol>
<symbol id="i-refresh" viewBox="0 0 24 24"><path d="M20 12a8 8 0 1 1-2.34-5.66"/><path d="M20 4v5h-5"/></symbol>
<symbol id="i-undo" viewBox="0 0 24 24"><path d="M9 14 4 9l5-5"/><path d="M4 9h11a5 5 0 0 1 0 10h-3"/></symbol>
<symbol id="i-cash" viewBox="0 0 24 24"><rect x="2.5" y="6" width="19" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M6 9.5v0.01M18 14.5v0.01"/></symbol>
<symbol id="i-bot" viewBox="0 0 24 24"><rect x="5" y="8" width="14" height="11" rx="3"/><path d="M12 8V4.5M12 4.5h0.01M9.5 13v1M14.5 13v1M2.5 12.5v3M21.5 12.5v3"/></symbol>
<symbol id="i-power" viewBox="0 0 24 24"><path d="M12 3v8"/><path d="M6.6 6.6a8 8 0 1 0 10.8 0"/></symbol>
<symbol id="i-gear" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1 7 17M17 7l2.1-2.1"/></symbol>
<symbol id="i-download" viewBox="0 0 24 24"><path d="M12 4v11M7 10l5 5 5-5M5 20h14"/></symbol>
</defs></svg>""".replace("{DEVICE_ICONS}", DEVICE_ICONS)

CSS = r"""
:root{color-scheme:light;--bg:#f3f4f6;--card:#fff;--fg:#1b1f27;--muted:#69707d;--faint:#9aa1ad;--line:#e2e5ea;
--chip:#eef0f4;--accent:#2a78d6;--accent-soft:#e3eefb;--good:#0ca30c;--warn:#b07a00;--warn-soft:#fff4dc;
--crit:#d03b3b;--crit-soft:#fdeceb;--add:#2a78d6;--add-soft:#e3eefb;--shadow:0 1px 2px rgba(16,24,40,.06);
--serious:#b34a14;--warn-text:#6e4d00}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#131518;--card:#1c1f24;
--fg:#e8eaed;--muted:#a0a7b2;--faint:#6f7680;--line:#2d3239;--chip:#262a31;--accent:#3987e5;--accent-soft:#1d2b3d;
--good:#2fbf2f;--warn:#fab219;--warn-soft:#33290f;--crit:#e66767;--crit-soft:#3a1f1f;--add:#6da7ec;--add-soft:#1d2b3d;--shadow:none;
--serious:#f0956c;--warn-text:#fab219}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#131518;--card:#1c1f24;--fg:#e8eaed;--muted:#a0a7b2;--faint:#6f7680;
--line:#2d3239;--chip:#262a31;--accent:#3987e5;--accent-soft:#1d2b3d;--good:#2fbf2f;--warn:#fab219;--warn-soft:#33290f;
--crit:#e66767;--crit-soft:#3a1f1f;--add:#6da7ec;--add-soft:#1d2b3d;--shadow:none;--serious:#f0956c;--warn-text:#fab219}
*{box-sizing:border-box}
body{margin:0;overflow-x:clip;background:var(--bg);color:var(--fg);font:14px/1.4 system-ui,"Segoe UI",sans-serif}
svg.i{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}
svg.i.s{width:18px;height:18px}svg.i.l{width:30px;height:30px}
svg.i .d{fill:currentColor;opacity:.2;stroke:none}
button{font:inherit;color:inherit}
.wrap{max-width:1400px;margin:auto;padding:16px 20px}
.mono{font-family:ui-monospace,Consolas,monospace}
.muted{color:var(--muted)}
/* шапка */
.top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.top h1{margin:0;font-size:20px;display:flex;align-items:center;gap:8px}
.top .when{color:var(--muted);font-size:13px}
.top .spacer{flex:1}
.iconbtn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--line);background:var(--card);
border-radius:8px;height:32px;min-width:32px;padding:0 8px;cursor:pointer;color:var(--fg)}
.iconbtn:hover{border-color:var(--accent);color:var(--accent)}
.iconbtn.on{background:var(--accent);border-color:var(--accent);color:#fff}
/* «О срезе»: строка под заголовком, подробности по нажатию */
details.about{margin-top:6px}
details.about>summary{list-style:none;display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap;cursor:pointer;color:var(--muted);font-size:13px}
details.about>summary::-webkit-details-marker{display:none}
details.about[open]>summary{color:var(--fg)}
.abody{margin-top:8px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px 12px;font-size:13px;display:grid;gap:8px}
.agrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:6px 18px}
.agrid>div{display:flex;align-items:center;gap:7px;min-width:0}.agrid span{color:var(--muted)}
.agrid b{font-weight:500;overflow-wrap:anywhere}.agrid svg.i{color:var(--muted)}
.agrid .ring{width:22px!important;height:22px!important}
.awarn{display:flex;align-items:center;gap:8px;flex-wrap:wrap;background:var(--warn-soft);color:var(--warn-text);border-radius:9px;padding:6px 10px}
.abody p{margin:0}.ptitle{font-weight:600;margin-top:4px}
.agrid.pass .good svg.i{color:var(--good)}.agrid.pass .warn svg.i{color:var(--warn)}
.agrid.pass .crit svg.i{color:var(--crit)}.agrid.pass .skip svg.i{color:var(--faint)}
.agrid.pass .warn b{color:var(--warn-text)}.agrid.pass .crit b{color:var(--crit)}
/* сводка: главная находка крупно, показатели — кнопки к разделам и фильтрам */
.sum{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin:12px 0}
.alert{grid-column:span 2;display:flex;align-items:center;gap:12px;text-align:left;cursor:pointer;color:var(--fg);
background:var(--crit-soft);border:1px solid var(--crit);border-left-width:6px;border-radius:12px;padding:10px 14px;min-width:0}
.alert:hover{box-shadow:0 0 0 2px var(--crit)}
.alert .aico{width:46px;height:46px;border-radius:12px;display:grid;place-items:center;flex:none;background:var(--crit);color:#fff}
.alert .aico svg.i{width:28px;height:28px}
.alert .atext{display:flex;flex-direction:column;min-width:0;flex:1}
.alert .atag{font-size:12px;font-weight:700;color:var(--crit);text-transform:uppercase;letter-spacing:.03em}
.alert b{font-size:16px;line-height:1.25}.alert .amore{font-size:12.5px;color:var(--muted)}
.alert.p2,.alert.p3{background:var(--warn-soft);border-color:var(--warn)}.alert.p2 .aico,.alert.p3 .aico{background:var(--warn)}
.alert.p2 .atag,.alert.p3 .atag{color:var(--warn-text)}
.alert.ok{background:var(--card);border-color:var(--good)}.alert.ok .aico{background:var(--good)}
@media (max-width:560px){.alert{grid-column:1/-1}}
.kpi{display:flex;align-items:center;gap:10px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px 12px;
box-shadow:var(--shadow);text-align:left;cursor:default}
button.kpi{cursor:pointer}button.kpi:hover{border-color:var(--accent)}
.kpi .ico{width:46px;height:46px;border-radius:12px;background:var(--chip);display:grid;place-items:center;flex:none}
.kpi .ico svg.i{width:28px;height:28px}
.ring{width:46px!important;height:46px!important}
.kpi b{display:block;font-size:22px;line-height:1.1}.kpi span.l{color:var(--muted);font-size:12px}
.kpi.crit{border-color:var(--crit)}.kpi.crit .ico{background:var(--crit-soft);color:var(--crit)}
.kpi.add .ico{background:var(--add-soft);color:var(--add)}
.kpi.good .ico{background:color-mix(in srgb,var(--good) 15%,var(--card));color:var(--good)}
.kpi .sub{display:block;color:var(--muted);font-size:11.5px}.kpi b small{font-size:13px;color:var(--muted);font-weight:500}
.kpi .ico .dot{width:16px;height:16px}
/* фильтры: быстрые кнопками, остальное — во всплывающем «Ещё» */
.bar .spacer{flex:1}
details.more{position:static}
details.more>summary{list-style:none}details.more>summary::-webkit-details-marker{display:none}
.mbadge{min-width:18px;height:18px;border-radius:9px;background:var(--accent);color:#fff;font-size:11px;font-weight:700;display:inline-grid;place-items:center;padding:0 5px}
.mbadge[hidden]{display:none}
.pop{position:absolute;z-index:25;top:calc(100% + 4px);left:0;width:min(460px,100%);background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px;box-shadow:0 8px 24px rgba(0,0,0,.18);display:grid;gap:8px}
.pop h4{margin:0;font-size:12px;color:var(--muted);font-weight:600}
.pop .gfilters{grid-template-columns:repeat(auto-fill,minmax(62px,1fr));gap:8px;margin:0}
.pop .gf{border-radius:14px}.pop .gf .badge{top:3px;right:3px;min-width:20px;height:20px;line-height:20px;font-size:11px;padding:0 5px;border-radius:10px}
.pop .lv{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.panels{margin-top:16px}
.ring{width:38px;height:38px;flex:none}.ring circle{fill:none;stroke-width:4}
.ring .bg{stroke:var(--chip)}.ring .fg{stroke:var(--accent);stroke-linecap:round;transform:rotate(-90deg);transform-origin:50% 50%}
.dot{display:inline-block;width:11px;height:11px;border-radius:50%;background:var(--good);flex:none}
.dot.off{background:transparent;border:2px solid var(--faint)}
/* панели */
details.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;margin:10px 0;box-shadow:var(--shadow)}
details.panel>summary{list-style:none;display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;flex-wrap:wrap}
details.panel>summary::-webkit-details-marker{display:none}
details.panel>summary h2{margin:0;font-size:15px;display:flex;align-items:center;gap:8px}
details.panel>summary .chev{margin-left:auto;transition:transform .15s}
details[open]>summary .chev{transform:rotate(180deg)}
details.panel.crit{border-color:var(--crit)}details.panel.crit>summary h2{color:var(--crit)}
.panel-body{padding:0 14px 12px}
.counters{display:flex;gap:6px;flex-wrap:wrap}
.cnt{display:inline-flex;align-items:center;gap:4px;font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;background:var(--chip)}
.cnt.add{background:var(--add-soft);color:var(--add)}.cnt.del{color:var(--muted)}.cnt.crit{background:var(--crit-soft);color:var(--crit)}
.cnt.zero{opacity:.45}
.note{display:flex;gap:6px;align-items:flex-start;color:var(--muted);font-size:12px;margin:4px 0}
.cgroup{margin-top:8px}.cgroup h3{margin:0 0 4px;font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
.crow{display:flex;align-items:center;gap:8px;padding:5px 6px;border-radius:8px;flex-wrap:wrap}
.crow:hover{background:var(--chip)}
.crow .who{display:inline-flex;align-items:center;gap:6px;min-width:0;border:0;background:none;padding:0;cursor:pointer;font-weight:600}
.crow .who:hover{color:var(--accent)}.crow.gone .who{text-decoration:line-through;color:var(--muted);cursor:default}
.crow .ip{color:var(--muted);font-size:12px}
.pc{display:inline-flex;align-items:center;gap:3px;font-size:13px;padding:2px 8px;border-radius:7px;background:var(--chip);
font-family:ui-monospace,Consolas,monospace;white-space:nowrap}
.pc.add{background:var(--add-soft);color:var(--add);font-weight:600}
.pc.del{color:var(--muted)}.pc.del s{text-decoration-thickness:2px}
.pc.crit{background:var(--crit-soft);color:var(--crit);font-weight:600}
.pc.warn{background:var(--warn-soft);color:var(--warn)}
.pc .to{color:var(--fg);font-weight:600}
.pc.trans{gap:4px}
/* пробросы */
.door{display:flex;align-items:center;gap:8px;padding:6px 8px;border-radius:8px;flex-wrap:wrap}
.door:hover{background:var(--crit-soft)}
.door .src{display:inline-flex;align-items:center;gap:6px;color:var(--crit);font-weight:600}
.door .arr{color:var(--crit)}
.door .desc{color:var(--muted);font-size:12px}
.door .who{display:inline-flex;align-items:center;gap:6px;border:0;background:none;padding:0;cursor:pointer;font-weight:600}
.door .who:hover{color:var(--accent)}
/* панель фильтров */
.bar{position:sticky;top:0;z-index:10;background:var(--bg);padding:8px 0;display:flex;gap:6px;flex-wrap:wrap;align-items:center;
border-bottom:1px solid var(--line)}
.search{flex:1 1 220px;display:flex;align-items:center;gap:6px;background:var(--card);border:1px solid var(--line);border-radius:8px;
padding:0 10px;height:32px;color:var(--muted)}
.search input{border:0;outline:0;background:transparent;color:var(--fg);flex:1;font:inherit;min-width:0}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:8px;background:var(--card)}
.seg button{border:0;background:transparent;height:30px;padding:0 9px;display:inline-flex;align-items:center;gap:5px;cursor:pointer;color:var(--muted)}
.seg button:first-child{border-radius:7px 0 0 7px}.seg button:last-child{border-radius:0 7px 7px 0}
.seg button+button{border-left:1px solid var(--line)}
.seg button.on{background:var(--accent);color:#fff}
/* фильтр групп: крупные значки, счётчик в уголке, подпись — в подсказке */
.gfilters{display:grid;grid-template-columns:repeat(auto-fill,minmax(118px,1fr));gap:14px;margin:16px 0 6px}
.gf{position:relative;aspect-ratio:1;border-radius:22px;border:2px solid transparent;cursor:pointer;padding:0;
display:grid;place-items:center;color:var(--g);
background:linear-gradient(150deg,color-mix(in srgb,var(--g) 10%,var(--card)),color-mix(in srgb,var(--g) 24%,var(--card)));
box-shadow:0 2px 6px color-mix(in srgb,var(--g) 18%,transparent);transition:transform .15s,box-shadow .15s}
.gf svg.i{width:62%;height:62%;stroke-width:1.6}
.gf svg.i .d{opacity:.28}
.gf:hover{transform:translateY(-3px);box-shadow:0 10px 22px color-mix(in srgb,var(--g) 30%,transparent)}
.gf:focus-visible{outline:3px solid var(--g);outline-offset:2px}
.gf .badge{position:absolute;top:8px;right:8px;min-width:30px;height:30px;padding:0 8px;border-radius:15px;background:var(--g);
color:#fff;font-size:15px;font-weight:700;line-height:30px;text-align:center}
.gf.on{background:var(--g);color:#fff;border-color:var(--g);box-shadow:0 10px 24px color-mix(in srgb,var(--g) 40%,transparent)}
.gf.on svg.i .d{opacity:.35}
.gf.on .badge{background:#fff;color:var(--g)}
.gfilters.picked .gf:not(.on){opacity:.45;filter:saturate(.6)}
.gfilters.picked .gf:not(.on):hover{opacity:1;filter:none}
/* плавающая подсказка: наведение и фокус с клавиатуры */
[data-tip]{position:relative}
[data-tip]::after{content:attr(data-tip);position:absolute;left:50%;top:calc(100% + 8px);transform:translate(-50%,-3px);
background:var(--fg);color:var(--bg);font:500 12px/1.3 system-ui,"Segoe UI",sans-serif;white-space:nowrap;padding:5px 9px;
border-radius:7px;pointer-events:none;opacity:0;transition:opacity .12s,transform .12s;z-index:40;box-shadow:0 4px 14px rgba(0,0,0,.18)}
[data-tip]:hover::after,[data-tip]:focus-visible::after{opacity:1;transform:translate(-50%,0)}
.tip-l[data-tip]::after{left:auto;right:0;transform:translate(0,-3px)}
.tip-l[data-tip]:hover::after,.tip-l[data-tip]:focus-visible::after{transform:translate(0,0)}
/* группы и плитки */
details.group{margin:14px 0}
details.group>summary{list-style:none;display:flex;align-items:center;gap:8px;cursor:pointer;padding:4px 0;font-size:15px;font-weight:600}
details.group>summary::-webkit-details-marker{display:none}
details.group>summary .n{color:var(--muted);font-weight:500}
details.group>summary .chev{color:var(--muted);transition:transform .15s}
details.group:not([open])>summary .chev{transform:rotate(-90deg)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:10px;align-items:start;margin-top:6px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow);min-width:0}
.tile.changed{border-color:var(--add)}.tile.risky{border-color:var(--crit)}
.tile.open{grid-column:1/-1}
.thead{display:grid;grid-template-columns:auto 1fr auto;grid-template-areas:"icon main side" "marks marks marks";gap:6px 10px;
width:100%;text-align:left;background:none;border:0;padding:12px;cursor:pointer;align-items:center}
.ticon{grid-area:icon;position:relative;width:54px;height:54px;border-radius:14px;display:grid;place-items:center;color:var(--g,var(--fg));
background:linear-gradient(150deg,color-mix(in srgb,var(--g,#888) 10%,var(--card)),color-mix(in srgb,var(--g,#888) 22%,var(--card)))}
.ticon svg.i .d{opacity:.28}
.gico{display:inline-grid;place-items:center;width:34px;height:34px;border-radius:10px;color:var(--g);
background:color-mix(in srgb,var(--g) 16%,var(--card))}
.ticon svg.i{width:32px;height:32px}
.ticon .dot{width:12px;height:12px}
.ticon .dot{position:absolute;right:-2px;bottom:-2px;box-shadow:0 0 0 2px var(--card)}
.tile.off .ticon{opacity:.55}
.tmain{grid-area:main;min-width:0;display:flex;flex-direction:column}
.tmain b{font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tmain .sub{color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tmain .ip{font-size:12px;color:var(--muted)}
.tside{grid-area:side;display:flex;flex-direction:column;align-items:flex-end;gap:6px;color:var(--muted)}
.meter{display:inline-flex;gap:3px}.meter i{width:8px;height:15px;border-radius:2px;background:var(--line)}
.meter i.f{background:var(--accent)}
.tmarks{grid-area:marks;display:flex;flex-wrap:wrap;gap:4px;align-items:center}
.flag{display:inline-flex;align-items:center;color:var(--muted)}
.flag.warn{color:var(--warn)}.flag.acc{color:var(--accent)}.flag.crit{color:var(--crit)}
.certw{display:inline-flex;align-items:center;gap:2px;margin-left:5px;color:var(--warn);font-weight:600}.certw.crit{color:var(--crit)}
.tdetail{padding:0 12px 12px;border-top:1px solid var(--line)}
.tdetail[hidden]{display:none}
.dgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:10px}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:3px 10px;font-size:13px;align-content:start}
.facts span{color:var(--muted)}.facts b{font-weight:500;word-break:break-word}
.ports{display:flex;flex-wrap:wrap;gap:4px;align-content:start}
.acts{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.act{display:inline-flex;align-items:center;gap:5px;font-size:12px;border:1px solid var(--line);background:var(--card);color:var(--fg);
border-radius:8px;padding:4px 9px;text-decoration:none;cursor:pointer}
.act:hover{border-color:var(--accent);color:var(--accent)}.act.danger{color:var(--crit)}
.why{margin-top:10px}.why>summary{cursor:pointer;color:var(--accent);font-size:13px}
.why ul{margin:6px 0;padding-left:18px;font-size:13px}.why li{margin:2px 0}
.why .src{color:var(--muted);font-size:12px}.why h4{margin:8px 0 2px;font-size:12px;color:var(--muted)}
.tag{font-size:11px;background:var(--chip);border-radius:4px;padding:0 5px}
.conflict{color:var(--crit)}
.chgline{display:flex;flex-wrap:wrap;gap:4px;margin-top:10px;align-items:center}
/* безопасность: приоритет — цветом, иконкой и словом */
.p1{--p:#d03b3b;--pt:var(--crit)}.p2{--p:#ec835a;--pt:var(--serious)}.p3{--p:#fab219;--pt:var(--warn-text)}
.cnt.p1,.cnt.p2,.cnt.p3,.pc.p1,.pc.p2,.pc.p3{background:color-mix(in srgb,var(--p) 16%,var(--card));color:var(--pt);font-weight:600}
.scard{display:flex;flex-direction:column;gap:12px;padding:12px 14px;border:1px solid var(--line);
border-left:6px solid var(--p);border-radius:12px;margin:10px 0}
.scard.quiet{opacity:.6}
.fico{width:46px;height:46px;border-radius:14px;display:grid;place-items:center;color:var(--p);flex:none;
background:linear-gradient(150deg,color-mix(in srgb,var(--p) 10%,var(--card)),color-mix(in srgb,var(--p) 26%,var(--card)))}
.fico svg.i{width:28px;height:28px}.fico svg.i .d{opacity:.28}
.fhead{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.fhead h3{margin:0;font-size:16px;flex:1 1 240px}
/* инфографика: схема «кто → куда» */
.scheme{display:flex;align-items:flex-start;gap:4px;padding:4px 0}
.sn{display:flex;flex-direction:column;align-items:center;text-align:center;gap:4px;width:150px;flex:none;--c:var(--fg);--cb:var(--chip)}
.sn.crit{--c:var(--crit);--cb:var(--crit-soft)}.sn.warn{--c:var(--warn-text);--cb:var(--warn-soft)}
.sn.dev{--c:var(--g);--cb:color-mix(in srgb,var(--g) 16%,var(--card));width:190px}
.snc{width:60px;height:60px;border-radius:50%;display:grid;place-items:center;background:var(--cb);color:var(--c)}
.snc svg.i{width:34px;height:34px}
.sn b{font-size:14px;line-height:1.25;word-break:break-word}.sn small{font-size:12px;color:var(--muted)}
.sl{flex:1 1 60px;min-width:60px;display:flex;flex-direction:column;align-items:center;gap:0;padding-top:12px;color:var(--muted)}
.sl small{font-size:12px;text-align:center;line-height:1.2}.sl svg.i{width:34px;height:28px}
.sl.l svg.i{transform:scaleX(-1)}.sl.crit{color:var(--crit)}.sl.warn{color:var(--warn-text)}
.lbl2{font-size:12px;color:var(--muted);display:inline-flex;align-items:center;gap:5px;margin-right:4px}
.threat{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.tch{display:inline-flex;align-items:center;gap:7px;padding:7px 12px;border-radius:10px;background:var(--chip);font-size:13px}
.tch svg.i{color:var(--pt)}.tarr{color:var(--faint);display:inline-flex}
.todo{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:8px}
.todo li{display:flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid var(--line);border-radius:10px;font-size:13.5px}
.todo li svg.i{color:var(--accent);width:24px;height:24px}
.nm{width:26px;height:26px;border-radius:50%;background:var(--accent-soft);color:var(--accent);display:grid;place-items:center;
font-size:13px;font-weight:700;flex:none}
.fobjs{display:flex;flex-direction:column;gap:4px}
.drow{border:1px solid var(--line);border-radius:10px}.drow.quiet{opacity:.6}
.drow>summary{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:6px 10px;cursor:pointer;list-style:none}
.drow>summary::-webkit-details-marker{display:none}
.drow .chev{color:var(--accent);transform:rotate(-90deg);transition:transform .15s}.drow[open] .chev{transform:none}
.drow .who{display:inline-flex;align-items:center;gap:6px;font-weight:600}
.drow .det{color:var(--muted);font-size:12px}.drow .goto{margin-left:auto;padding:3px 6px}
.dbody{padding:2px 14px 10px 36px}
.dbody ol{margin:6px 0;padding-left:20px;font-size:13px;line-height:1.5}.dbody li{margin:3px 0}
.dbody li.vfy{list-style:none;margin-left:-20px;color:var(--good)}.dbody li.vfy::before{content:"✓ ";font-weight:700}
.vend{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:var(--good);font-weight:600;margin-right:12px}
.vend.gen{color:var(--muted);font-weight:400}
.fnote{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.more>summary{cursor:pointer;color:var(--accent);font-size:13px;display:inline-flex;align-items:center;gap:6px;list-style:none}
.more>summary::-webkit-details-marker{display:none}
.prio{display:inline-flex;align-items:center;gap:4px;font-size:12px;font-weight:700;padding:3px 10px;border-radius:999px;
background:var(--p);color:#fff;white-space:nowrap}
.p3 .prio,.prio.p3{color:#2b2100}.p2 .prio{color:#2b1200}
.facets{display:inline-flex;gap:6px;align-items:center}
.facet{display:inline-grid;place-items:center;width:38px;height:38px;border-radius:11px;background:var(--chip);color:var(--fg)}
.facet.net{background:var(--crit-soft);color:var(--crit)}
.facet+.facet.stake{margin-left:0}.facets .sep{width:1px;height:26px;background:var(--line);margin:0 2px}
.frisk{margin:8px 0 0;font-size:13.5px;line-height:1.5;max-width:95ch}
.conf{font-size:11px;padding:1px 7px;border-radius:999px;background:var(--chip);color:var(--muted);white-space:nowrap}
.conf.likely{background:var(--warn-soft);color:var(--warn-text)}.conf.verify{border:1px dashed var(--faint)}
.st{display:inline-flex;align-items:center;gap:4px;font-size:12px;font-weight:600;padding:2px 8px;border-radius:999px;background:var(--chip)}
.st.crit{background:var(--crit-soft);color:var(--crit)}.st.good{color:var(--good)}
.hgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;margin:8px 0}
.hbox{background:var(--chip);border-radius:10px;padding:8px 10px;font-size:12.5px;line-height:1.45}
.hbox b{display:flex;align-items:center;gap:6px;margin-bottom:3px;font-size:12px}
.cli{display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-size:12px;color:var(--muted)}
.cli code{font-family:ui-monospace,Consolas,monospace;background:var(--chip);padding:2px 6px;border-radius:6px;color:var(--fg)}
.sline{display:flex;align-items:center;gap:6px;font-size:13px;margin-top:6px}
.sline a{color:inherit}
.ok-big{display:flex;align-items:center;gap:10px;color:var(--good);font-weight:600;padding:6px 0}
/* вид «список» */
main.list .grid{grid-template-columns:1fr;gap:4px}
main.list .tile.open{grid-column:auto}
main.list .thead{grid-template-columns:auto minmax(180px,1.4fr) minmax(0,2fr) auto;grid-template-areas:"icon main marks side";padding:6px 10px}
main.list .ticon{width:40px;height:40px;border-radius:11px}main.list .ticon svg.i{width:26px;height:26px}
main.list .tside{flex-direction:row;align-items:center}
/* легенда */
.legend{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:6px 14px;font-size:13px}
.legend div{display:flex;align-items:center;gap:8px}
footer{color:var(--muted);text-align:center;padding:20px;font-size:12px}
.hidden{display:none!important}
.flash{animation:flash 1.4s ease}
@keyframes flash{0%,40%{box-shadow:0 0 0 3px var(--accent)}100%{box-shadow:var(--shadow)}}
.score{font-size:14px;color:var(--muted)}.score b{font-size:22px;color:var(--fg);margin-right:2px}
.sbar{flex:0 1 160px;min-width:80px;height:8px;border-radius:4px;background:var(--chip);overflow:hidden}
.sbar i,.mini i{display:block;height:100%;background:var(--good);border-radius:inherit}
.erows{display:flex;flex-direction:column;gap:6px}
.erow{border:1px solid var(--line);border-radius:10px}
.erow>summary{display:flex;align-items:center;gap:10px;padding:6px 10px;cursor:pointer;list-style:none}
.erow>summary::-webkit-details-marker{display:none}
.erow .chev{color:var(--accent);transform:rotate(-90deg);transition:transform .15s;margin-left:6px}.erow[open] .chev{transform:none}
.est{width:30px;height:30px;border-radius:50%;display:grid;place-items:center;flex:none;background:var(--chip);color:var(--faint)}
.est svg.i{width:18px;height:18px}.est.sm{width:22px;height:22px}.est.sm svg.i{width:13px;height:13px}
.est.ok{background:color-mix(in srgb,var(--good) 18%,var(--card));color:var(--good)}
.est.no{background:var(--crit-soft);color:var(--crit)}.est.own{background:var(--warn-soft);color:var(--warn-text)}
.ecode{font-size:12px;color:var(--faint);width:22px;flex:none}.eico{color:var(--muted);display:inline-flex}
.etitle{flex:1 1 auto;min-width:0;font-weight:600}.erow.ok .etitle{color:var(--muted)}
.mini{width:70px;height:6px;border-radius:3px;background:var(--chip);overflow:hidden;flex:none}
.frac{font-size:12px;color:var(--muted);min-width:34px;text-align:right}
.ebody{display:flex;flex-wrap:wrap;gap:6px;align-items:center;padding:2px 12px 10px 74px}
.ebody a.pc{text-decoration:none;font-family:inherit}.ebody>div{flex-basis:100%}
.edevs{display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center}
.edevs .who{display:inline-flex;align-items:center;gap:6px;border:0;background:none;padding:0;cursor:pointer;font:inherit;font-weight:600;color:inherit}
.edevs button.who:hover{color:var(--accent)}
.enote{display:flex;gap:6px;align-items:flex-start;font-size:12px;color:var(--muted)}
@media (max-width:560px){.ebody{padding-left:12px}.mini{display:none}.gfilters{grid-template-columns:repeat(3,1fr);gap:10px}.gf .badge{top:5px;right:5px;min-width:24px;
height:24px;line-height:24px;font-size:13px}.wrap{padding:12px}
.scheme{flex-direction:column;align-items:stretch}.sn,.sn.dev{width:auto;flex-direction:row;text-align:left;gap:10px}
.sn small{margin-left:auto}.snc{width:44px;height:44px}.snc svg.i{width:26px;height:26px}
.sl{flex-direction:row;padding:0 0 0 10px;gap:8px;min-height:34px}.sl svg.i{width:26px;transform:rotate(90deg)}
.sl.l svg.i{transform:rotate(-90deg)}.dbody{padding-left:14px}.tarr{display:none}.kpis{grid-template-columns:1fr 1fr}.grid{grid-template-columns:1fr}
main.list .thead{grid-template-columns:auto 1fr auto;grid-template-areas:"icon main side" "marks marks marks"}}
/* веб-интерфейс (python -m lanmap serve): кнопки вместо команд; в статическом отчёте скрыты */
.live-only{display:none!important}.live .live-only{display:inline-flex!important}.live .static-only{display:none!important}
.lv{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:8px}
.sbtn{display:inline-flex;align-items:center;gap:6px;font:inherit;font-size:13px;font-weight:600;padding:7px 11px;border-radius:10px;
 border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
.sbtn:hover{border-color:var(--accent);color:var(--accent)}
.sbtn.on{background:var(--accent);border-color:var(--accent);color:#fff}
.sbtn.on.good{background:var(--good);border-color:var(--good)}.sbtn.on.crit{background:var(--crit);border-color:var(--crit)}
.sbtn.save{background:var(--accent);border-color:var(--accent);color:#fff}
.lv input{font:inherit;font-size:13px;padding:7px 10px;border-radius:10px;border:1px solid var(--line);background:var(--card);
 color:var(--fg);min-width:0;flex:1 1 170px}
.lv input:focus{outline:2px solid var(--accent);outline-offset:-1px}
.signf input{flex:1 1 150px}
.snapf{margin-top:8px}.snapf img{display:block;max-width:100%;max-height:60vh;border-radius:10px;border:1px solid var(--line)}
.snapf form.lv input{flex:1 1 140px}.snapf .msg{font-size:13px;margin:6px 0 0}.snapf .msg.err{color:var(--crit)}
.act.sign{border-color:var(--accent);color:var(--accent);font-weight:600}
.busy{opacity:.6;pointer-events:none}
.scanbtn.busy svg{animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.scanst{font-size:12px;color:var(--muted);max-width:42ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.scanst.crit{color:var(--crit)}
.toast{position:fixed;left:50%;bottom:20px;transform:translate(-50%,20px);background:var(--crit);color:#fff;padding:10px 16px;
 border-radius:12px;opacity:0;pointer-events:none;transition:.2s;z-index:50;max-width:90vw;font-size:14px}
.toast.on{opacity:1;transform:translate(-50%,0)}
/* настройка: база производителей, вход в роутер, паспорт роутера */
dialog.setupdlg{border:0;border-radius:16px;padding:0;background:var(--bg);color:var(--fg);width:min(640px,calc(100vw - 32px));
 max-height:calc(100vh - 32px);box-shadow:0 20px 60px rgba(0,0,0,.35)}
dialog.setupdlg::backdrop{background:rgba(0,0,0,.45)}
.setupdlg .dh{display:flex;align-items:center;gap:10px;padding:14px 16px 0}.setupdlg .dh h2{margin:0;font-size:18px;flex:1;
 display:flex;align-items:center;gap:8px}
.setup{display:grid;gap:10px;padding:14px 16px 16px}
.sx{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px 14px}
.sxhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sxico{display:grid;place-items:center;width:40px;height:40px;border-radius:12px;background:var(--chip);color:var(--muted);flex:none}
.sxico svg.i{width:24px;height:24px}
.sx.ok .sxico{background:color-mix(in srgb,var(--good) 16%,transparent);color:var(--good)}
.sx.warn .sxico{background:var(--warn-soft);color:var(--warn)}
.sxhead b{font-size:15px}.sxst{font-size:12px;color:var(--muted)}.sx.ok .sxst{color:var(--good)}.sx.warn .sxst{color:var(--warn-text)}
.sxn{display:grid;place-items:center;width:22px;height:22px;border-radius:50%;background:var(--accent);color:#fff;font-size:12px;font-weight:700}
.sx p{margin:8px 0 0;font-size:13px;color:var(--muted)}
.sx .err{color:var(--crit)}
.sxlogin[hidden]{display:none}.sxlogin p{margin-top:6px}
.sx form.lv input{flex:1 1 140px}
.sx textarea{width:100%;min-height:150px;margin-top:8px;font:12px/1.4 ui-monospace,Consolas,monospace;padding:8px;border-radius:10px;
 border:1px solid var(--line);background:var(--bg);color:var(--fg);resize:vertical}
.shname{display:block;margin-top:8px;font-size:13px;cursor:pointer}.shname input{margin:0 6px 0 0;vertical-align:-2px}
.shname .muted{font-size:12px}
.aires ul{margin:4px 0 0;padding-left:20px;font-size:13px}.airule{white-space:pre-wrap;word-break:break-all;font:11px/1.4 ui-monospace,Consolas,monospace;background:var(--card,transparent);border:1px solid var(--line);border-radius:8px;padding:6px;margin:6px 0 0}
.reads{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px}.reads span{display:inline-flex;align-items:center;gap:3px;font-size:12px;
 padding:2px 8px;border-radius:999px;background:var(--chip)}.reads span.no{color:var(--crit)}
.sbtn.busy svg{animation:spin 1s linear infinite}
a.sbtn{text-decoration:none}
.pillbtn{margin-top:8px}
.first{max-width:680px;margin:6vh auto;padding:0 16px}.first h1{display:flex;align-items:center;gap:10px;font-size:22px}
.first .go{margin:4px 16px 0}.first .sbtn.save{font-size:15px;padding:10px 18px}
/* «Найти устройство» */
.findbtn,.askbtn{border-color:var(--accent);color:var(--accent);font-weight:600}
.quitbtn:hover{border-color:var(--crit);color:var(--crit)}
.bye{position:fixed;inset:0;z-index:60;background:var(--bg);display:grid;place-items:center;text-align:center;padding:16px}
.bye svg.i{width:64px;height:64px;color:var(--muted)}
.bye b{display:block;font-size:22px;margin:12px 0 6px}
.finder{position:fixed;inset:0;z-index:40;background:var(--bg);overflow:auto;padding:16px}
.finder[hidden]{display:none}
.finder .fin{max-width:1200px;margin:0 auto}
.fhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.fhead .spacer{flex:1}
.fhead h2{display:flex;align-items:center;gap:10px;margin:0;font-size:22px}
.fhead h2 svg.i{width:28px;height:28px;color:var(--accent)}
.fpulse{display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--muted)}
.fpulse i{width:10px;height:10px;border-radius:50%;background:var(--good);animation:pulse 2s infinite}
.fpulse.off i{background:var(--faint);animation:none}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(12,163,12,.5)}70%{box-shadow:0 0 0 10px rgba(12,163,12,0)}100%{box-shadow:0 0 0 0 rgba(12,163,12,0)}}
.fhint{display:flex;align-items:center;gap:12px;margin:14px 0;padding:12px 16px;border-radius:14px;background:var(--accent-soft);
 font-size:15px;line-height:1.4}
.fhint svg.i{width:34px;height:34px;color:var(--accent)}
.fnote{display:flex;align-items:center;gap:6px;font-size:12.5px;color:var(--warn);margin:-6px 0 10px}
.fnote[hidden]{display:none}
.fevents{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;min-height:30px}
.fev{display:inline-flex;align-items:center;gap:6px;font-size:13px;padding:5px 10px;border-radius:999px;background:var(--card);
 border:1px solid var(--line)}
.fev time{color:var(--muted);font-variant-numeric:tabular-nums}
.fev.gone{border-color:var(--crit);color:var(--crit)}.fev.back,.fev.new{border-color:var(--good);color:var(--good)}
.fev b{color:var(--fg);font-weight:600}
.fsign{margin-bottom:12px;padding:10px 12px;border:2px solid var(--accent);border-radius:14px;background:var(--card)}
.fsign[hidden]{display:none}
.fsign .lv{margin-top:6px}
.fgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px}
.ft{display:flex;align-items:center;gap:10px;padding:10px;border-radius:14px;background:var(--card);border:2px solid var(--line);
 transition:opacity .3s,border-color .3s}
.ft .ticon{flex:none;width:44px;height:44px}
.ft .ticon svg.i{width:30px;height:30px}
.ft .fmain{min-width:0;flex:1}
.ft .fmain b{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;line-height:1.25}
.ft .fips{display:flex;gap:8px;flex-wrap:wrap;font-size:12px;color:var(--muted);font-family:ui-monospace,Consolas,monospace}
.ft .fips span{display:inline-flex;align-items:center;gap:4px}
.ft .fips i{width:8px;height:8px;border-radius:50%;background:var(--good)}.ft .fips i.off{background:var(--faint)}
.ft.off{opacity:.45}
.ft.gone{border-color:var(--crit);opacity:1}.ft.back,.ft.new{border-color:var(--good)}
.ft .fbadge{flex:none;display:inline-flex;align-items:center;gap:4px;font-size:12px;font-weight:700;padding:3px 8px;border-radius:999px}
.ft.gone .fbadge{background:var(--crit-soft);color:var(--crit)}
.ft.back .fbadge,.ft.new .fbadge{background:var(--chip);color:var(--good)}
.ft .act{flex:none}
.ft.fixed{opacity:.6}
/* карта сети: вид по умолчанию, когда есть данные роутера */
#mapv,.dhead,.tone{display:none}
body.v-map #mapv{display:block}
body.v-map main details.group,body.v-map #expand{display:none}
.mapbox{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;margin-top:6px;
background-image:radial-gradient(var(--line) 1px,transparent 1px);background-size:18px 18px}
.trunk{display:flex;flex-direction:column;align-items:center}
.inet{display:flex;flex-direction:column;align-items:center;gap:6px}
.cloud{display:inline-flex;align-items:center;gap:8px;padding:5px 14px;border-radius:99px;background:var(--chip);border:1px solid var(--line);font-weight:600}
.mdoor{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--crit);background:var(--crit-soft);color:var(--crit);
border-radius:99px;padding:2px 10px;font-size:12.5px;font-weight:600;cursor:pointer}
.wire{width:2px;height:20px;background:var(--line)}
.wire.hot{background:repeating-linear-gradient(var(--crit) 0 5px,transparent 5px 9px)}
.nodes{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:6px;align-items:start;padding:4px 0 2px}
.nodes.gw{display:flex;justify-content:center;padding:0}.nodes.gw .tile{width:min(100%,300px)}
.segs{display:grid;grid-template-columns:minmax(0,2.4fr) minmax(240px,1fr);gap:14px;align-items:start;padding-top:18px;border-top:2px solid var(--line)}
.segs.one{grid-template-columns:1fr}
.side{display:grid;gap:14px;min-width:0}
.segcol{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px;min-width:0}
.segcol.guest{border-style:dashed}.segcol.scan{border-style:dotted}
.seghead{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-weight:600;margin:0 2px 6px}
.seghead .n,.branch .n,.offline .n{color:var(--muted);font-weight:500;font-size:12.5px}
.seghead .hint{flex-basis:100%;font-weight:400;font-size:12px;color:var(--muted);margin-top:-4px}
.seginner{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:4px 12px;align-items:start}
.branch{margin:0 0 6px 6px;padding-left:10px;border-left:2px solid var(--line)}
.branch>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:6px;flex-wrap:wrap;padding:3px 0;font-weight:600;font-size:13px}
.branch>summary::-webkit-details-marker,.offline>summary::-webkit-details-marker{display:none}
.branch>summary .chev{color:var(--muted);transition:transform .15s}
.branch:not([open])>summary .chev{transform:rotate(-90deg)}
.bhint{flex-basis:100%;padding-left:42px;margin-top:-3px;font-size:12px;font-weight:500;color:var(--warn-text)}
.offline{margin-top:12px}
.offline>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:8px;font-weight:600;padding:8px 10px;border-radius:10px;background:var(--chip)}
.offline>summary .muted{font-weight:400;font-size:12.5px}
/* компактная плитка на карте: значок, имя, адрес и один признак; подробности — в боковой панели */
body.v-map #mapv .thead{grid-template-areas:"icon main one";gap:4px 9px;padding:6px 8px}
body.v-map #mapv .tside,body.v-map #mapv .tmarks,body.v-map #mapv .thead .sub{display:none}
body.v-map #mapv .tone{display:flex;grid-area:one;gap:3px;align-items:center}
body.v-map #mapv .ticon{width:38px;height:38px;border-radius:10px}
body.v-map #mapv .ticon svg.i{width:24px;height:24px}
body.v-map #mapv .tmain b{font-size:13.5px}
body.v-map .tile.open{grid-column:auto;outline:3px solid var(--accent);outline-offset:1px}
body.v-map .tile.open .tdetail{position:fixed;z-index:30;top:10px;right:10px;bottom:10px;width:min(460px,calc(100vw - 20px));overflow:auto;
background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:0 12px 40px rgba(0,0,0,.28);padding:0 14px 14px}
body.v-map .tdetail .dhead{display:flex;align-items:center;gap:10px;position:sticky;top:0;z-index:1;background:var(--card);
margin:0 -14px;padding:12px 14px;border-bottom:1px solid var(--line)}
.dhead .ticon{width:46px;height:46px;flex:none}.dhead .ticon svg.i{width:28px;height:28px}
.dhead .tmain{flex:1}.dhead .tmain b{font-size:16px}
@media (min-width:1100px){body.v-map.drawer .wrap{padding-right:490px}}
@media (max-width:1099px){body.v-map .tile.open .tdetail{top:auto;left:0;right:0;bottom:0;width:auto;max-height:75vh;border-radius:16px 16px 0 0}}
@media (max-width:700px){.segs{grid-template-columns:1fr;border-top:0;padding-top:6px}.nodes{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""

JS = r"""
(function(){
const $=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
const store={get(k){try{return localStorage.getItem('lanmap.'+k)}catch(e){return null}},
             set(k,v){try{localStorage.setItem('lanmap.'+k,v)}catch(e){}}};
const main=$('main');
const st={group:'',status:'',changed:false,low:false,q:'',quick:''};

// тема
const theme=store.get('theme');if(theme)document.documentElement.dataset.theme=theme;
$('#theme').addEventListener('click',()=>{const dark=matchMedia('(prefers-color-scheme: dark)').matches;
 const cur=document.documentElement.dataset.theme||(dark?'dark':'light');const next=cur==='dark'?'light':'dark';
 document.documentElement.dataset.theme=next;store.set('theme',next);});

// вид: карта / плитки / список. Плитка в отчёте одна: при смене вида она переезжает между картой и группами,
// поэтому обработчики кнопок и поиск плитки по id работают в любом виде
const tiles=$$('.tile'),hasMap=main.dataset.map==='1';let viewNow='';
function place(v){if(v==='map'){const ss=$$('.nodes[data-slot]',main);tiles.forEach(t=>{const s=ss.find(x=>x.dataset.slot===t.dataset.slot);if(s)s.appendChild(t);});}
 else{const gs=$$('details.group',main);tiles.forEach(t=>{const g=gs.find(x=>x.dataset.g===t.dataset.group);if(g)$('.grid',g).appendChild(t);});}}
function setView(v){if(v==='map'&&!hasMap)v='tiles';
 if(!viewNow||(viewNow==='map')!==(v==='map')){$$('.tile.open').forEach(t=>openTile(t,false));place(v);}
 document.body.classList.toggle('v-map',v==='map');main.classList.toggle('list',v==='list');
 $$('[data-view]').forEach(b=>b.classList.toggle('on',b.dataset.view===v));
 // новый ключ: у прежних отчётов сохранено «плитки», а карта теперь — вид по умолчанию
 const first=!viewNow;viewNow=v;if(!first){store.set('view2',v);apply();}}
$$('[data-view]').forEach(b=>b.addEventListener('click',()=>setView(b.dataset.view)));
setView(store.get('view2')||(hasMap?'map':'tiles'));

// разворот плитки; на карте подробности — боковая панель (на узком экране — снизу), открыта одна
function openTile(t,open){const d=$('.tdetail',t),h=$('.thead',t);
 open=open===undefined?d.hidden:open;
 if(open&&viewNow==='map')$$('.tile.open').forEach(x=>{if(x!==t)openTile(x,false);});
 d.hidden=!open;t.classList.toggle('open',open);h.setAttribute('aria-expanded',open);
 document.body.classList.toggle('drawer',!!$('.tile.open'));}
$$('.tile').forEach(t=>$('.thead',t).addEventListener('click',()=>openTile(t)));
$$('.dclose').forEach(b=>b.addEventListener('click',e=>{e.stopPropagation();const t=b.closest('.tile');openTile(t,false);$('.thead',t).focus();}));
document.addEventListener('keydown',e=>{if(e.key!=='Escape'||viewNow!=='map'||document.querySelector('dialog[open]'))return;
 const f=$('#finder');if(f&&!f.hidden)return;if(e.target.closest&&e.target.closest('.signf,.snapf'))return;
 const t=$('.tile.open');if(t){openTile(t,false);$('.thead',t).focus();}});
$('#expand').addEventListener('click',()=>{const vis=$$('.tile:not(.hidden)');const anyClosed=vis.some(t=>$('.tdetail',t).hidden);
 vis.forEach(t=>openTile(t,anyClosed));$$('details.group').forEach(g=>{if(anyClosed&&g.querySelector('.tile:not(.hidden)'))g.open=true});});

// переход к устройству из панели изменений и пробросов
$$('[data-goto]').forEach(b=>b.addEventListener('click',e=>{e.preventDefault();
 const t=document.getElementById('d-'+b.dataset.goto);if(!t)return;
 st.group='';st.status='';st.changed=false;st.low=false;st.q='';st.quick='';$('#q').value='';sync();
 for(let p=t.parentElement;p;p=p.parentElement)if(p.tagName==='DETAILS')p.open=true;openTile(t,true);
 t.scrollIntoView({behavior:'smooth',block:'center'});t.classList.remove('flash');void t.offsetWidth;t.classList.add('flash');}));

// фильтры
function apply(){const q=st.q.trim().toLowerCase();
 $$('.tile').forEach(t=>{const d=t.dataset;
  const ok=(!st.group||d.group===st.group)&&(!st.status||d.status===st.status)&&(!st.changed||d.changed==='1')
   &&(!st.low||+d.conf<3)&&(!q||d.search.includes(q))&&(!st.quick||(st.quick==='new'?d.new==='1':d.find==='1'));t.classList.toggle('hidden',!ok);});
 $$('details.group').forEach(g=>{const n=$$('.tile:not(.hidden)',g).length;g.classList.toggle('hidden',!n);
  $('.n',g).textContent=n;if(q&&n)g.open=true;});
 // карта: пустые ветки и сегменты прячутся, счётчики — по видимым
 $$('#mapv .branch,#mapv .segcol,#mapv .offline').forEach(c=>{const n=$$('.tile:not(.hidden)',c).length;c.classList.toggle('hidden',!n);
  const s=$(':scope>summary>.n,:scope>.seghead>.n',c);if(s)s.textContent=n;if((q||st.status==='off')&&n&&c.tagName==='DETAILS')c.open=true;});
 $$('.tile.open.hidden').forEach(t=>openTile(t,false));
 $('#empty').classList.toggle('hidden',!!$('.tile:not(.hidden)'));}
function sync(){$$('.gf').forEach(b=>b.classList.toggle('on',b.dataset.group===st.group));
 $('.gfilters').classList.toggle('picked',!!st.group);
 $$('button[data-status]').forEach(b=>b.classList.toggle('on',b.dataset.status===st.status));
 const c=$('#f-changed');if(c)c.classList.toggle('on',st.changed);$('#f-low').classList.toggle('on',st.low);
 $$('[data-quick]').forEach(b=>b.classList.toggle('on',b.dataset.quick===st.quick));
 // на «Ещё» — сколько скрытых фильтров включено, чтобы фильтр не забылся
 const n=(st.group?1:0)+(st.status?1:0)+(st.changed?1:0)+(st.low?1:0),mb=$('.mbadge');if(mb){mb.hidden=!n;mb.textContent=n;}
 apply();}
$$('[data-quick]').forEach(b=>b.addEventListener('click',()=>{st.quick=b.dataset.quick;sync();}));
$$('.gf').forEach(b=>b.addEventListener('click',()=>{st.group=st.group===b.dataset.group?'':b.dataset.group;sync();}));
$$('button[data-status]').forEach(b=>b.addEventListener('click',()=>{st.status=b.dataset.status;sync();}));
const fc=$('#f-changed');if(fc)fc.addEventListener('click',()=>{st.changed=!st.changed;sync();});
$('#f-low').addEventListener('click',()=>{st.low=!st.low;sync();});
$('#q').addEventListener('input',e=>{st.q=e.target.value;apply();});
$$('[data-kpi]').forEach(b=>b.addEventListener('click',()=>{const k=b.dataset.kpi;
 if(k==='online'){st.status='on';sync();$('.bar').scrollIntoView({behavior:'smooth'});}
 else if(k==='new'){st.quick='new';sync();$('.bar').scrollIntoView({behavior:'smooth'});}
 else if(k==='all'){st.group='';st.status='';st.changed=false;st.low=false;st.quick='';sync();}
 else{const p=document.getElementById(k);if(!p)return;
  // главная находка: раскрыть «Безопасность» и показать её карточку
  const t=(b.dataset.sec&&document.getElementById('sec-'+b.dataset.sec))||p;
  for(let x=t;x;x=x.parentElement)if(x.tagName==='DETAILS')x.open=true;
  t.scrollIntoView({behavior:'smooth',block:'start'});t.classList.remove('flash');void t.offsetWidth;t.classList.add('flash');}}));

// копирование
$$('[data-copy]').forEach(b=>b.addEventListener('click',async e=>{e.stopPropagation();const v=b.dataset.copy;
 try{await navigator.clipboard.writeText(v)}catch(err){const a=document.createElement('textarea');a.value=v;document.body.appendChild(a);
 a.select();document.execCommand('copy');a.remove()}const l=$('.lbl',b),old=l.textContent;l.textContent='✓';setTimeout(()=>l.textContent=old,1100);}));

// «Помочь опознать»: обезличенный текст собран при сборке отчёта (lanmap/share.py), работает и без сервера
const NEW_ISSUE='https://github.com/padrefalcon2011-code/lanMap/issues/new';
let shdlg=null;
function shareOpen(d,title){
 const sico=n=>`<svg class="i s" aria-hidden="true"><use href="#i-${n}"/></svg>`;
 const sesc=t=>String(t??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
 if(!shdlg){shdlg=document.createElement('dialog');shdlg.className='setupdlg';document.body.appendChild(shdlg);
  shdlg.addEventListener('click',e=>{if(e.target===shdlg)shdlg.close();});}
 shdlg.innerHTML=`<div class="dh"><h2>${sico('question')}Помочь опознать</h2><button class="iconbtn" data-close title="Закрыть">${sico('x')}</button></div>
 <div class="setup"><section class="sx"><div class="sxhead"><b>${sesc(title)}</b><span class="sxst">${sesc(d.lanmap)}</span></div>
  <p>Знаешь, что это за устройство? Отправь заявку: LanMap научится его узнавать — у тебя и у других.
   IP, MAC, подписи, имена сетей и серийные номера сюда не попадают. Проверь текст перед отправкой.</p>
  ${d.names?`<label class="shname"><input type="checkbox" data-names> Добавить имя, которое устройство сообщает сети
   <span class="muted">— часто это лучшая улика, но в нём бывает имя человека</span></label>`:''}
  <textarea data-text></textarea>
  <div class="lv"><button class="sbtn" data-shcopy>${sico('copy')}<span>Копировать</span></button>
   <a class="sbtn" data-issue target="_blank" rel="noopener noreferrer">${sico('open')}<span>Открыть заявку на GitHub</span></a></div>
  <p class="shhint muted"></p></section></div>`;
 const ta=$('[data-text]',shdlg),cb=$('[data-names]',shdlg),a=$('[data-issue]',shdlg),hint=$('.shhint',shdlg);
 const build=()=>{ta.value=d.text+(cb&&cb.checked?'\n'+d.names:'');link();};
 const link=()=>{const q=new URLSearchParams({template:'device-identification.yml',lanmap:d.lanmap,evidence:ta.value});
  const url=NEW_ISSUE+'?'+q.toString(),long=url.length>7500;
  a.href=long?NEW_ISSUE+'?'+new URLSearchParams({template:'device-identification.yml',lanmap:d.lanmap}):url;
  hint.textContent=long?'Текст длинный для ссылки: скопируй его и вставь в поле «Улики» в заявке.'
   :'Заявка откроется с уже заполненными уликами. Останется написать, что это на самом деле.';};
 build();ta.addEventListener('input',link);if(cb)cb.addEventListener('change',build);
 $('[data-close]',shdlg).addEventListener('click',()=>shdlg.close());
 $('[data-shcopy]',shdlg).addEventListener('click',async ev=>{const l=$('span',ev.currentTarget);
  try{await navigator.clipboard.writeText(ta.value);}catch(e){ta.select();document.execCommand('copy');}
  l.textContent='✓ скопировано';setTimeout(()=>l.textContent='Копировать',1500);});
 shdlg.showModal();}
$$('[data-share]').forEach(b=>b.addEventListener('click',e=>{e.stopPropagation();const t=b.closest('.tile');
 const n=t&&$('.tmain b',t);shareOpen(JSON.parse(b.dataset.share),n?n.textContent:'');}));

// «Разобрать с ИИ» (lanmap/aiparse.py): промт = общий шаблон страницы + улики из «Помочь опознать» той же плитки.
// Никуда не отправляется: владелец копирует его в свой ИИ. В веб-интерфейсе ответ ИИ можно вставить обратно.
function aiOpen(b){
 const sico=n=>`<svg class="i s" aria-hidden="true"><use href="#i-${n}"/></svg>`;
 const sesc=t=>String(t??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
 const t=b.closest('.tile'),sb=t&&$('[data-share]',t),n=t&&$('.tmain b',t);if(!sb)return;
 const d=JSON.parse(sb.dataset.share),tpl=JSON.parse($('#aiprompt').textContent).prompt,key=b.dataset.ai,L=window.LANMAP;
 if(!shdlg){shdlg=document.createElement('dialog');shdlg.className='setupdlg';document.body.appendChild(shdlg);
  shdlg.addEventListener('click',e=>{if(e.target===shdlg)shdlg.close();});}
 shdlg.innerHTML=`<div class="dh"><h2>${sico('bot')}Разобрать с ИИ</h2><button class="iconbtn" data-close title="Закрыть">${sico('x')}</button></div>
 <div class="setup"><section class="sx"><div class="sxhead"><b>${sesc(n?n.textContent:'')}</b><span class="sxst">${sesc(d.lanmap)}</span></div>
  <p><b>1. Скопируй промт в свой ИИ</b> — хватит обычного чата: ChatGPT, Claude, GigaChat, DeepSeek. Агенту с доступом
   к компьютеру лучше не давать: в уликах строки, которые прислали устройства сети. IP, MAC, подписей и имён в тексте нет — проверь перед отправкой.</p>
  ${d.names?`<label class="shname"><input type="checkbox" data-names> Добавить имя, которое устройство сообщает сети
   <span class="muted">— часто это лучшая улика, но в нём бывает имя человека</span></label>`:''}
  <textarea data-text></textarea>
  <div class="lv"><button class="sbtn" data-shcopy>${sico('copy')}<span>Копировать промт</span></button></div>
  ${L?`<p><b>2. Вставь ответ ИИ</b> — LanMap проверит его и покажет, что запишет. Без твоего «Принять» ничего не пишется.</p>
  <textarea data-answer placeholder="ответ ИИ целиком, с блоком json"></textarea>
  <div class="lv"><button class="sbtn" data-aicheck>${sico('check')}<span>Проверить ответ</span></button></div>
  <div class="aires"></div>`:`<p class="muted">Ответ ИИ можно вставить обратно в веб-интерфейсе (python -m lanmap serve): тип и модель уйдут в реестр, правило — в базу опознания.</p>`}
 </section></div>`;
 const ta=$('[data-text]',shdlg),cb=$('[data-names]',shdlg);
 // замена функцией: «$&» в уликах — не шаблон; «===» → «==», как aiparse.fence_safe: ограду улик не закрыть
 const build=()=>{ta.value=tpl.replace('{evidence}',()=>(d.text+(cb&&cb.checked?'\n'+d.names:'')).replace(/={3,}/g,'=='));};
 build();if(cb)cb.addEventListener('change',build);
 $('[data-close]',shdlg).addEventListener('click',()=>shdlg.close());
 $('[data-shcopy]',shdlg).addEventListener('click',async ev=>{const l=$('span',ev.currentTarget);
  try{await navigator.clipboard.writeText(ta.value);}catch(e){ta.select();document.execCommand('copy');}
  l.textContent='✓ скопировано — вставь в ИИ';setTimeout(()=>l.textContent='Копировать промт',2500);});
 if(L){
  const ans=$('[data-answer]',shdlg),res=$('.aires',shdlg),chk=$('[data-aicheck]',shdlg);
  const post=async(path,body)=>{let r;
   try{r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-LanMap-Token':L.token},body:JSON.stringify(body)});}
   catch(e){throw new Error('Сервер LanMap не отвечает: окно serve закрыто?');}
   const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||('ошибка '+r.status));return j;};
  chk.addEventListener('click',async()=>{chk.classList.add('busy');
   try{const j=await post('/api/ai/check',{key,answer:ans.value});
    const what=[j.vendor,j.model].filter(Boolean).join(' ');
    const rule=j.rule?`<p><b>Правило</b> (${sesc(j.rule.why)}): ${j.rule_others.length
      ?`<span class="err">подходит ещё к ${j.rule_others.length}: ${sesc(j.rule_others.slice(0,8).join(', '))}${j.rule_others.length>8?'…':''}</span> — проверь, что это такие же устройства`
      :'подходит только к этому устройству'}.</p><pre class="airule">${sesc(JSON.stringify(j.rule.if_any?{if:j.rule.if,if_any:j.rule.if_any,if_not:j.rule.if_not,then:j.rule.then}:{if:j.rule.if,if_not:j.rule.if_not,then:j.rule.then}))}</pre>`
     :j.rule_error?`<p class="err">Правило не годится: ${sesc(j.rule_error)}</p>`:'';
    res.innerHTML=`<p><b>${sesc(j.type_label||'тип не назван')}</b>${what?' · '+sesc(what):''} · уверенность ИИ: ${sesc(j.confidence_label)}</p>
     <p>${sesc(j.explanation)}</p>${j.checks.length?'<p><b>Что ещё проверить:</b></p><ul>'+j.checks.map(c=>`<li>${sesc(c)}</li>`).join('')+'</ul>':''}${rule}
     ${j.can_sign?`<label class="shname"><input type="checkbox" data-reg checked> Записать тип и модель в реестр — как подпись владельца</label>
      ${Object.entries(j.replaces).map(([k,[was,now]])=>`<p class="err">${sesc({type:'тип',vendor:'производитель',model:'модель'}[k])} в реестре сейчас «${sesc(was)}» — станет «${sesc(now)}»</p>`).join('')}`
      :'<p class="muted">MAC неизвестен — в реестр не записать, только правило.</p>'}
     ${j.rule?'<label class="shname"><input type="checkbox" data-rule checked> Сохранить правило — дальше LanMap узнает такие устройства сам</label>':''}
     <div class="lv"><button class="sbtn save" data-apply>${sico('check')}<span>Принять</span></button></div>`;
    $('[data-apply]',res).addEventListener('click',async ev=>{const btn=ev.currentTarget;btn.classList.add('busy');
     try{await post('/api/ai/apply',{key,answer:ans.value,registry:!!($('[data-reg]',res)||{}).checked,rule:!!($('[data-rule]',res)||{}).checked});
      try{sessionStorage.setItem('lanmap.back',JSON.stringify({y:scrollY,id:b.dataset.id}))}catch(e){}location.reload();}
     catch(e){btn.classList.remove('busy');res.insertAdjacentHTML('beforeend',`<p class="err">${sesc(e.message)}</p>`);}});}
   catch(e){res.innerHTML=`<p class="err">${sesc(e.message)}</p>`;}
   finally{chk.classList.remove('busy');}});}
 shdlg.showModal();}
$$('[data-ai]').forEach(b=>b.addEventListener('click',e=>{e.stopPropagation();aiOpen(b);}));

// «Спросить ИИ»: обезличенный текст всего отчёта (lanmap/askai.py), только копирование — никуда не отправляется
const askBtn=$('#askai');
if(askBtn)askBtn.addEventListener('click',()=>{
 const sico=n=>`<svg class="i s" aria-hidden="true"><use href="#i-${n}"/></svg>`;
 if(!shdlg){shdlg=document.createElement('dialog');shdlg.className='setupdlg';document.body.appendChild(shdlg);
  shdlg.addEventListener('click',e=>{if(e.target===shdlg)shdlg.close();});}
 shdlg.innerHTML=`<div class="dh"><h2>${sico('bot')}Спросить ИИ</h2><button class="iconbtn" data-close title="Закрыть">${sico('x')}</button></div>
 <div class="setup"><section class="sx">
  <p><b>Скопируй текст и вставь в чат с ИИ</b> — ChatGPT, Claude, GigaChat, Алиса. Он объяснит, что из находок
   опасно на самом деле, что чинить первым и как — по шагам для твоих моделей.</p>
  <p>Адреса, MAC, имена и подписи заменены метками У1, У2… — ИИ видит устройства и связи между ними, но не твою сеть.
   Пробегись глазами перед отправкой. Это список слабых мест сети: для чата с ИИ годится, а на открытый форум — лучше после исправления.</p>
  <textarea data-text></textarea>
  <div class="lv"><button class="sbtn save" data-shcopy>${sico('copy')}<span>Копировать</span></button>
   <span class="muted" data-size></span></div></section></div>`;
 const ta=$('[data-text]',shdlg);ta.value=JSON.parse(askBtn.dataset.askai).text;
 $('[data-size]',shdlg).textContent=`${ta.value.split('\n').length} строк`;
 $('[data-close]',shdlg).addEventListener('click',()=>shdlg.close());
 $('[data-shcopy]',shdlg).addEventListener('click',async ev=>{const l=$('span',ev.currentTarget);
  try{await navigator.clipboard.writeText(ta.value);}catch(e){ta.select();document.execCommand('copy');}
  l.textContent='✓ скопировано — вставь в чат';setTimeout(()=>l.textContent='Копировать',2500);});
 shdlg.showModal();});

// всплывающие заметки: закрывать по клику мимо
document.addEventListener('click',e=>{$$('details.more[open]').forEach(d=>{if(!d.contains(e.target))d.open=false;});});
sync();

// веб-интерфейс (python -m lanmap serve): кнопки вместо команд. Без сервера (файл отчёта) ничего не делает.
const L=window.LANMAP;
if(L){
 document.body.classList.add('live');
 const ico=n=>`<svg class="i s" aria-hidden="true"><use href="#i-${n}"/></svg>`;
 const esc=t=>String(t).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
 function toast(msg){let t=$('#toast');if(!t){t=document.createElement('div');t.id='toast';t.className='toast';
  t.setAttribute('role','alert');document.body.appendChild(t);}
  t.textContent=msg;t.classList.add('on');clearTimeout(t._h);t._h=setTimeout(()=>t.classList.remove('on'),6000);}
 async function api(path,body,el){if(el)el.classList.add('busy');
  try{const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-LanMap-Token':L.token},
   body:JSON.stringify(body)});const j=await r.json().catch(()=>({}));
   if(!r.ok)throw new Error(j.error||('ошибка '+r.status));return j;}
  catch(err){toast(err.message==='Failed to fetch'?'Сервер LanMap не отвечает: окно serve закрыто?':err.message);throw err;}
  finally{if(el)el.classList.remove('busy');}}
 // после записи страница перезагружается с новым отчётом: вернуть прокрутку и раскрыть то, с чем работали
 function back(id){try{sessionStorage.setItem('lanmap.back',JSON.stringify({y:scrollY,id}))}catch(e){}location.reload();}

 // находка: статус кнопками + причина
 const FS=[['open','alert','открыта','crit'],['in_progress','wrench','в работе',''],['fixed','check','исправлена','good'],
  ['accepted','eye','оставляю','' ],['na','minus','не применимо','']];
 $$('[data-finding]').forEach(c=>{const d=JSON.parse(c.dataset.finding);
  c.className='lv';
  c.innerHTML=FS.map(([k,i,t,cls])=>`<button class="sbtn ${cls}${d.status===k?' on':''}" data-st="${k}" title="${esc(t)}">${ico(i)}${esc(t)}</button>`).join('')
   +`<input type="text" maxlength="300" placeholder="почему (для «оставляю»)" value="${esc(d.reason)}">`
   +(d.recheck?`<button class="sbtn rc" title="Проверить по сети ещё раз только эту находку">${ico('refresh')}перепроверить</button>`:'');
  const inp=$('input',c),rc=$('.rc',c);
  if(rc)rc.addEventListener('click',async()=>{rc.lastChild.textContent='проверяю…';
   try{await api('/api/recheck',{check:d.check,key:d.key},c);back(c.dataset.id);}
   catch(e){rc.lastChild.textContent='перепроверить';}});
  $$('[data-st]',c).forEach(b=>b.addEventListener('click',async()=>{
   try{await api('/api/finding',{check:d.check,key:d.key,status:b.dataset.st,reason:inp.value},c);back(c.dataset.id);}catch(e){}}));});

 // E6, E8: сделано / не сделано + заметка
 $$('[data-mark]').forEach(c=>{const d=JSON.parse(c.dataset.mark);
  c.className='lv';
  c.innerHTML=`<button class="sbtn good${d.done?' on':''}" data-st="done">${ico('check')}сделано</button>`
   +`<button class="sbtn${d.done?'':' on'}" data-st="open">${ico('x')}не сделано</button>`
   +`<input type="text" maxlength="300" placeholder="что сделал" value="${esc(d.note)}">`;
  const inp=$('input',c);
  $$('[data-st]',c).forEach(b=>b.addEventListener('click',async()=>{
   try{await api('/api/check',{code:d.code,status:b.dataset.st,note:inp.value},c);back(c.dataset.id);}catch(e){}}));});

 // подписать устройство: название, место, чьё
 $$('[data-sign]').forEach(b=>b.addEventListener('click',ev=>{ev.stopPropagation();
  const acts=b.closest('.acts');let f=acts.nextElementSibling;
  if(f&&f.classList.contains('signf')){f.remove();return;}
  const d=JSON.parse(b.dataset.sign);f=document.createElement('div');f.className='lv signf';
  f.innerHTML=`<input name="name" maxlength="120" placeholder="название: камера над калиткой" value="${esc(d.name)}">`
   +`<input name="place" maxlength="120" placeholder="где стоит" value="${esc(d.place)}">`
   +`<input name="owner" maxlength="120" placeholder="чьё" value="${esc(d.owner)}">`
   +`<button class="sbtn save">${ico('check')}сохранить</button><button class="sbtn" data-x>${ico('x')}</button>`;
  acts.after(f);const first=$('input',f);first.focus();first.select();
  const save=async()=>{const fields={};$$('input',f).forEach(i=>fields[i.name]=i.value.trim());
   if(!fields.name){toast('Нужно название');first.focus();return;}
   try{await api('/api/sign',{key:d.key,fields},f);back(b.dataset.id);}catch(e){}};
  $('.save',f).addEventListener('click',save);$('[data-x]',f).addEventListener('click',()=>f.remove());
  f.addEventListener('keydown',e=>{if(e.key==='Enter')save();if(e.key==='Escape')f.remove();});}));

 // стоп-кадр камеры по ONVIF: кадр только в памяти страницы; пароль — в диспетчер учётных данных Windows
 async function snapCall(what,body){let r;
  try{r=await fetch('/api/camera/'+what,{method:'POST',headers:{'Content-Type':'application/json','X-LanMap-Token':L.token},
   body:JSON.stringify(body)});}catch(e){throw new Error('Сервер LanMap не отвечает: окно serve закрыто?');}
  const j=await r.json().catch(()=>({}));if(!r.ok)throw Object.assign(new Error(j.error||('ошибка '+r.status)),{need:!!j.need_login});return j;}
 $$('[data-snap]').forEach(b=>b.addEventListener('click',ev=>{ev.stopPropagation();
  const acts=b.closest('.acts');let f=acts.parentNode.querySelector('.snapf');
  if(f){f.remove();return;}
  const key=b.dataset.snap;f=document.createElement('div');f.className='snapf';acts.after(f);
  const msg=(t,err)=>`<p class="msg${err?' err':' muted'}">${esc(t)}</p>`;
  const show=j=>{f.innerHTML=`<img alt="стоп-кадр камеры" src="data:image/jpeg;base64,${j.image}">`
    +`<div class="lv"><button class="sbtn" data-again>${ico('refresh')}ещё кадр</button>`
    +`<button class="sbtn" data-forget>${ico('x')}забыть пароль</button></div>`;
   $('[data-again]',f).addEventListener('click',take);
   $('[data-forget]',f).addEventListener('click',async()=>{if(!confirm('Забыть пароль этой камеры?'))return;
    try{await snapCall('forget',{key});f.remove();toast('Пароль камеры удалён');}catch(e){toast(e.message);}});};
  const login=text=>{f.innerHTML=`<form class="lv" autocomplete="on"><input name="user" autocomplete="username" placeholder="логин камеры" maxlength="200" required>`
    +`<input name="password" type="password" autocomplete="current-password" placeholder="пароль" maxlength="500" required>`
    +`<button class="sbtn save" type="submit">${ico('camera')}<span>Кадр</span></button></form>`
    +msg(text||'Пароль хранится в диспетчере учётных данных Windows. Лучше отдельный пользователь камеры только для просмотра.',!!text);
   const form=$('form',f);form.user.focus();
   form.addEventListener('submit',async e=>{e.preventDefault();const btn=$('button',form),pw=form.password;btn.classList.add('busy');
    try{const j=await snapCall('login',{key,user:form.user.value.trim(),password:pw.value});pw.value='';show(j);}
    catch(err){pw.value='';btn.classList.remove('busy');$('.msg',f).outerHTML=msg(err.message,true);pw.focus();}});};
  async function take(){const img=$('img',f);if(img)img.style.opacity=.5;else f.innerHTML=msg('беру кадр…');
   try{show(await snapCall('snapshot',{key}));}
   catch(e){if(e.need)login(/не сохранён/.test(e.message)?'':e.message);else f.innerHTML=msg(e.message,true);}}
  take();}));

 // запуск программ из карточки (lanmap/launch.py): уходят только ключ устройства и имя действия, команду строит сервер
 async function launchCall(body){let r;
  try{r=await fetch('/api/launch',{method:'POST',headers:{'Content-Type':'application/json','X-LanMap-Token':L.token},
   body:JSON.stringify(body)});}catch(e){throw new Error('Сервер LanMap не отвечает: окно serve закрыто?');}
  const j=await r.json().catch(()=>({}));if(!r.ok)throw Object.assign(new Error(j.error||('ошибка '+r.status)),{url:j.url,ack:!!j.need_ack});
  return j;}
 $$('[data-launch]').forEach(b=>b.addEventListener('click',async ev=>{ev.stopPropagation();
  const d=JSON.parse(b.dataset.launch);b.classList.add('busy');
  try{let j;
   try{j=await launchCall(d);}
   catch(e){if(!e.ack)throw e;  // Telnet: сначала предупреждение, запуск — только после согласия
    if(!confirm(e.message+'\n\nВсё равно открыть Telnet?'))return;
    j=await launchCall({...d,ack:true});}
   toast(j.message);}
  catch(e){if(e.url){try{await navigator.clipboard.writeText(e.url)}catch(_){}}toast(e.message);}
  finally{b.classList.remove('busy');}}));

 // новый срез: запуск и ход
 const sb=$('#scan'),ss=$('#scanst');let scanning=false;
 async function poll(){let j;
  try{const r=await fetch('/api/scan',{headers:{'X-LanMap-Token':L.token}});j=await r.json();}
  catch(e){ss.hidden=false;ss.className='scanst crit';ss.textContent='сервер не отвечает';sb.classList.remove('busy');return;}
  if(j.running){scanning=true;sb.classList.add('busy');ss.hidden=false;ss.className='scanst';
   ss.textContent=j.stages.length?j.stages[j.stages.length-1]:'начинаю…';ss.title=ss.textContent;setTimeout(poll,1500);return;}
  sb.classList.remove('busy');
  if(j.error){ss.hidden=false;ss.className='scanst crit';ss.textContent='срез не удался: '+j.error;ss.title=j.error;}
  else if(scanning&&j.snapshot){try{sessionStorage.removeItem('lanmap.back')}catch(e){}scrollTo(0,0);location.reload();}}
 if(sb)sb.addEventListener('click',async()=>{try{await api('/api/scan',{},sb);}catch(e){}scanning=true;poll();});
 poll();

 // «Найти устройство»: живой список — выключил устройство, и видно, какая плитка погасла
 const fb=$('#find');let fbox=null,ftimer=null,fdata=null;const RECENT=180;
 const FKIND={gone:['x','погасло'],back:['check','появилось'],new:['plus','новое']};
 const fmt=t=>new Date(t*1000).toLocaleTimeString('ru-RU');
 function tileOf(key){return document.getElementById('d-'+key);}
 function fTitle(d){const t=tileOf(d.key);const b=t&&t.querySelector('.tmain b');return b?b.textContent:d.title;}
 function fIcon(d){const t=tileOf(d.key);const i=t&&t.querySelector('.ticon');
  if(i){const c=i.cloneNode(true);const dot=c.querySelector('.dot');if(dot)dot.remove();return c.outerHTML;}
  return `<span class="ticon">${ico('question')}</span>`;}
 function fOpen(){if(!fbox){fbox=document.createElement('div');fbox.className='finder';fbox.id='finder';
   fbox.innerHTML=`<div class="fin"><div class="fhead"><h2>${ico('search')}Найти устройство</h2>
    <span class="fpulse off"><i></i><span>запускаю…</span></span><span class="spacer"></span>
    <button class="iconbtn" data-close title="Закрыть">${ico('x')}</button></div>
    <div class="fhint">${ico('power')}<span>Выключи устройство или Wi-Fi на телефоне — его плитка <b>погаснет</b> и всплывёт наверх.
     Включи обратно — <b>загорится</b>. Так видно, какое оно, и его можно сразу подписать или ${ico('question')} помочь опознать.</span></div>
    <div class="fnote" hidden>${ico('info')}<span></span></div>
    <div class="fsign" hidden></div><div class="fevents"></div><div class="fgrid"></div></div>`;
   document.body.appendChild(fbox);$('[data-close]',fbox).addEventListener('click',fClose);
   document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!fbox.hidden&&$('.fsign',fbox).hidden
    &&!document.querySelector('dialog[open]'))fClose();});}
  fbox.hidden=false;document.body.style.overflow='hidden';try{sessionStorage.setItem('lanmap.finder','1')}catch(e){}
  api('/api/watch',{}).then(()=>fPoll()).catch(()=>{});}
 function fClose(){fbox.hidden=true;document.body.style.overflow='';clearTimeout(ftimer);
  try{sessionStorage.removeItem('lanmap.finder')}catch(e){}
  fetch('/api/watch',{method:'POST',headers:{'Content-Type':'application/json','X-LanMap-Token':L.token},body:'{"stop":true}'});}
 async function fPoll(){clearTimeout(ftimer);if(!fbox||fbox.hidden)return;
  try{const r=await fetch('/api/watch',{headers:{'X-LanMap-Token':L.token}});fdata=await r.json();fRender();}
  catch(e){const p=$('.fpulse',fbox);p.className='fpulse off';$('span',p).textContent='сервер не отвечает';}
  if(fdata&&fdata.status==='stopped'&&!fdata.error){api('/api/watch',{}).catch(()=>{});}
  ftimer=setTimeout(fPoll,1000);}
 function fRender(){const d=fdata,p=$('.fpulse',fbox);
  const on=d.status==='running';p.className='fpulse'+(on?'':' off');
  $('span',p).textContent=d.error?('ошибка: '+d.error):on?`опрос каждые ${d.interval} с`:'запускаю…';
  const note=$('.fnote',fbox);note.hidden=!d.router;if(d.router)$('span',note).textContent=
   d.router.startsWith('роутер не ответил')?d.router:`Без роутера (${d.router}): спящий телефон может казаться выключенным.`;
  if(!d.devices)return;
  const now=d.now,devs=d.devices.map((x,i)=>({...x,i,recent:x.changed_at&&now-x.changed_at<RECENT}));
  devs.sort((a,b)=>(b.recent?b.changed_at:0)-(a.recent?a.changed_at:0)||(a.fixed-b.fixed)||(b.alive-a.alive)||(a.i-b.i));
  $('.fevents',fbox).innerHTML=(d.events||[]).slice(0,8).map(e=>{const [i,t]=FKIND[e.kind];
   return `<span class="fev ${e.kind}">${ico(i)}<time>${fmt(e.t)}</time>${t}: <b>${esc(fTitle(e))}</b></span>`;}).join('')
   ||`<span class="fev"><time>${fmt(now)}</time>пока без изменений</span>`;
  $('.fgrid',fbox).innerHTML=devs.map(x=>{const cls=['ft',x.alive?'':'off',x.recent?x.change:'',x.fixed?'fixed':''].join(' ');
   const ips=Object.entries(x.ips).map(([ip,a])=>`<span><i class="${a?'':'off'}"></i>${esc(ip)}</span>`).join('');
   const badge=x.recent?`<span class="fbadge">${ico(FKIND[x.change][0])}${FKIND[x.change][1]}</span>`:'';
   const sign=x.mac&&(x.recent||x.new)?`<button class="act sign" data-fsign="${esc(x.key)}" title="Подписать">${ico('pencil')}</button>`:'';
   const help=(x.recent||x.new)&&fShare(x)?`<button class="act" data-fshare="${esc(x.key)}" title="Помочь опознать: обезличенный рассказ для заявки на GitHub">${ico('question')}</button>`:'';
   return `<div class="${cls}">${fIcon(x)}<div class="fmain"><b>${esc(fTitle(x))}</b><div class="fips">${ips}</div></div>${badge}${help}${sign}</div>`;}).join('');
  $$('[data-fsign]',fbox).forEach(b=>b.addEventListener('click',()=>fSign(devs.find(x=>x.key===b.dataset.fsign))));
  $$('[data-fshare]',fbox).forEach(b=>b.addEventListener('click',()=>{const x=devs.find(v=>v.key===b.dataset.fshare);
   shareOpen(fShare(x),fTitle(x));}));}
 // данные «Помочь опознать»: у устройства из среза — из его плитки, у нового — что собрал сервер (OUI и роутер)
 function fShare(x){const t=tileOf(x.key);const b=t&&t.querySelector('[data-share]');return b?JSON.parse(b.dataset.share):x.share||null;}
 function fSign(x){const box=$('.fsign',fbox);const t=tileOf(x.key);const pre=t&&t.querySelector('[data-sign]');
  const d=pre?JSON.parse(pre.dataset.sign):{key:x.key,name:'',place:'',owner:''};
  box.innerHTML=`<b>${ico('pencil')} ${esc(fTitle(x))}</b><div class="lv signf">
   <input name="name" maxlength="120" placeholder="название: камера над калиткой" value="${esc(d.name)}">
   <input name="place" maxlength="120" placeholder="где стоит" value="${esc(d.place)}">
   <input name="owner" maxlength="120" placeholder="чьё" value="${esc(d.owner)}">
   <button class="sbtn save">${ico('check')}сохранить</button><button class="sbtn" data-x>${ico('x')}</button></div>`;
  box.hidden=false;const first=$('input',box);first.focus();first.select();
  const save=async()=>{const fields={};$$('input',box).forEach(i=>fields[i.name]=i.value.trim());
   if(!fields.name){toast('Нужно название');first.focus();return;}
   try{await api('/api/sign',{key:x.key,fields},box);back(null);}catch(e){}};
  $('.save',box).addEventListener('click',save);$('[data-x]',box).addEventListener('click',()=>{box.hidden=true;});
  box.onkeydown=e=>{if(e.key==='Enter')save();if(e.key==='Escape'){box.hidden=true;e.stopPropagation();}};}
 if(fb)fb.addEventListener('click',fOpen);
 try{if(sessionStorage.getItem('lanmap.finder'))fOpen();}catch(e){}

 // настройка: шестерёнка в шапке и кнопки в плашках «нет базы IEEE», «роутер недоступен»
 const sg=$('#setup');if(sg&&window.lanmapSetup)sg.addEventListener('click',()=>window.lanmapSetup.open());
 $$('[data-setup]').forEach(b=>b.addEventListener('click',e=>{e.preventDefault();window.lanmapSetup&&window.lanmapSetup.open();}));

 // выключить: сервер останавливается, вкладка закрывается (если браузер разрешит — иначе подсказка)
 const qb=$('#quit');
 if(qb)qb.addEventListener('click',async()=>{if(!confirm('Выключить LanMap?'))return;
  try{await api('/api/shutdown',{},qb);}catch(e){return;}
  clearTimeout(ftimer);fbox=null;try{sessionStorage.removeItem('lanmap.finder')}catch(e){}
  const bye=document.createElement('div');bye.className='bye';
  bye.innerHTML=`<div>${ico('power')}<b>LanMap выключен</b><span class="muted">Эту вкладку можно закрыть. Запустить снова — LanMap.bat</span></div>`;
  document.body.appendChild(bye);setTimeout(()=>window.close(),300);});

 // вернуть прокрутку и раскрыть то, с чем работали
 let bk=null;try{bk=JSON.parse(sessionStorage.getItem('lanmap.back')||'null');sessionStorage.removeItem('lanmap.back');}catch(e){}
 if(bk){if(bk.id){const el=$$('[data-id]').find(x=>x.dataset.id===bk.id);
   for(let p=el;p;p=p.parentElement){if(p.tagName==='DETAILS')p.open=true;if(p.classList&&p.classList.contains('tile'))openTile(p,true);}}
  scrollTo(0,bk.y||0);}
}
})();
"""


# Настройка (только в веб-интерфейсе): база производителей, вход в роутер, паспорт роутера для заявки.
# Общая для пустой первой страницы (встроена в неё) и отчёта (окно по шестерёнке). Без сервера не запускается.
SETUP_JS = r"""
window.lanmapSetup=(function(){
const L=window.LANMAP;if(!L)return null;
const $=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
const ico=n=>`<svg class="i s" aria-hidden="true"><use href="#i-${n}"/></svg>`;
const esc=t=>String(t??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ISSUE='https://github.com/padrefalcon2011-code/lanMap/issues/new/choose';
async function call(path,body){const o={headers:{'X-LanMap-Token':L.token}};
 if(body!==undefined){o.method='POST';o.headers['Content-Type']='application/json';o.body=JSON.stringify(body);}
 let r;try{r=await fetch(path,o);}catch(e){throw new Error('Сервер LanMap не отвечает: окно LanMap закрыто?');}
 const j=await r.json().catch(()=>({}));if(!r.ok&&!j.running)throw new Error(j.error||('ошибка '+r.status));return j;}
let dirty=false,dlg=null;

function mount(box,numbered){
 const n=i=>numbered?`<span class="sxn">${i}</span>`:'';
 box.classList.add('setup');
 box.innerHTML=`
 <section class="sx" id="st-oui"><div class="sxhead">${n(1)}<span class="sxico">${ico('barcode')}</span><b>База производителей</b>
   <span class="sxst"></span></div>
  <p>По MAC видно, кто сделал устройство. Скачивается весь публичный реестр IEEE (3–6 МБ): твои MAC никуда не уходят.</p>
  <div class="lv"><button class="sbtn" data-oui>${ico('download')}<span>Скачать</span></button><span class="sxmsg"></span></div></section>
 <section class="sx" id="st-router"><div class="sxhead">${n(2)}<span class="sxico">${ico('key')}</span><b>Роутер</b>
   <span class="sxst">ищу…</span></div><div class="sxbody"></div></section>
 <section class="sx" id="st-probe"><div class="sxhead"><span class="sxico">${ico('router')}</span><b>Паспорт роутера</b>
   <span class="sxst"></span></div>
  <p>Для роутера нет модуля? Собери обезличенный паспорт и отправь заявку: модуль добавят. Без пароля, только чтение.</p>
  <div class="lv"><button class="sbtn" data-probe>${ico('search')}<span>Собрать</span></button></div><div class="probeout"></div></section>`;
 ouiInit(box);routerInit(box);probeInit(box);}

// --- база производителей -------------------------------------------------------------------
function ouiShow(box,j){const st=$('#st-oui',box),b=$('[data-oui]',st),msg=$('.sxmsg',st);
 st.className='sx '+(j.available?'ok':'warn');
 $('.sxst',st).textContent=j.available?`есть · ${Number(j.count).toLocaleString('ru-RU')} записей`:'нет';
 $('span',b).textContent=j.running?'скачиваю…':(j.available?'Обновить':'Скачать');b.classList.toggle('busy',!!j.running);
 msg.className='sxmsg '+(j.error?'err':'muted');msg.textContent=j.error||'';}
async function ouiPoll(box,watching){let j;try{j=await call('/api/oui');}catch(e){return;}
 ouiShow(box,j);if(j.running){setTimeout(()=>ouiPoll(box,true),1500);return;}
 if(watching&&!j.error)dirty=true;}
function ouiInit(box){$('[data-oui]',box).addEventListener('click',async()=>{
  try{await call('/api/oui',{});}catch(e){const m=$('#st-oui .sxmsg',box);m.className='sxmsg err';m.textContent=e.message;return;}
  ouiPoll(box,true);});
 ouiPoll(box,false);}

// --- роутер: вход только для чтения, пароль уходит в диспетчер учётных данных Windows -------
function routerShow(box,j,extra){const st=$('#st-router',box),body=$('.sxbody',st);
 if(j.error&&!j.host){st.className='sx warn';$('.sxst',st).textContent='';body.innerHTML=`<p class="err">${esc(j.error)}</p>`;return;}
 if(!j.kind){st.className='sx warn';$('.sxst',st).textContent=`${j.host} · модуля нет`;
  body.innerHTML=`<p>LanMap работает на сканировании, без данных роутера. Помоги добавить модуль: собери паспорт ниже.</p>`;return;}
 const has=!!j.login;st.className='sx '+(has?'ok':'warn');
 $('.sxst',st).textContent=`${j.product||j.kind} · ${j.host}`+(has?` · вход: ${j.login}`:' · вход не настроен');
 body.innerHTML=(has?`<div class="lv"><button class="sbtn" data-relogin>${ico('key')}Войти заново</button>
   <button class="sbtn" data-forget>${ico('x')}Забыть пароль</button></div>`:'')
  +`<div class="sxlogin" ${has?'hidden':''}><form class="lv" autocomplete="on"><input name="user" autocomplete="username" placeholder="логин" maxlength="200" required>
   <input name="password" type="password" autocomplete="current-password" placeholder="пароль" maxlength="500" required>
   <button class="sbtn save" type="submit">${ico('check')}<span>Войти</span></button></form>
  <p>Лучше отдельный пользователь роутера с правами «Веб-конфигуратор» и «Запретить сохранять настройки системы».
   Пароль хранится в диспетчере учётных данных Windows, не в папке LanMap.</p></div><p class="sxmsg"></p>`+(extra||'');
 const form=$('form',body),msg=$('.sxmsg',body);
 $('[data-relogin]',body)?.addEventListener('click',()=>{$('.sxlogin',body).hidden=false;$('input',form).focus();});
 $('[data-forget]',body)?.addEventListener('click',async e=>{if(!confirm('Забыть пароль роутера?'))return;
  try{await call('/api/router/forget',{});routerLoad(box);}catch(err){msg.className='sxmsg err';msg.textContent=err.message;}});
 form.addEventListener('submit',async e=>{e.preventDefault();const btn=$('button',form),pw=form.password;
  btn.classList.add('busy');msg.className='sxmsg muted';msg.textContent='вхожу…';
  try{const r=await call('/api/router/login',{user:form.user.value.trim(),password:pw.value});pw.value='';
   const reads=(r.reads||[]).map(x=>`<span class="${x.ok?'':'no'}" title="${esc(x.path+': '+x.info)}">${ico(x.ok?'check':'x')}${esc(x.name)}</span>`).join('');
   routerShow(box,r,`<p class="muted">Вход проверен. Что роутер даёт прочитать:</p><div class="reads">${reads}</div>
    <p class="muted">Данные роутера появятся в следующем срезе.</p>`);}
  catch(err){pw.value='';msg.className='sxmsg err';msg.textContent=err.message;btn.classList.remove('busy');pw.focus();}});}
async function routerLoad(box){try{routerShow(box,await call('/api/router'));}catch(e){routerShow(box,{error:e.message});}}
function routerInit(box){routerLoad(box);}

// --- паспорт роутера для заявки ------------------------------------------------------------
function probeShow(box,j){const st=$('#st-probe',box),b=$('[data-probe]',st),out=$('.probeout',st);
 b.classList.toggle('busy',!!j.running);$('span',b).textContent=j.running?'собираю… (~10 с)':(j.result?'Собрать заново':'Собрать');
 if(j.error){out.innerHTML=`<p class="err">${esc(j.error)}</p>`;return;}
 if(!j.result){out.innerHTML='';return;}
 st.className='sx ok';
 out.innerHTML=`<textarea readonly>${esc(j.result)}</textarea><div class="lv"><button class="sbtn" data-copy>${ico('copy')}<span>Копировать</span></button>
  <a class="sbtn" href="${ISSUE}" target="_blank" rel="noopener noreferrer">${ico('open')}Открыть заявку на GitHub</a></div>
  <p>IP, MAC и серийные номера вырезаны автоматически. Проверь текст перед отправкой.</p>`;
 $('[data-copy]',out).addEventListener('click',async ev=>{const t=$('textarea',out),l=$('span',ev.currentTarget);
  try{await navigator.clipboard.writeText(t.value);}catch(e){t.select();document.execCommand('copy');}
  l.textContent='✓ скопировано';setTimeout(()=>l.textContent='Копировать',1500);});}
async function probePoll(box){let j;try{j=await call('/api/probe');}catch(e){return;}
 probeShow(box,j);if(j.running)setTimeout(()=>probePoll(box),1500);}
function probeInit(box){$('[data-probe]',box).addEventListener('click',async()=>{
  try{await call('/api/probe',{});}catch(e){$('#st-probe .probeout',box).innerHTML=`<p class="err">${esc(e.message)}</p>`;return;}
  probePoll(box);});
 probePoll(box);}

function open(){if(!dlg){dlg=document.createElement('dialog');dlg.className='setupdlg';
  dlg.innerHTML=`<div class="dh"><h2>${ico('gear')}Настройка</h2><button class="iconbtn" data-close title="Закрыть">${ico('x')}</button></div><div></div>`;
  document.body.appendChild(dlg);$('[data-close]',dlg).addEventListener('click',()=>dlg.close());
  dlg.addEventListener('click',e=>{if(e.target===dlg)dlg.close();});
  dlg.addEventListener('close',()=>{if(dirty){dirty=false;try{sessionStorage.setItem('lanmap.back',JSON.stringify({y:scrollY}))}catch(e){}location.reload();}});}
 mount(dlg.lastElementChild,false);dlg.showModal();}
return {mount,open};
})();
"""
