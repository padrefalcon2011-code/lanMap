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
<symbol id="i-undo" viewBox="0 0 24 24"><path d="M9 14 4 9l5-5"/><path d="M4 9h11a5 5 0 0 1 0 10h-3"/></symbol>
<symbol id="i-cash" viewBox="0 0 24 24"><rect x="2.5" y="6" width="19" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M6 9.5v0.01M18 14.5v0.01"/></symbol>
<symbol id="i-bot" viewBox="0 0 24 24"><rect x="5" y="8" width="14" height="11" rx="3"/><path d="M12 8V4.5M12 4.5h0.01M9.5 13v1M14.5 13v1M2.5 12.5v3M21.5 12.5v3"/></symbol>
<symbol id="i-power" viewBox="0 0 24 24"><path d="M12 3v8"/><path d="M6.6 6.6a8 8 0 1 0 10.8 0"/></symbol>
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
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 system-ui,"Segoe UI",sans-serif}
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
.pills{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
details.pill{position:relative}
details.pill>summary{list-style:none;display:inline-flex;align-items:center;gap:5px;font-size:12px;padding:3px 9px;border-radius:999px;
background:var(--chip);cursor:pointer;color:var(--muted)}
details.pill>summary::-webkit-details-marker{display:none}
details.pill.warn>summary{background:var(--warn-soft);color:var(--warn)}
details.pill>div{position:absolute;z-index:20;top:28px;left:0;width:min(360px,80vw);background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:10px 12px;box-shadow:0 8px 24px rgba(0,0,0,.15);font-size:13px}
/* показатели */
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin:14px 0}
.kpi{display:flex;align-items:center;gap:10px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px 12px;
box-shadow:var(--shadow);text-align:left;cursor:default}
button.kpi{cursor:pointer}button.kpi:hover{border-color:var(--accent)}
.kpi .ico{width:46px;height:46px;border-radius:12px;background:var(--chip);display:grid;place-items:center;flex:none}
.kpi .ico svg.i{width:28px;height:28px}
.ring{width:46px!important;height:46px!important}
.kpi b{display:block;font-size:22px;line-height:1.1}.kpi span.l{color:var(--muted);font-size:12px}
.kpi.crit{border-color:var(--crit)}.kpi.crit .ico{background:var(--crit-soft);color:var(--crit)}
.kpi.add .ico{background:var(--add-soft);color:var(--add)}
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
.flag.warn{color:var(--warn)}.flag.acc{color:var(--accent)}
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
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""

JS = r"""
(function(){
const $=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
const store={get(k){try{return localStorage.getItem('lanmap.'+k)}catch(e){return null}},
             set(k,v){try{localStorage.setItem('lanmap.'+k,v)}catch(e){}}};
const main=$('main');
const st={group:'',status:'',changed:false,low:false,q:''};

// тема
const theme=store.get('theme');if(theme)document.documentElement.dataset.theme=theme;
$('#theme').addEventListener('click',()=>{const dark=matchMedia('(prefers-color-scheme: dark)').matches;
 const cur=document.documentElement.dataset.theme||(dark?'dark':'light');const next=cur==='dark'?'light':'dark';
 document.documentElement.dataset.theme=next;store.set('theme',next);});

// вид плитки / список
function setView(v){main.classList.toggle('list',v==='list');
 $$('[data-view]').forEach(b=>b.classList.toggle('on',b.dataset.view===v));store.set('view',v);}
$$('[data-view]').forEach(b=>b.addEventListener('click',()=>setView(b.dataset.view)));
setView(store.get('view')||'tiles');

// разворот плитки
function openTile(t,open){const d=$('.tdetail',t),h=$('.thead',t);
 open=open===undefined?d.hidden:open;d.hidden=!open;t.classList.toggle('open',open);h.setAttribute('aria-expanded',open);}
$$('.tile').forEach(t=>$('.thead',t).addEventListener('click',()=>openTile(t)));
$('#expand').addEventListener('click',()=>{const vis=$$('.tile:not(.hidden)');const anyClosed=vis.some(t=>$('.tdetail',t).hidden);
 vis.forEach(t=>openTile(t,anyClosed));$$('details.group').forEach(g=>{if(anyClosed&&g.querySelector('.tile:not(.hidden)'))g.open=true});});

// переход к устройству из панели изменений и пробросов
$$('[data-goto]').forEach(b=>b.addEventListener('click',e=>{e.preventDefault();
 const t=document.getElementById('d-'+b.dataset.goto);if(!t)return;
 st.group='';st.status='';st.changed=false;st.low=false;st.q='';$('#q').value='';sync();
 const g=t.closest('details.group');if(g)g.open=true;openTile(t,true);
 t.scrollIntoView({behavior:'smooth',block:'center'});t.classList.remove('flash');void t.offsetWidth;t.classList.add('flash');}));

// фильтры
function apply(){const q=st.q.trim().toLowerCase();
 $$('.tile').forEach(t=>{const d=t.dataset;
  const ok=(!st.group||d.group===st.group)&&(!st.status||d.status===st.status)&&(!st.changed||d.changed==='1')
   &&(!st.low||+d.conf<3)&&(!q||d.search.includes(q));t.classList.toggle('hidden',!ok);});
 $$('details.group').forEach(g=>{const n=$$('.tile:not(.hidden)',g).length;g.classList.toggle('hidden',!n);
  $('.n',g).textContent=n;if(q&&n)g.open=true;});
 $('#empty').classList.toggle('hidden',!!$('.tile:not(.hidden)'));}
function sync(){$$('.gf').forEach(b=>b.classList.toggle('on',b.dataset.group===st.group));
 $('.gfilters').classList.toggle('picked',!!st.group);
 $$('[data-status]').forEach(b=>b.classList.toggle('on',b.dataset.status===st.status));
 const c=$('#f-changed');if(c)c.classList.toggle('on',st.changed);$('#f-low').classList.toggle('on',st.low);apply();}
$$('.gf').forEach(b=>b.addEventListener('click',()=>{st.group=st.group===b.dataset.group?'':b.dataset.group;sync();}));
$$('[data-status]').forEach(b=>b.addEventListener('click',()=>{st.status=b.dataset.status;sync();}));
const fc=$('#f-changed');if(fc)fc.addEventListener('click',()=>{st.changed=!st.changed;sync();});
$('#f-low').addEventListener('click',()=>{st.low=!st.low;sync();});
$('#q').addEventListener('input',e=>{st.q=e.target.value;apply();});
$$('[data-kpi]').forEach(b=>b.addEventListener('click',()=>{const k=b.dataset.kpi;
 if(k==='online'){st.status='on';sync();$('.bar').scrollIntoView({behavior:'smooth'});}
 else if(k==='all'){st.group='';st.status='';st.changed=false;st.low=false;sync();}
 else{const p=document.getElementById(k);if(p){p.open=true;p.scrollIntoView({behavior:'smooth'});}}}));

// копирование
$$('[data-copy]').forEach(b=>b.addEventListener('click',async e=>{e.stopPropagation();const v=b.dataset.copy;
 try{await navigator.clipboard.writeText(v)}catch(err){const a=document.createElement('textarea');a.value=v;document.body.appendChild(a);
 a.select();document.execCommand('copy');a.remove()}const l=$('.lbl',b),old=l.textContent;l.textContent='✓';setTimeout(()=>l.textContent=old,1100);}));

// всплывающие заметки: закрывать по клику мимо
document.addEventListener('click',e=>{$$('details.pill[open]').forEach(d=>{if(!d.contains(e.target))d.open=false;});});
sync();
})();
"""
