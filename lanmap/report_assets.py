"""Оформление отчёта: набор иконок (встроенный SVG), стили и скрипт. Без внешних файлов и шрифтов.

Строки сырые (r\"\"\"…\"\"\"): в JS и CSS не должно появиться случайных управляющих символов.
Числа в путях SVG — всегда через пробел и с ведущим нулём (тест-сторож ищет IP-адреса в пакете).
"""

# Иконки 24×24, линия currentColor. Тип устройства → символ i-<тип>.
ICONS = r"""<svg xmlns="http://www.w3.org/2000/svg" style="display:none">
<defs>
<symbol id="i-router" viewBox="0 0 24 24"><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h0.01M10.5 16.5h0.01M8 13 6 5M16 13 18 5"/></symbol>
<symbol id="i-network" viewBox="0 0 24 24"><rect x="2" y="8" width="20" height="8" rx="2"/><path d="M6 12h1M9 12h1M12 12h1M15 12h1M18 12h0.01"/></symbol>
<symbol id="i-camera" viewBox="0 0 24 24"><path d="M2 8 15 5 17 11 4 14z"/><path d="M16.5 8.2 21 7v5l-3.5 0.8"/><path d="M8 13.1 9 18H4M4 15.5v5"/></symbol>
<symbol id="i-nas" viewBox="0 0 24 24"><rect x="5" y="3" width="14" height="18" rx="2"/><path d="M5 9h14M5 15h14M8.5 6h0.01M8.5 12h0.01M8.5 18h0.01"/></symbol>
<symbol id="i-tv" viewBox="0 0 24 24"><rect x="2" y="7" width="20" height="13" rx="2"/><path d="M8 3l4 4 4-4"/></symbol>
<symbol id="i-media" viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="12" rx="2"/><path d="M10 9.5v5l4.5-2.5z"/></symbol>
<symbol id="i-speaker" viewBox="0 0 24 24"><ellipse cx="12" cy="6" rx="6" ry="2.5"/><path d="M6 6v12c0 1.4 2.7 2.5 6 2.5s6-1.1 6-2.5V6M9.5 13h5"/></symbol>
<symbol id="i-printer" viewBox="0 0 24 24"><path d="M7 9V3h10v6"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M7 14h10v7H7z"/></symbol>
<symbol id="i-computer" viewBox="0 0 24 24"><rect x="4" y="5" width="16" height="11" rx="1.5"/><path d="M2 19.5h20"/></symbol>
<symbol id="i-phone" viewBox="0 0 24 24"><rect x="7" y="2" width="10" height="20" rx="2.5"/><path d="M11 18.5h2"/></symbol>
<symbol id="i-wearable" viewBox="0 0 24 24"><rect x="7" y="7" width="10" height="10" rx="3"/><path d="M9 7V3h6v4M9 17v4h6v-4"/></symbol>
<symbol id="i-iot" viewBox="0 0 24 24"><path d="M3 11l9-7 9 7v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/><circle cx="12" cy="14.5" r="2.5"/></symbol>
<symbol id="i-unknown" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.4 2.3c-0.6 0.3-0.9 0.9-0.9 1.5V14M12 17.5h0.01"/></symbol>
<symbol id="i-offline" viewBox="0 0 24 24"><path d="M20 15A8 8 0 1 1 9 4a6 6 0 0 0 11 11z"/></symbol>
<symbol id="i-devices" viewBox="0 0 24 24"><circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5 6.5 17M12 11.5 17.5 17"/></symbol>
<symbol id="i-globe" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/></symbol>
<symbol id="i-arrow" viewBox="0 0 24 24"><path d="M4 12h16M14 6l6 6-6 6"/></symbol>
<symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
<symbol id="i-minus" viewBox="0 0 24 24"><path d="M5 12h14"/></symbol>
<symbol id="i-delta" viewBox="0 0 24 24"><path d="M12 4 3 20h18z"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></symbol>
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
</defs></svg>"""

CSS = r"""
:root{color-scheme:light;--bg:#f3f4f6;--card:#fff;--fg:#1b1f27;--muted:#69707d;--faint:#9aa1ad;--line:#e2e5ea;
--chip:#eef0f4;--accent:#2a78d6;--accent-soft:#e3eefb;--good:#0ca30c;--warn:#b07a00;--warn-soft:#fff4dc;
--crit:#d03b3b;--crit-soft:#fdeceb;--add:#2a78d6;--add-soft:#e3eefb;--shadow:0 1px 2px rgba(16,24,40,.06)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#131518;--card:#1c1f24;
--fg:#e8eaed;--muted:#a0a7b2;--faint:#6f7680;--line:#2d3239;--chip:#262a31;--accent:#3987e5;--accent-soft:#1d2b3d;
--good:#2fbf2f;--warn:#fab219;--warn-soft:#33290f;--crit:#e66767;--crit-soft:#3a1f1f;--add:#6da7ec;--add-soft:#1d2b3d;--shadow:none}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#131518;--card:#1c1f24;--fg:#e8eaed;--muted:#a0a7b2;--faint:#6f7680;
--line:#2d3239;--chip:#262a31;--accent:#3987e5;--accent-soft:#1d2b3d;--good:#2fbf2f;--warn:#fab219;--warn-soft:#33290f;
--crit:#e66767;--crit-soft:#3a1f1f;--add:#6da7ec;--add-soft:#1d2b3d;--shadow:none}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 system-ui,"Segoe UI",sans-serif}
svg.i{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}
svg.i.s{width:14px;height:14px}svg.i.l{width:26px;height:26px}
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
.kpi .ico{width:38px;height:38px;border-radius:10px;background:var(--chip);display:grid;place-items:center;flex:none}
.kpi b{display:block;font-size:22px;line-height:1.1}.kpi span.l{color:var(--muted);font-size:12px}
.kpi.crit{border-color:var(--crit)}.kpi.crit .ico{background:var(--crit-soft);color:var(--crit)}
.kpi.add .ico{background:var(--add-soft);color:var(--add)}
.ring{width:38px;height:38px;flex:none}.ring circle{fill:none;stroke-width:4}
.ring .bg{stroke:var(--chip)}.ring .fg{stroke:var(--accent);stroke-linecap:round;transform:rotate(-90deg);transform-origin:50% 50%}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--good);flex:none}
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
.pc{display:inline-flex;align-items:center;gap:3px;font-size:12px;padding:1px 7px;border-radius:6px;background:var(--chip);
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
.seg{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:var(--card)}
.seg button{border:0;background:transparent;height:30px;padding:0 9px;display:inline-flex;align-items:center;gap:5px;cursor:pointer;color:var(--muted)}
.seg button+button{border-left:1px solid var(--line)}
.seg button.on{background:var(--accent);color:#fff}
.gfilters{display:flex;gap:4px;flex-wrap:wrap;width:100%}
.gf{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--line);background:var(--card);border-radius:999px;
height:30px;padding:0 10px 0 8px;cursor:pointer;color:var(--fg)}
.gf small{color:var(--muted);font-weight:600}
.gf.on{background:var(--accent);border-color:var(--accent);color:#fff}.gf.on small{color:#fff}
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
.ticon{grid-area:icon;position:relative;width:42px;height:42px;border-radius:12px;background:var(--chip);display:grid;place-items:center}
.ticon .dot{position:absolute;right:-2px;bottom:-2px;box-shadow:0 0 0 2px var(--card)}
.tile.off .ticon{opacity:.55}
.tmain{grid-area:main;min-width:0;display:flex;flex-direction:column}
.tmain b{font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tmain .sub{color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tmain .ip{font-size:12px;color:var(--muted)}
.tside{grid-area:side;display:flex;flex-direction:column;align-items:flex-end;gap:6px;color:var(--muted)}
.meter{display:inline-flex;gap:2px}.meter i{width:7px;height:12px;border-radius:2px;background:var(--line)}
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
/* вид «список» */
main.list .grid{grid-template-columns:1fr;gap:4px}
main.list .tile.open{grid-column:auto}
main.list .thead{grid-template-columns:auto minmax(180px,1.4fr) minmax(0,2fr) auto;grid-template-areas:"icon main marks side";padding:6px 10px}
main.list .ticon{width:32px;height:32px;border-radius:9px}
main.list .tside{flex-direction:row;align-items:center}
/* легенда */
.legend{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:6px 14px;font-size:13px}
.legend div{display:flex;align-items:center;gap:8px}
footer{color:var(--muted);text-align:center;padding:20px;font-size:12px}
.hidden{display:none!important}
.flash{animation:flash 1.4s ease}
@keyframes flash{0%,40%{box-shadow:0 0 0 3px var(--accent)}100%{box-shadow:var(--shadow)}}
@media (max-width:560px){.wrap{padding:12px}.kpis{grid-template-columns:1fr 1fr}.grid{grid-template-columns:1fr}
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
