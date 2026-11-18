"""Иконки типов устройств для отчёта: оригинальные двухтоновые контурные символы SVG."""

DEVICE_ICONS = r"""
<symbol id="i-router" viewBox="0 0 32 32">
  <rect class="d" x="4" y="17" width="24" height="10" rx="3"/>
  <rect x="4" y="17" width="24" height="10" rx="3"/>
  <path d="M8 17 L6 7 M24 17 L26 7 M11 7 Q16 3 21 7 M13.5 10.5 Q16 8.5 18.5 10.5 M8 22 H10 M14 22 H15 M24 27 V29 M8 27 V29"/>
</symbol>
<symbol id="i-network" viewBox="0 0 32 32">
  <rect class="d" x="3" y="14" width="26" height="13" rx="3"/>
  <rect x="3" y="14" width="26" height="13" rx="3"/>
  <path d="M10 6 Q16 1 22 6 M13 9 Q16 6.5 19 9 M7 19 H11 V23 H7 Z M14 19 H18 V23 H14 Z M21 19 H25 V23 H21 Z"/>
</symbol>
<symbol id="i-camera" viewBox="0 0 32 32">
  <path class="d" d="M4 9 L8 6 L27 11 L23 21 L5 16 Z"/>
  <path d="M4 9 L8 6 L27 11 L23 21 L5 16 Z M20 9.2 L16 18.8 M12 18 L10 24 H4 M3 21 V28"/>
  <ellipse cx="22" cy="14.5" rx="1.8" ry="2.6" transform="rotate(22 22 14.5)"/>
</symbol>
<symbol id="i-nas" viewBox="0 0 32 32">
  <rect class="d" x="6" y="4" width="20" height="24" rx="3"/>
  <rect x="6" y="4" width="20" height="24" rx="3"/>
  <rect x="9.5" y="8" width="5" height="15" rx="1.5"/>
  <rect x="17.5" y="8" width="5" height="15" rx="1.5"/>
  <path d="M12 18 V20 M20 18 V20 M11 25.5 H13 M19 25.5 H21"/>
</symbol>
<symbol id="i-tv" viewBox="0 0 32 32">
  <rect class="d" x="3" y="6" width="26" height="18" rx="3"/>
  <rect x="3" y="6" width="26" height="18" rx="3"/>
  <path d="M12 24 L10 28 M20 24 L22 28 M7 11 L10 9 M7 16 L15 9"/>
</symbol>
<symbol id="i-media" viewBox="0 0 32 32">
  <rect class="d" x="4" y="13" width="24" height="14" rx="4"/>
  <rect x="4" y="13" width="24" height="14" rx="4"/>
  <path d="M11 13 V8 Q11 5 14 5 H18 M14 17 L20 20 L14 23 Z M9 27 V29 M23 27 V29"/>
  <rect x="18" y="3" width="7" height="5" rx="1.5"/>
</symbol>
<symbol id="i-speaker" viewBox="0 0 32 32">
  <path class="d" d="M7 8 C7 2 25 2 25 8 V24 C25 30 7 30 7 24 Z"/>
  <path d="M7 8 C7 2 25 2 25 8 V24 C25 30 7 30 7 24 Z"/>
  <path d="M7 8 C7 14 25 14 25 8 M12 19 V21 M16 18 V22 M20 19 V21"/>
  <ellipse cx="16" cy="7.5" rx="2" ry="0.8"/>
</symbol>
<symbol id="i-printer" viewBox="0 0 32 32">
  <path class="d" d="M8 12 H6 Q3 12 3 15 V22 Q3 25 6 25 H8 V20 H24 V25 H26 Q29 25 29 22 V15 Q29 12 26 12 H24 Z"/>
  <rect class="d" x="8" y="20" width="16" height="9" rx="1"/>
  <path d="M8 12 V4 H24 V12 M8 25 H6 Q3 25 3 22 V15 Q3 12 6 12 H26 Q29 12 29 15 V22 Q29 25 26 25 H24"/>
  <rect x="8" y="20" width="16" height="9" rx="1"/>
  <path d="M12 24 H20 M23 16 H25"/>
</symbol>
<symbol id="i-computer" viewBox="0 0 32 32">
  <rect class="d" x="6" y="5" width="20" height="17" rx="2.5"/>
  <rect x="6" y="5" width="20" height="17" rx="2.5"/>
  <path d="M6 22 L3 26 Q2 28 5 28 H27 Q30 28 29 26 L26 22 M13 25 H19 M10 10 L12 8"/>
</symbol>
<symbol id="i-phone" viewBox="0 0 32 32">
  <rect class="d" x="8" y="3" width="16" height="26" rx="4"/>
  <rect x="8" y="3" width="16" height="26" rx="4"/>
  <path d="M13 6 H19 M14 25.5 H18"/>
</symbol>
<symbol id="i-wearable" viewBox="0 0 32 32">
  <path class="d" d="M11 9 L12 3 H20 L21 9 M11 23 L12 29 H20 L21 23 Z"/>
  <rect class="d" x="7" y="9" width="18" height="14" rx="4"/>
  <path d="M11 9 L12 3 H20 L21 9 M11 23 L12 29 H20 L21 23 M25 14 H27 V18 H25"/>
  <rect x="7" y="9" width="18" height="14" rx="4"/>
  <path d="M16 12 V16 L19 18"/>
</symbol>
<symbol id="i-iot" viewBox="0 0 32 32">
  <path class="d" d="M6 14 L16 5 L26 14 V26 Q26 28 24 28 H8 Q6 28 6 26 Z"/>
  <path d="M3 16 L16 4 L29 16 M6 14 V26 Q6 28 8 28 H24 Q26 28 26 26 V14 M11 17 Q16 13 21 17 M13.5 20 Q16 18 18.5 20"/>
  <circle cx="16" cy="23" r="0.9"/>
</symbol>
<symbol id="i-unknown" viewBox="0 0 32 32">
  <rect class="d" x="7" y="4" width="18" height="24" rx="4"/>
  <rect x="7" y="4" width="18" height="24" rx="4"/>
  <path d="M12.5 12 C12.5 7.5 20 7.5 20 12 C20 15 16 15 16 18"/>
  <circle cx="16" cy="22" r="0.9"/>
</symbol>
<symbol id="i-offline" viewBox="0 0 32 32">
  <path class="d" d="M25 4 C19 3 14 8 16 14 C18 20 26 21 29 14 C23 16 19 9 25 4 Z"/>
  <rect class="d" x="4" y="16" width="11" height="12" rx="2.5"/>
  <path d="M25 4 C19 3 14 8 16 14 C18 20 26 21 29 14 C23 16 19 9 25 4 Z"/>
  <rect x="4" y="16" width="11" height="12" rx="2.5"/>
  <path d="M8 24.5 H11"/>
</symbol>
"""
