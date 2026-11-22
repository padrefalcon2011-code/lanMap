# LanMap для разработчика: карта модулей и контракт среза

Короткая карта, где что лежит и какие файлы друг другу обещают модули. Зачем программа и как она думает — в [концепции](CONCEPT.md). Правила работы и подробности каждой функции — в разделе «Статус» [AGENTS.md](../AGENTS.md); здесь их не повторяем, только показываем дорогу.

## Путь данных

```
scan.run_scan ─► data/snapshots/<время>/raw/*.json + meta.json   (сырые улики, сеть только читается)
                         │
build.build   ─► devices.make_model ─► identify.resolve ─► security / checklist / changes / history
                         │
                         └► devices.json + report.html          (пересобираются сколько угодно, без сети)
```

Сбор и разбор разделены: срез пишется один раз и больше не меняется, а опознание, проверки и отчёт строятся из него заново (`python -m lanmap build`). Поэтому новое правило или проверка видны на старых срезах без сканирования.

## Модули

| Слой | Модуль | Что делает |
|---|---|---|
| Вход | `lanmap/cli.py`, `lanmap/__main__.py` | Командная строка `python -m lanmap <команда>` |
| | `lanmap/server.py` | Локальный веб-интерфейс (`serve`): токен, проверка `Host`, API для кнопок отчёта |
| | `lanmap/tray.py` | Значок Windows, меню и уведомления. Сервер запускает по `POST /api/tray` после нажатия «Свернуть в трей» |
| | `lanmap/monitor.py`, `lanmap/monitor_page.py` | Фоновый опрос устройств, история по подсети и MAC шлюза, журнал `/monitor`, настройки `/api/monitor` |
| | `lanmap/ops.py` | Действия владельца, общие для CLI и сервера: подписать, отметить, перепроверить, войти в роутер |
| Сбор | `lanmap/scan.py` | Порядок этапов среза, паспорт полноты (`Passport`), папка среза |
| | `lanmap/netinfo.py` | Сети компьютера, выбор интерфейса (Windows) |
| | `lanmap/collectors/__init__.py` | `ScanContext` (границы подсети), `url_target` — разбор адресов от устройств |
| | `lanmap/collectors/discovery.py` | ping, ARP, таблица соседей, mDNS, SSDP, WS-Discovery |
| | `lanmap/collectors/tcp.py` | Порты и баннеры (HTTP, TLS, RTSP, SSH…) |
| | `lanmap/collectors/protocols.py` | UPnP-описания, ONVIF без пароля, SMB-согласование, имена |
| | `lanmap/collectors/igd.py` | UPnP IGD: список пробросов у шлюза (только чтение) |
| | `lanmap/collectors/onvif.py` | Стоп-кадр и адрес потока камеры, проверка утечки пароля |
| | `lanmap/collectors/windows.py` | Этот компьютер: то, что по сети не видно (клиент SMB1) |
| | `lanmap/collectors/live.py` | Живой опрос для «Найти устройство» |
| | `lanmap/collectors/dnswire.py` | Разбор DNS-пакетов |
| | `lanmap/routers/` | Модули роутеров: `__init__.py` — общий формат и `MODULES`, `keenetic.py`, `probe.py` — паспорт роутера для заявки |
| Разбор | `lanmap/snapshot.py` | Готовность, манифест и «та же сеть» для срезов |
| | `lanmap/devices.py` | Сырые файлы → устройства по MAC |
| | `lanmap/identify.py` | Опознание по правилам `lanmap/fingerprints/rules.json` и `data/fingerprints/*.json` |
| | `lanmap/oui.py` | Производитель по MAC (база IEEE или `manuf` Wireshark) |
| | `lanmap/registry.py` | Подписи владельца (`data/registry.json`) |
| | `lanmap/security.py` | Проверки безопасности (`CHECKS`), статусы находок |
| | `lanmap/recheck.py` | Перепроверка одной находки |
| | `lanmap/checklist.py` | Чек-лист E1–E9 |
| | `lanmap/changes.py`, `lanmap/history.py` | Что изменилось с прошлого среза; календарь наблюдений |
| | `lanmap/forwards.py` | Пробросы портов из всех источников |
| | `lanmap/actions.py`, `lanmap/launch.py`, `lanmap/linktest.py` | Что можно сделать с устройством; запуск программ; тест связи |
| | `lanmap/ports.py` | Список портов и имена служб |
| Отчёт | `lanmap/build.py` | Модель среза → `devices.json` и `report.html` |
| | `lanmap/report.py`, `lanmap/report_assets.py`, `lanmap/report_icons.py` | HTML, стили и JS, значки |
| Обмен | `lanmap/share.py`, `lanmap/anonymize.py` | Обезличенный рассказ об устройстве («Помочь опознать») |
| | `lanmap/askai.py` | Обезличенные промты по всему отчёту и по одному решению (`Advice`, кнопки `data-advice`) |
| | `lanmap/aiparse.py` | Промт для опознания устройства и проверка ответа |
| Общее | `lanmap/util.py` | JSON (`read_json`, `read_state`, `BadJSON`), время, MAC, папка данных |
| | `lanmap/credentials.py` | Пароли в диспетчере учётных данных Windows |
| Сборка | `tools/build_portable.py` | Портативный zip со встраиваемым Python |

## Контракт среза

Папка `data/snapshots/<ГГГГ-ММ-ДД_ЧЧММСС>[_N]/`. Имя занимает сам `mkdir` (`scan.new_snapshot_dir`), порядок — `snapshot.order_key` (`_2` раньше `_10`). Существующая папка не перезаписывается никогда.

**`meta.json`** — пишется в начале среза и ещё раз в конце:

| Поле | Когда | Что |
|---|---|---|
| `lanmap_version`, `started`, `admin`, `hostname`, `interface`, `ports_mode`, `ports_tested` | в начале | Кто, когда и с какими правами снимал; `interface` — подсеть, шлюз, адрес, MAC |
| `finished` | в конце | Срез дошёл до конца. Нет поля — срез прерван |
| `passport` | в конце | Список `{id, status, detail}`: этап из `snapshot.STAGES`, исход `ok` / `partial` / `skipped` / `error` |
| `manifest` | в конце, той же записью, что `finished` | `{"raw/<имя>": {size, sha256}}` — для `snapshot.verify`; в модель не копируется |
| `stages`, `candidates` | в конце | Ход среза по времени; сколько адресов опрошено |

**Завершённый срез** (`snapshot.finished`) = `finished` в `meta.json` и все файлы `snapshot.CORE_RAW` на месте: `ping.json`, `neighbors.json`, `arp.json`, `ports.json`, `probes.json`. Без них срез не годится, поэтому ping, ARP и порты при сбое обрывают срез. Прерванный срез не берётся ни «последним» (`scan.latest_snapshot`), ни базой сравнения (`changes.previous_snapshot`).

**`raw/`** — сырые улики, по файлу на этап:

| Файл | Этап | Нет файла |
|---|---|---|
| `ping.json`, `neighbors.json`, `arp.json`, `ports.json`, `probes.json` | обязательные | срез не завершён |
| `multicast.json`, `wsd.json` | discovery | — |
| `router.json` | router | нет данных роутера |
| `names.json`, `upnp.json`, `smb.json` | names, upnp, smb | меньше улик |
| `upnp_igd.json` | igd | UPnP-пробросы — «нечем проверить» |
| `onvif.json`, `onvif_snapshot.json` | onvif | проверка утечки пароля камеры — «нечем проверить» |
| `windows.json` | windows | клиент SMB1 — «нечем проверить» |

Необязательный этап, который упал, свой файл не пишет (`Passport.guard`): отсутствие файла означает «не знаем», а не «чисто». Новая проверка должна держаться того же правила.

**Производные** — `devices.json` (модель: устройства, проверки, чек-лист, изменения, история) и `report.html` — рядом с `raw/`, если срез лежит в каталоге данных, иначе в `data/external/<имя среза>` (`build.output_dir`). Их можно удалить и собрать заново.

## Каталог данных

`util.data_dir()`: `LANMAP_DATA` → `data/` рядом с программой → `%LOCALAPPDATA%\LanMap\data`. Всё личное — только здесь, в git не попадает.

| Путь | Что | Кто пишет |
|---|---|---|
| `snapshots/` | срезы | `scan` |
| `registry.json` | подписи устройств | `registry.save`, `ops.sign` |
| `findings.json` | статусы находок и итоги перепроверок | `security.set_status`, `security.record_recheck` |
| `checklist.json` | отметки E6, E8 | `checklist.set_mark` |
| `monitor.json` | порог возвращения, пауза, последние наблюдения по сетям и до 250 событий журнала | `monitor.Monitor` |
| `fingerprints/*.json` | свои правила опознания (`ai.json` — из «Разобрать с ИИ») | владелец, `ops.ai_apply` |
| `oui.txt` | база производителей | `oui` |
| `external/` | отчёты по срезам, принесённым извне | `build` |
| `tmp-cert/` | временный PEM при разборе TLS | `collectors/tcp.py` |

Состояние владельца читается через `util.read_state`: испорченный файл копируется рядом как `<имя>.json.broken-<время>` (не `.json`, чтобы копия в `fingerprints/` не стала правилами) и не перезаписывается.

## Куда добавлять

- **Правило опознания** — `lanmap/fingerprints/rules.json`, тест в `tests/test_core.py`, затем `python -m lanmap build`.
- **Проверку безопасности** — запись в `security.CHECKS`; если её можно перепроверить — ветка в `lanmap/recheck.py`.
- **Модуль роутера** — `lanmap/routers/<марка>.py` по порядку из раздела «GitHub и заявки» [AGENTS.md](../AGENTS.md).
- **Новый сырой файл** — этап в `scan.run_scan` через `Passport.guard`, имя этапа в `snapshot.STAGES`, чтение в `devices.build` или `build.make_model`.

## Тесты

`python -m unittest discover -s tests`. Только стандартная библиотека. Адреса — из RFC 5737, MAC — `00:00:5E:00:53:xx`: тест-сторож ловит частные IP и MAC в пакете, даже в докстрингах. Тесты, которые запускают `scan.run_scan`, подменяют `scan.snapshots_dir`; тестовый срез помечается завершённым через `finish_snapshot()` в `tests/test_core.py`.
