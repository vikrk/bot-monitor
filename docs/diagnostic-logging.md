# Автоматические диагностические журналы

Журналирование настраивается при установке управляющего сервера пунктом 1
install.sh и при подключении Linux-сервера через fleetctl. Для системных
настроек требуется SSH-доступ с UID 0, systemd и Python3. На Debian/Ubuntu
установщик добавляет logrotate и python3-yaml. При подключении обычным
пользователем агент работает, но меню явно сообщает, что системные журналы
не настроены; этот факт сохраняется в записи узла.
SSH-роутеры этим Linux-настройщиком не изменяются.

## Что включается

| Компонент | Настройки | Хранение |
|---|---|---|
| journald | постоянное хранение, Storage=persistent, MaxFileSec=1h, SystemMaxUse=1G, RuntimeMaxUse=1G | MaxRetentionSec=72h |
| Xray в 3X-UI | access, error с уровнем info, dnsLog=true; в шаблоне панели и рабочем JSON | 72h |
| Отдельная xray.service | те же параметры в JSON-конфиге | 72h |
| nginx HTTP | JSON: время запроса, код, upstream, connect/header/response time, TLS, cipher и SNI | 72h |
| nginx stream | SNI, TLS, session/connect/first-byte time, объём трафика | 72h |
| Amnezia | journald-драйвер либо отдельный docker logs --follow → journald | политика journald 72h |
| Проверки | последний результат read-only-check.json, история read-only-check.jsonl, включая ошибки | история 72h; последний результат сохраняется |
| AdGuardHome | querylog.enabled=true, querylog.interval=6h, statistics.enabled=true, statistics.interval=6h | заданный интервал 6h |

AdGuard удаляет внутренние данные по своему расписанию: это заданный интервал
хранения, а не гарантия удаления каждой записи в секунду её шестичасового
возраста. DNS upstream, фильтры, правила, клиенты и порты не перенастраиваются.
Неподдерживаемая схема интервалов даёт явную ошибку.

В nginx сохраняются маршруты и существующие журналы; access_log off
заменяется включённым диагностическим журналированием. URL, query string,
Cookie и Authorization в новый HTTP-формат не записываются.
Если нет stream-блока, SNI-прокси не создаётся. Без модуля ssl_preread
SNI/TLS в stream-журнале указаны как "-". Настройщик не включает preread
в маршрутах: настоящее имя появляется там, где preread уже используется.

## Применение и очистка

Активируется rvkomi-log-maintenance.timer. Каждый час он проверяет компоненты,
настраивает журналы для появившихся Xray/nginx/AdGuard/Amnezia, ротирует
файлы и удаляет архивы старше 72h. Отсутствующий компонент отмечается как
not installed; сами панели, прокси и AdGuard вместо пользователя не устанавливаются.

При изменении log-настроек работающая 3X-UI/xray.service перезапускается;
AdGuardHome кратковременно останавливается и запускается. nginx проходит
проверку конфигурации и reload. Повторное применение одинаковых настроек
не перезапускает эти службы. Amnezia-контейнеры не пересоздаются и не
перезапускаются. При первом включении persistent journald перезапускается
его служба и выполняется journalctl --flush.

Ротация каждый час использует отдельный logrotate-конфиг с copytruncate,
позволяя Xray продолжать писать без перезапуска ядра. У copytruncate есть
короткое окно возможной потери строк. Текущие файлы и свежие архивы
сохраняются; резервные копии, базы и querylog AdGuard очиститель не удаляет.
Лимит journald 1 ГБ и свободное место могут сократить историю раньше 72h.
Почасовое выполнение даёт задержку очистки относительно границы 72h.

## Состояние и повторное применение

На управляющем сервере:

    sudo systemctl status rvkomi-log-maintenance.timer
    sudo cat /var/lib/rvkomi-watchdog/diagnostic-logging-status.json
    sudo journalctl -u rvkomi-log-maintenance.service --since today
    sudo rvkomi-logging-setup install --agent-dir /etc/rvkomi-watchdog

На подключённом узле:

    sudo python3 /usr/local/lib/rvkomi-watchdog/configure_logging.py maintain

Файл состояния содержит результаты компонентов и причины ошибок.
Ошибка даёт ненулевой exit code; установщик не объявляет её успехом.
Переподключение через fleetctl повторно применяет настройки; журналы
не обнуляются. Нестандартные расположения или не-JSON конфиг Xray могут
потребовать адаптации и будут отмечены ошибкой.

## Проверки и статус

check выполняет свежую проверку и сохраняет last_check, включая ошибки.
Одновременный запрос возвращает skipped=running, не освежая статус.
status выбирает последнюю завершённую проверку; запрос статуса не меняет
её время. Центральный таймер выполняет check на подключённых узлах,
включая старые SPB/NL-инвентари. Ошибки SSH/RPC сохраняются в центре.
История центра и агента — 72h; последний результат доступен и позже.

Исходные настройки сохраняются в /var/backups/rvkomi-logging/<timestamp>/
с правами root. Копии базы и конфигурации могут содержать секреты:
их нельзя публиковать или отправлять как диагностический журнал.

Параметры журналов описаны в документации
[Xray](https://xtls.github.io/en/config/log.html),
[nginx HTTP](https://nginx.org/en/docs/http/ngx_http_log_module.html)
и [nginx stream](https://nginx.org/en/docs/stream/ngx_stream_log_module.html).
