# SplitWire 1.2.0

SplitWire — переносимый Windows-клиент для выборочного WireGuard-туннелирования без Wintun/TUN-адаптера и без добавления системных маршрутов Windows.

Приложение рассчитано на одновременную работу с другим VPN: корпоративный VPN продолжает управлять обычной маршрутизацией Windows, а SplitWire перехватывает только трафик, который совпал с его правилами, и отправляет его в отдельный WireGuard peer.

**SplitWire не является Windows Service и не создаёт Scheduled Task.** Туннель активен только после нажатия **«Подключить»** и пока работает `SplitWire.exe`. Нажатие **«Отключить»** или закрытие окна восстанавливает временный PAC, закрывает WinDivert handles и полностью выключает SplitWire.

## Быстрый запуск

1. Положите рядом `SplitWire.exe` и `splitwire.default.conf`.
2. Запустите `SplitWire.exe` и подтвердите UAC: права администратора нужны WinDivert.
3. В поле **«Конфиг»** выберите обычный WireGuard `.conf` через **«Обзор…»**.
4. Проверьте загруженные группы слева и нажмите **«Подключить»**.
5. Кнопка **«Отключить»** выключает SplitWire без закрытия приложения.
6. Закрытие окна также гарантированно выключает туннель и восстанавливает временные proxy/PAC settings.

Путь к последнему WireGuard-конфигу сохраняется в `last-config.txt` и подставляется при следующем запуске.

Конфиг можно заранее передать аргументом — UI откроется уже с заполненным путём:

```powershell
.\SplitWire.exe "C:\VPN\my-wireguard.conf"
```

или:

```powershell
.\SplitWire.exe --config "C:\VPN\my-wireguard.conf"
```

При первом подключении SplitWire при необходимости скачивает официальный x64 runtime WinDivert 2.2.2. Собственного kernel-драйвера SplitWire не устанавливает.

## UI

В 1.2.0 консольный интерфейс заменён на небольшое native Win32-окно. В проект не добавлены UI-фреймворки, WebView, CGO или новые runtime-зависимости.

Основные элементы:

- **Конфиг / Обзор…** — выбор WireGuard `.conf`;
- **Правила** — открывает фактически используемый источник правил: `splitwire.default.conf` или WireGuard-конфиг с собственными `[Group]`; изменения применяются при следующем подключении;
- **Подключить / Отключить** — явное управление runtime без Windows Service;
- блок **Состояние** — physical interface, WireGuard endpoint, последний handshake, hostname/PAC mode, WG TX/RX и основные packet counters;
- **Группы маршрутизации** — показывает текущие `Apps`, `Domains` и `Networks`;
- **Лог** — live tail `splitwire.log`; кнопка **«Открыть лог»** открывает файл обычным Windows-приложением, **«Очистить окно»** очищает только UI, не файл.

UI читает статус непосредственно из того же `engine.Runner`, который маршрутизирует трафик. Отдельного фонового helper/service процесса нет.

## WireGuard-конфиг и default config

Обычный WireGuard-конфиг может вообще не содержать настроек SplitWire:

```ini
[Interface]
PrivateKey = <YOUR_PRIVATE_KEY>
Address = 10.66.66.20/32, fd42:42:42::20/128

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
PresharedKey = <OPTIONAL_PSK>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

`AllowedIPs` не превращается в Windows routes. В текущей one-peer реализации он не используется как системная таблица маршрутизации: уже отобранный SplitWire трафик отправляется этому peer.

### Как выбирается источник split-правил

Если WireGuard `.conf` **не содержит** ни `[SplitWire]`, ни `[Group "..."]`, SplitWire загружает правила из:

```text
splitwire.default.conf
```

рядом с `SplitWire.exe`. При запуске из `dist` исходного проекта также проверяется родительская папка, поэтому корневой `splitwire.default.conf` работает во время разработки.

Если в WireGuard `.conf` присутствует `[SplitWire]` **или хотя бы одна `[Group "..."]`**, default-файл **не смешивается** с ним. Все группы из WireGuard-конфига становятся полной политикой. Это специально сделано, чтобы поведение было однозначным.

Старый формат `Processes / BrowserProcesses / DomainContains` в 1.1.x не поддерживается.

## Модель групп

Количество групп программно не ограничено.

Между группами действует **OR**, внутри группы — **AND между приложением и назначением**:

```text
Tunnel = Group1 OR Group2 OR Group3 OR ...

GroupMatch = AppMatches
             AND
             (DomainMatches OR NetworkMatches)
```

`*` означает «любое».

### Пример default config

В проект уже положен такой `splitwire.default.conf`:

```ini
[SplitWire]
MTU = 1380
DNSRefreshSeconds = 60

[Group "Messengers"]
Apps = Discord.exe, Telegram.exe
Domains = *

[Group "AI"]
Apps = chrome.exe, firefox.exe, msedge.exe
Domains = chatgpt.com, *.chatgpt.com, openai.com, *.openai.com, oaistatic.com, *.oaistatic.com, oaiusercontent.com, *.oaiusercontent.com

[Group "YouTube"]
Apps = *
Domains = youtube.com, *.youtube.com, youtu.be, *.googlevideo.com, *.ytimg.com, youtubei.googleapis.com
```

Получается:

```text
Discord.exe / Telegram.exe + любой адрес       -> WireGuard
Chrome/Firefox/Edge + ChatGPT/OpenAI hostname -> WireGuard
любой процесс + YouTube hostname              -> WireGuard
всё остальное                                 -> DIRECT / корпоративный VPN
```

### Правила доменов

Доменное совпадение намеренно строгое:

```text
chatgpt.com     -> только chatgpt.com
*.chatgpt.com   -> a.chatgpt.com, www.chatgpt.com, ...
                   но НЕ сам chatgpt.com
*               -> любой destination
```

Поэтому для корня и поддоменов обычно указываются оба правила:

```ini
Domains = youtube.com, *.youtube.com
```

Поддерживается только `*` целиком и wildcard `*.` в начале имени. Маски вида `chat*gpt.com` считаются ошибкой конфигурации.

### Глобальная группа

```ini
[Group "GitHub everywhere"]
Apps = *
Domains = github.com, *.github.com, *.githubusercontent.com
```

Такой домен будет отправляться через WireGuard независимо от приложения.

### Всё приложение

```ini
[Group "Telegram"]
Apps = Telegram.exe
Domains = *
```

TCP и UDP Telegram будут туннелироваться независимо от назначения.

### Несколько приложений + несколько доменов

```ini
[Group "AI browsers"]
Apps = chrome.exe, firefox.exe, msedge.exe
Domains = chatgpt.com, *.chatgpt.com, claude.ai, *.claude.ai
```

### IP/CIDR внутри группы

`Networks` необязателен и объединяется с `Domains` через OR внутри destination-части группы:

```ini
[Group "Internal tool"]
Apps = tool.exe
Domains = api.example.com, *.api.example.com
Networks = 203.0.113.0/24, 2001:db8:1234::/48
```

То есть `tool.exe` будет туннелироваться при совпадении **домена или сети**.

Глобальные сети:

```ini
[Group "Global networks"]
Apps = *
Networks = 203.0.113.0/24
```

## `[SplitWire]`

В этой секции остаются только общие настройки движка:

```ini
[SplitWire]
PhysicalInterface = Wi-Fi
MTU = 1380
DNSRefreshSeconds = 60
```

`PhysicalInterface` можно не указывать. Тогда SplitWire выбирает активный hardware NIC с IPv4 default gateway. Можно указать alias (`Wi-Fi`, `Ethernet`, `Беспроводная сеть`) или числовой `IfIndex`.


### Исправление 1.1.1: hostname proxy на Windows

В 1.1.0 upstream TCP socket локального hostname proxy ошибочно делал `bind()` внутри `ControlContext`, после чего Go/Windows выполнял второй bind перед `ConnectEx`. На Windows это приводило к `WSAEINVAL` / `bind: An invalid argument was supplied`, поэтому app+domain группы (например Chrome + ChatGPT) могли загружать оболочку страницы, но HTTPS-запросы через proxy падали.

В 1.1.1 SplitWire заранее резервирует ephemeral source port, регистрирует решение `WireGuard`/`DIRECT` до первого SYN, но сам bind оставляет стандартному `net.Dialer`. Повторяющиеся одинаковые ошибки hostname proxy также rate-limit'ятся в логе.

## Как работает доменная фильтрация

У Windows packet layer нет hostname — у пакета есть только IP. Поэтому SplitWire использует несколько источников и сохраняет соответствие `hostname -> IP -> group`.

### 1. Hostname PAC proxy

Для всех конкретных `Domains` (кроме `Domains = *`) SplitWire строит один временный PAC и локальный HTTP CONNECT proxy.

PAC содержит **объединение доменных шаблонов всех групп**, но это не делает правила глобальными. PAC сам не умеет узнать имя процесса, поэтому proxy дополнительно:

1. получает loopback-соединение приложения;
2. определяет PID владельца TCP socket;
3. снова проверяет `Apps AND Domains` для исходного процесса;
4. если группа совпала — upstream TCP socket регистрируется как `WireGuard` **до `connect()` / первого SYN**;
5. если группа не совпала — тот же proxy открывает upstream как явный `DIRECT`.

Благодаря этому одновременно корректны оба случая:

```text
chrome.exe  + chatgpt.com -> WireGuard
notepad.exe + chatgpt.com -> DIRECT

любой процесс + youtube.com -> WireGuard
```

Chrome/Edge и другие программы, которые используют Windows PAC, получают hostname-маршрутизацию до установления HTTPS-соединения. Это также обходит проблему Secure DNS/DoH, когда обычный UDP/53 не виден приложению-фильтру.

Если в Windows уже настроен чужой explicit proxy/PAC, SplitWire его не перезаписывает и переходит на DNS/SNI fallback.

### 2. DNS A/AAAA/CNAME

SplitWire пассивно читает DNS-ответы и запоминает IP **отдельно для каждой группы**. Один и тот же CDN IP может одновременно принадлежать нескольким группам; это не превращает доменные правила одной группы в правила другой.

### 3. TLS SNI fallback

Для TCP/443 SplitWire умеет прочитать TLS ClientHello SNI. Если hostname совпал с группой текущего процесса, IP запоминается и соединение один раз переподключается уже через WireGuard.

Для явно перечисленных приложений с доменными правилами неизвестный QUIC/UDP:443 кратковременно подавляется, чтобы приложение попробовало TCP и hostname стал виден через TLS SNI. **Глобальные `Apps = *` группы намеренно не делают такой QUIC suppression для каждого процесса в системе**, иначе добавление одного глобального домена ухудшало бы весь UDP/443 на машине.

Практическое следствие: глобальные домены наиболее надёжно определяются через PAC или обычный DNS. Нативное приложение, которое одновременно игнорирует Windows PAC, использует собственный DoH и сразу отправляет только QUIC к ранее неизвестному CDN IP, может не быть классифицировано до тех пор, пока этот IP не будет выучен другим способом. Full-app группы (`Domains = *`) этого ограничения не имеют.

## UDP и отсутствие TUN

Для выбранного процесса UDP не превращается в TCP и не проходит через Windows TUN adapter. SplitWire перехватывает исходный IP-пакет WinDivert, выполняет NAT на адрес WireGuard, шифрует его WireGuard data plane и отправляет внешний UDP непосредственно к peer.

UDP source port сохраняется, а при коллизиях выделяется отдельный tunnel-side port с reverse NAT.

Отдельный Wintun/TUN adapter не создаётся, `route add` не выполняется.

## Почему корпоративный VPN не должен забирать WireGuard transport

Внешний UDP socket WireGuard привязывается к выбранному физическому интерфейсу через Windows interface binding. Поэтому сам WireGuard transport не должен переехать на default route корпоративного VPN после его подключения.

Ответный расшифрованный пакет инжектируется обратно с метаданными интерфейса исходного Windows flow. Это важно при одновременном присутствии физического NIC и корпоративного VPN.

## Производительность и зависимость от правил

Главный фактор нагрузки — **packet rate**, а не количество строк в конфиге. WinDivert видит исходящие TCP/UDP пакеты, поэтому базовая работа примерно пропорциональна:

```text
CPU ~= packets_per_second × packet_processing_cost
```

Дальше влияние правил устроено так.

### Количество групп с конкретными `Apps`

Имена приложений индексируются при старте:

```text
exe name/path -> список относящихся к нему групп
```

Поэтому добавление сотен групп для **других** приложений почти не увеличивает стоимость решения для текущего пакета. Hot path проверяет:

```text
глобальные Apps=* группы
+
группы текущего executable
```

а не весь конфиг.

В проекте есть benchmark `BenchmarkDecideIndexedGroups`. На тестовой Linux VM policy-only benchmark для 3, 50 и 500 групп с одной релевантной группой остаётся одного порядка величины (сотни наносекунд на решение); конкретное число на Windows зависит от CPU и не включает WinDivert/NAT/WireGuard crypto.

Запуск:

```powershell
go test .\internal\policy -run '^$' -bench BenchmarkDecideIndexedGroups -benchmem
```

### `Apps = *`

Глобальная группа неизбежно проверяется для любого captured packet. Поэтому именно большое количество глобальных групп влияет на packet hot path сильнее всего.

Условно:

```text
packet decision cost ~ O(global_groups + groups_for_current_app)
```

Внутри релевантной группы `Networks` проверяются последовательно, поэтому очень длинные списки CIDR тоже увеличивают работу пакета.

### Количество `Domains`

Доменный список **не перебирается на каждом обычном пакете**. После того как hostname сопоставлен с IP, packet hot path делает lookup `IP -> group`.

Число доменных шаблонов в основном влияет на более редкие события:

- DNS response;
- новый TLS ClientHello/SNI;
- запрос к локальному hostname proxy;
- выполнение PAC браузером.

Поэтому 100 доменов обычно значительно дешевле, чем 100 глобальных packet-level групп.

### PAC

PAC содержит линейное условие по конкретным доменным шаблонам. Очень большие списки (тысячи/десятки тысяч доменов) уже могут быть заметны на большом количестве browser URL lookups. Для обычных десятков или сотен шаблонов это не является основным bottleneck по сравнению с сетевой обработкой и WireGuard encryption.

### `Domains = *`

Для full-app группы нет DNS/SNI/PAC lookup: после определения процесса пакет сразу подходит по destination. Это самый дешёвый тип сложного правила после `Apps = * / Domains = *`.

### WireGuard crypto

После выбора пакета его стоимость уже почти не зависит от количества правил: NAT/checksum + WireGuard encryption зависят от объёма и packet rate выбранного трафика.

Итого, если важна производительность:

1. можно свободно заводить много групп для разных конкретных приложений;
2. не стоит без необходимости делать сотни `Apps = *` групп;
3. большие доменные списки обычно дешевле больших глобальных CIDR/group списков;
4. основная реальная нагрузка возникает при высоком PPS и большом объёме уже туннелируемого трафика.

## Файлы приложения

Рядом с EXE могут появиться:

- `splitwire.default.conf` — default split policy;
- `WinDivert.dll`;
- `WinDivert64.sys`;
- `WinDivert-LICENSE.txt`;
- `last-config.txt` — только путь к последнему WireGuard `.conf`;
- `splitwire.log` — технический лог без WireGuard private key.

Если удалить `last-config.txt`, следующий запуск снова попросит путь.

SplitWire не пытается перезаписать уже существующий корректный `WinDivert64.sys`: это также позволяет перезапустить/обновить приложение, когда драйвер уже загружен Windows и файл временно занят.

## Статус

Основной статус теперь отображается в окне и обновляется раз в секунду:

```text
состояние runtime / handshake
physical interface / WireGuard endpoint
hostname PAC mode
WG TX / RX
tunnel / bypass / dropped
proxyWG
```

Подробные диагностические счётчики (`captured`, `learnedIPs`, `proc resolved/missed`, `discovery`, `domain`, `sni`, `quicFallback`, `reconnects`, `proxyDirect`) остаются внутри engine и технического лога; UI специально показывает только основные показатели, чтобы не превращаться в dashboard на десятки полей.

`proxyWG` — hostname proxy запросы, которые после проверки исходного процесса были направлены в WireGuard. `proxyDirect` — запросы, попавшие в PAC по домену, но не совпавшие с app+domain группой исходного процесса и поэтому отправленные DIRECT.

## Сборка

На Windows x64 достаточно клонировать репозиторий и запустить:

```powershell
.\scripts\build.ps1
```

Если Go 1.23+ уже есть в `PATH`, скрипт использует его. Если Go отсутствует или слишком старый, `build.ps1` сам скачивает официальный Windows x64 ZIP с `go.dev`, проверяет SHA-256 из официального download API и распаковывает portable toolchain в `.tools\go`. Системная установка Go и изменение `PATH` не требуются. Каталог `.tools` исключён из Git.

Обычная release-сборка выполняет:

```text
go test ./...
go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w -H=windowsgui" ...
```

Race detector намеренно не запускается по умолчанию: на Windows он требует cgo и установленный C compiler. Для dev-проверки, если подходящий mingw-w64/clang уже установлен:

```powershell
.\scripts\build.ps1 -Race
```

После сборки папка `dist` содержит native GUI executable и portable-файлы:

```text
SplitWire.exe
splitwire.default.conf
README_RU.md
THIRD_PARTY_NOTICES.md
CHANGELOG_1.2.0.md
remove-windivert-driver.ps1
```

`SplitWire.exe` собирается как Windows GUI subsystem (`-H=windowsgui`), поэтому рядом не появляется отдельное консольное окно.

Запуск:

```powershell
.\dist\SplitWire.exe
```

или с заранее выбранным конфигом:

```powershell
.\dist\SplitWire.exe "C:\VPN\my-wireguard.conf"
```

## Тесты

```powershell
.\scripts\test.ps1
```

Покрыты:

- fallback `splitwire.default.conf`;
- полный override правилами из WireGuard config;
- неограниченное количество group sections на уровне parser/data structures;
- точные домены и `*.` wildcards;
- OR между группами / AND внутри группы;
- `Apps = *` и `Domains = *`;
- изоляция `IP -> group` при общем CDN IP;
- per-client hostname proxy route decision (`WireGuard`/`DIRECT`);
- pre-connect proxy route table для первого SYN;
- process/flow tracking;
- IPv4/IPv6 packet parsing;
- checksums и TCP MSS clamp;
- NAT/reverse NAT и UDP port collisions;
- DNS parser;
- TLS SNI parser;
- WireGuard handshake/data plane crypto tests.

В `tests` также находится независимый WireGuard interoperability smoke test с Python responder.

## Ограничения

- Windows x64.
- Один WireGuard peer на конфиг.
- Нельзя надёжно определить конкретную вкладку браузера только по network packet; правила задаются по process + hostname.
- Чужой существующий Windows proxy/PAC не перезаписывается.
- Для глобального домена нативное приложение с собственным DoH + QUIC, которое игнорирует системный PAC, может потребовать предварительно выученный destination IP; SplitWire намеренно не ломает неизвестный QUIC глобально.

## Лицензии

Код SplitWire — MIT, см. `LICENSE`.

WinDivert поставляется/скачивается отдельно из официального binary distribution и имеет собственную лицензию. См. `THIRD_PARTY_NOTICES.md` и `WinDivert-LICENSE.txt` после загрузки runtime.
