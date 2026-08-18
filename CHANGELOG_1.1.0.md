# SplitWire 1.1.0

- Полностью заменён старый `Processes / BrowserProcesses / DomainContains` на произвольное количество `[Group "..."]`.
- Между группами — OR; внутри группы — `Apps AND (Domains OR Networks)`.
- Добавлены `Apps = *` и `Domains = *`.
- Добавлены строгие wildcard-домены `*.example.com`.
- Добавлен `splitwire.default.conf`: если WireGuard config не содержит SplitWire sections, правила берутся из default-файла рядом с EXE.
- Default policy: Discord+Telegram целиком, ChatGPT/OpenAI только Chrome/Firefox/Edge, YouTube глобально.
- Hostname PAC proxy теперь повторно определяет исходный PID и соблюдает app+domain группу. PAC больше не превращает app-specific домены в глобальные.
- Upstream proxy socket получает явное WireGuard/DIRECT решение до `connect()` и первого SYN.
- Domain IP cache стал group-aware: общий CDN IP не смешивает политики разных групп.
- Application selectors индексируются при старте, поэтому сотни нерелевантных app groups почти не влияют на packet decision hot path.
- Глобальные domain groups не вызывают системное подавление неизвестного QUIC/UDP:443.
- WinDivert asset bootstrap не пытается заменить уже существующий валидный `WinDivert64.sys`, если драйвер загружен и файл занят.
- Обновлены тесты, benchmark, portable build и README с разделом о производительности.
