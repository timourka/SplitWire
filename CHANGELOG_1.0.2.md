# SplitWire 1.0.2

Исправление сценария `learned IPs > 0`, но `tunnel=0` для ChatGPT в Chrome.

Главные изменения:

- основной browser-routing теперь hostname-based через временный локальный PAC + HTTP CONNECT proxy;
- ChatGPT/OpenAI выбирается до HTTPS по имени хоста, а не только по CDN IP;
- локальный proxy разрешает только `DomainContains` и его исходящие TCP-соединения туннелируются по process rule самого SplitWire;
- Windows proxy settings восстанавливаются при нормальном выходе; существующий явный proxy/PAC не перезаписывается;
- добавлен fallback для Chrome Secure DNS/DoH: краткий QUIC->TCP fallback + TLS ClientHello SNI learning;
- pre-existing Chrome TLS connections перезапускаются один раз для hostname discovery;
- первый TCP SYN/UDP datagram теперь получает PID через on-demand `GetExtendedTcpTable/GetExtendedUdpTable`, а не ждёт только WinDivert FLOW event;
- расширен status output для диагностики process/domain/SNI/QUIC;
- добавлены тесты TLS SNI reassembly, PAC generation/proxy endpoint, TCP reset construction и internal proxy policy.
