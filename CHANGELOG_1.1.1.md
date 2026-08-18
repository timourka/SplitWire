# SplitWire 1.1.1

- Исправлен критический regression 1.1.0 в hostname PAC proxy на Windows: удалён двойной `bind()` перед `ConnectEx`, который давал `WSAEINVAL / An invalid argument was supplied`.
- Upstream proxy теперь заранее резервирует ephemeral source port, регистрирует WireGuard/DIRECT route до первого SYN и позволяет Go выполнить единственный bind.
- Добавлен regression test `TestDialProxyRegisteredNoDoubleBind`, который реально устанавливает TCP соединение и проверяет pre-connect route registration.
- Повторяющиеся одинаковые ошибки и успешные hostname-proxy route messages rate-limit'ятся, чтобы `splitwire.log` не разрастался при retry storm.
- Групповая модель, default config и WireGuard dataplane не менялись.
