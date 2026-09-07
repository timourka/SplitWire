# SplitWire 1.2.0

## Native Windows UI

- Консольный интерфейс заменён на native Win32 GUI без стороннего UI framework и без CGO.
- Выбор WireGuard `.conf` через стандартный Windows file dialog.
- Явные кнопки «Подключить» и «Отключить»; закрытие окна полностью останавливает runtime.
- Основной статус подключения: physical interface, endpoint, WireGuard handshake, PAC/hostname mode, WG TX/RX и packet counters.
- Просмотр активных routing groups (`Apps`, `Domains`, `Networks`).
- Live log внутри приложения, открытие `splitwire.log` и очистка только UI-представления.
- Кнопка «Правила» открывает фактически используемый файл правил.

## Runtime refactor

- Startup/shutdown вынесены из `cmd/splitwire` в `internal/app`.
- `Session.Close()` восстанавливает временный PAC до остановки локального hostname proxy.
- Один и тот же runtime можно запускать и останавливать несколько раз за жизнь GUI-процесса.
- Путь к последнему WireGuard config по-прежнему хранится в `last-config.txt`.

## Build

- `scripts/build.ps1` собирает `SplitWire.exe` с `-H=windowsgui`, поэтому отдельное console window не создаётся.
- Сохраняется zero-extra-dependency подход: стандартная библиотека Go + Win32 API, без дополнительных Go modules для UI.
