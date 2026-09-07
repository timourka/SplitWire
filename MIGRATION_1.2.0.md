# Переход текущего репозитория timourka/SplitWire на UI 1.2.0

Основа изменений — текущая структура `main` репозитория `https://github.com/timourka/SplitWire`.

## Удалить

1. `cmd/splitwire/main.go`
   - старый console entry point (`S`/`Q`, stdin/stdout) больше не используется;
   - его функциональность разделена между native GUI и `internal/app`.

2. `default configs/splitwire.default.conf`
   - в репозитории уже есть канонический `splitwire.default.conf` в корне;
   - папка с пробелом создаёт второй экземпляр одних и тех же default rules и не используется runtime/build script.

3. `default configs/`
   - удалить директорию после удаления единственного файла, если она пустая.

## Добавить

1. `cmd/splitwire/main_windows.go`
   - native Windows GUI;
   - выбор WireGuard config;
   - Connect / Disconnect;
   - status;
   - groups;
   - live log;
   - open rules / open log;
   - shutdown cleanup.

2. `cmd/splitwire/main_other.go`
   - небольшой non-Windows stub, чтобы `go test ./...` продолжал собирать весь module на других ОС.

3. `cmd/splitwire/win32_windows.go`
   - минимальные Win32 bindings на стандартной библиотеке Go;
   - User32, Comdlg32, Shell32, Gdi32;
   - без стороннего UI framework и без CGO.

4. `internal/app/session.go`
   - общий lifecycle runtime;
   - загрузка config/default rules;
   - WinDivert assets;
   - physical interface;
   - engine.Runner;
   - hostname proxy + temporary PAC;
   - ordered Stop/Close.

5. `internal/app/session_test.go`
   - тест default-rules inspection;
   - тест `last-config.txt`.

6. `CHANGELOG_1.2.0.md`
   - changelog UI-релиза.

7. `MIGRATION_1.2.0.md`
   - этот файл.

## Заменить содержимое файла на новую версию с тем же именем

1. `scripts/build.ps1`
   - build теперь использует `-H=windowsgui`;
   - в `dist` копируется `CHANGELOG_1.2.0.md`.

2. `README_RU.md`
   - console-инструкция заменена на UI-инструкцию;
   - описаны Connect/Disconnect, status, groups и log;
   - описана сборка GUI subsystem.

3. `TEST_RESULTS.txt`
   - результаты тестов/Windows cross-build для 1.2.0.

## Оставить без изменений

- `go.mod` — новых Go dependencies не появилось;
- `splitwire.default.conf` в корне — остаётся каноническим default config;
- `internal/engine/*` — routing/data-plane не переписывался;
- `internal/browserproxy/*`;
- `internal/config/*`;
- `internal/policy/*`;
- `internal/windivert/*`;
- `internal/wireguard/*`;
- `internal/winutil/*`;
- старые changelog-файлы 1.0.2 / 1.1.0 / 1.1.1 — оставить как историю.

## Итоговая часть дерева

```text
cmd/
  splitwire/
    main_windows.go
    main_other.go
    win32_windows.go

internal/
  app/
    session.go
    session_test.go
  engine/
  browserproxy/
  ...

scripts/
  build.ps1
  test.ps1
  remove-windivert-driver.ps1

splitwire.default.conf
README_RU.md
CHANGELOG_1.2.0.md
TEST_RESULTS.txt
MIGRATION_1.2.0.md
```

## Сборка

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

Готовое приложение:

```text
dist\SplitWire.exe
```

Это GUI executable. Отдельное console window при запуске не создаётся.
