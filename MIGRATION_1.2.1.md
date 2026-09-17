# Upgrade to SplitWire 1.2.1

No config changes are required.

Replace/add these source files compared with 1.2.0 UI:

- REPLACE `internal/wireguard/client.go`
- ADD `internal/wireguard/client_test.go`
- REPLACE `internal/engine/engine_windows.go`
- REPLACE `internal/engine/engine_other.go`
- REPLACE `internal/browserdisc/discovery.go`
- REPLACE `internal/app/session.go`
- REPLACE `cmd/splitwire/main_windows.go`
- REPLACE `scripts/build.ps1`
- REPLACE `README_RU.md`
- REPLACE `TEST_RESULTS.txt`
- ADD `CHANGELOG_1.2.1.md`
- ADD `MIGRATION_1.2.1.md`

Delete nothing for this upgrade. `CHANGELOG_1.2.0.md` may remain as release history.

For the older console repository (1.1.1), the core stability fix is the same in `internal/wireguard/client.go`, `internal/engine/engine_windows.go`, `internal/engine/engine_other.go`, and `internal/browserdisc/discovery.go`; the UI-only `internal/app/session.go` file does not exist there.
