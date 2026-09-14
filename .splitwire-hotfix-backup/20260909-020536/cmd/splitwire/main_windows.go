//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"splitwire/internal/app"
	"splitwire/internal/winutil"
)

const version = "1.2.0"

const (
	idConfigEdit = 1001 + iota
	idBrowse
	idStart
	idStop
	idRules
	idState
	idNetwork
	idHandshake
	idProxy
	idTraffic
	idPackets
	idGroups
	idLog
	idOpenLog
	idClearLog
)

const (
	wmAppLog = wmApp + 1 + iota
	wmAppStartDone
	wmAppStopDone
)

const statusTimerID = 1

var activeGUI *gui

type startResult struct {
	s      *app.Session
	err    error
	cancel context.CancelFunc
}

type gui struct {
	hwnd uintptr
	font uintptr

	configLabel uintptr
	configEdit  uintptr
	browseBtn   uintptr
	startBtn    uintptr
	stopBtn     uintptr
	rulesBtn    uintptr

	stateText     uintptr
	networkText   uintptr
	handshakeText uintptr
	proxyText     uintptr
	trafficText   uintptr
	packetsText   uintptr
	groupsEdit    uintptr
	logEdit       uintptr
	openLogBtn    uintptr
	clearLogBtn   uintptr

	connectionBox uintptr
	groupsBox     uintptr
	logBox        uintptr

	appDir  string
	logPath string
	logger  *log.Logger
	logSink *uiLogSink

	rootCtx    context.Context
	rootCancel context.CancelFunc

	session       *app.Session
	sessionCancel context.CancelFunc
	startCancel   context.CancelFunc
	starting      bool
	stopping      bool
	lastError     string
	startResults  chan startResult
	stopResults   chan error
	closing       bool

	initialConfig string
	initialLog    string
}

func main() {
	runtime.LockOSThread()

	dir, err := winutil.AppDir()
	if err != nil {
		messageBox(0, "SplitWire", err.Error(), mbOK|mbIconError)
		return
	}
	_ = os.Chdir(dir)
	if !winutil.IsAdmin() {
		if err := winutil.RelaunchElevated(); err != nil {
			messageBox(0, "SplitWire", "Не удалось запросить права администратора:\n"+err.Error(), mbOK|mbIconError)
		}
		return
	}

	logPath := filepath.Join(dir, "splitwire.log")
	initialLog := tailFile(logPath, 160<<10)
	lf, err := openLog(logPath)
	if err != nil {
		messageBox(0, "SplitWire", "Не удалось открыть лог:\n"+err.Error(), mbOK|mbIconError)
		return
	}
	defer lf.Close()

	sink := &uiLogSink{}
	logger := log.New(io.MultiWriter(lf, sink), "", log.LstdFlags)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initialConfig := configArg()
	if initialConfig == "" {
		initialConfig = app.LoadLastConfig(dir)
	}

	g := &gui{
		appDir:        dir,
		logPath:       logPath,
		logger:        logger,
		logSink:       sink,
		rootCtx:       ctx,
		rootCancel:    cancel,
		startResults:  make(chan startResult, 1),
		stopResults:   make(chan error, 1),
		initialConfig: initialConfig,
		initialLog:    initialLog,
	}
	activeGUI = g
	defer func() { activeGUI = nil }()

	className := "SplitWireMainWindow"
	cb := syscall.NewCallback(windowProc)
	if err := registerClass(className, cb); err != nil {
		messageBox(0, "SplitWire", err.Error(), mbOK|mbIconError)
		return
	}

	hwnd := createWindow(0, className, "SplitWire "+version, wsOverlappedWindow|wsVisible, cwUseDefault, cwUseDefault, 980, 680, 0, 0)
	if hwnd == 0 {
		messageBox(0, "SplitWire", "CreateWindowExW failed", mbOK|mbIconError)
		return
	}
	g.hwnd = hwnd
	g.logSink.Attach(hwnd)
	showWindow(hwnd)
	setTimer(hwnd, statusTimerID, 1000)
	g.refreshStatus()
	_ = messageLoop()
}

func windowProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	g := activeGUI
	if g == nil {
		return defWindowProc(hwnd, message, wParam, lParam)
	}
	switch message {
	case wmCreate:
		g.hwnd = hwnd
		g.createControls()
		return 0
	case wmSize:
		w, h := sizeFromLParam(lParam)
		g.layout(w, h)
		return 0
	case wmCommand:
		g.command(int(lowWord(wParam)))
		return 0
	case wmTimer:
		if wParam == statusTimerID {
			g.refreshStatus()
		}
		return 0
	case wmAppLog:
		g.drainLog()
		return 0
	case wmAppStartDone:
		g.finishStart()
		return 0
	case wmAppStopDone:
		g.finishStop()
		return 0
	case wmClose:
		g.closeWindow()
		return 0
	case wmDestroy:
		killTimer(hwnd, statusTimerID)
		postQuitMessage(0)
		return 0
	}
	return defWindowProc(hwnd, message, wParam, lParam)
}

func (g *gui) createControls() {
	g.font = stockGUIFont()
	mk := func(class, text string, style uint32, id int) uintptr {
		h := createWindow(0, class, text, style|wsChild|wsVisible, 0, 0, 10, 10, g.hwnd, uintptr(id))
		setFont(h, g.font)
		return h
	}

	// Standard Win32 controls only: no external UI module and no CGO.
	g.configLabel = mk("STATIC", "Конфиг:", 0, 0)
	g.configEdit = mk("EDIT", g.initialConfig, wsBorder|wsTabStop|esAutoHScroll, idConfigEdit)
	g.browseBtn = mk("BUTTON", "Обзор…", bsPushButton|wsTabStop, idBrowse)
	g.startBtn = mk("BUTTON", "Подключить", bsPushButton|wsTabStop, idStart)
	g.stopBtn = mk("BUTTON", "Отключить", bsPushButton|wsTabStop, idStop)
	g.rulesBtn = mk("BUTTON", "Правила", bsPushButton|wsTabStop, idRules)

	g.connectionBox = mk("BUTTON", "Состояние", bsGroupBox, 0)
	g.stateText = mk("STATIC", "Состояние: остановлен", 0, idState)
	g.networkText = mk("STATIC", "Сеть: —", 0, idNetwork)
	g.handshakeText = mk("STATIC", "WireGuard: —", 0, idHandshake)
	g.proxyText = mk("STATIC", "Доменные правила: —", 0, idProxy)
	g.trafficText = mk("STATIC", "Трафик WG: TX 0 B / RX 0 B", 0, idTraffic)
	g.packetsText = mk("STATIC", "Пакеты: 0", 0, idPackets)

	g.groupsBox = mk("BUTTON", "Группы маршрутизации", bsGroupBox, 0)
	g.groupsEdit = mk("EDIT", "Выберите конфиг для просмотра правил.", wsBorder|wsVScroll|wsHScroll|esMultiline|esAutoVScroll|esAutoHScroll|esReadOnly, idGroups)

	g.logBox = mk("BUTTON", "Лог", bsGroupBox, 0)
	g.logEdit = mk("EDIT", normalizeEditNewlines(g.initialLog), wsBorder|wsVScroll|wsHScroll|esMultiline|esAutoVScroll|esAutoHScroll|esReadOnly, idLog)
	scrollEditToEnd(g.logEdit)
	g.openLogBtn = mk("BUTTON", "Открыть лог", bsPushButton|wsTabStop, idOpenLog)
	g.clearLogBtn = mk("BUTTON", "Очистить окно", bsPushButton|wsTabStop, idClearLog)

	enableWindow(g.stopBtn, false)
	if g.initialConfig != "" {
		g.previewConfig(false)
	}
	focus(g.startBtn)
}

func (g *gui) layout(w, h int32) {
	if w < 760 {
		w = 760
	}
	if h < 500 {
		h = 500
	}
	const m int32 = 12
	const gap int32 = 8
	const rowH int32 = 26

	y := m
	moveWindow(g.configLabel, m, y+5, 52, 20)
	buttonsW := int32(96*4 + gap*3)
	editX := m + 58
	editW := w - editX - m - buttonsW - gap
	if editW < 180 {
		editW = 180
	}
	moveWindow(g.configEdit, editX, y, editW, rowH)
	x := editX + editW + gap
	moveWindow(g.browseBtn, x, y, 96, rowH)
	x += 96 + gap
	moveWindow(g.rulesBtn, x, y, 96, rowH)
	x += 96 + gap
	moveWindow(g.startBtn, x, y, 96, rowH)
	x += 96 + gap
	moveWindow(g.stopBtn, x, y, 96, rowH)

	y = 48
	connH := int32(126)
	moveWindow(g.connectionBox, m, y, w-2*m, connH)
	leftX := m + 14
	rightX := w/2 + 4
	colW := w/2 - 30
	moveWindow(g.stateText, leftX, y+24, colW, 20)
	moveWindow(g.networkText, leftX, y+50, colW, 20)
	moveWindow(g.handshakeText, leftX, y+76, colW, 20)
	moveWindow(g.proxyText, rightX, y+24, colW, 20)
	moveWindow(g.trafficText, rightX, y+50, colW, 20)
	moveWindow(g.packetsText, rightX, y+76, colW, 20)

	contentY := y + connH + gap
	contentH := h - contentY - m
	leftW := w * 36 / 100
	if leftW < 300 {
		leftW = 300
	}
	if leftW > 390 {
		leftW = 390
	}
	rightW := w - 3*m - leftW
	moveWindow(g.groupsBox, m, contentY, leftW, contentH)
	moveWindow(g.groupsEdit, m+10, contentY+22, leftW-20, contentH-32)

	logX := 2*m + leftW
	moveWindow(g.logBox, logX, contentY, rightW, contentH)
	btnY := contentY + contentH - 38
	moveWindow(g.logEdit, logX+10, contentY+22, rightW-20, contentH-68)
	moveWindow(g.openLogBtn, logX+10, btnY, 110, rowH)
	moveWindow(g.clearLogBtn, logX+128, btnY, 120, rowH)
}

func (g *gui) command(id int) {
	switch id {
	case idBrowse:
		initial := strings.TrimSpace(getText(g.configEdit))
		if p, ok := openConfigDialog(g.hwnd, initial); ok {
			setText(g.configEdit, p)
			g.lastError = ""
			g.previewConfig(true)
		}
	case idStart:
		g.beginStart()
	case idStop:
		g.beginStop()
	case idRules:
		g.openRules()
	case idOpenLog:
		if err := openTextFile(g.logPath); err != nil {
			messageBox(g.hwnd, "SplitWire", err.Error(), mbOK|mbIconError)
		}
	case idClearLog:
		setText(g.logEdit, "")
	}
}

func (g *gui) previewConfig(showError bool) {
	path := strings.TrimSpace(getText(g.configEdit))
	if path == "" {
		setText(g.groupsEdit, "Выберите WireGuard .conf")
		return
	}
	info, err := app.Inspect(path, g.appDir)
	if err != nil {
		setText(g.groupsEdit, "Ошибка конфигурации:\r\n"+err.Error())
		if showError {
			messageBox(g.hwnd, "SplitWire — конфигурация", err.Error(), mbOK|mbIconError)
		}
		return
	}
	setText(g.groupsEdit, formatGroups(info))
}

func (g *gui) beginStart() {
	if g.starting || g.stopping || g.session != nil {
		return
	}
	path := strings.TrimSpace(getText(g.configEdit))
	if path == "" {
		if p, ok := openConfigDialog(g.hwnd, ""); ok {
			path = p
			setText(g.configEdit, p)
		} else {
			return
		}
	}
	if info, err := app.Inspect(path, g.appDir); err != nil {
		g.lastError = err.Error()
		g.refreshStatus()
		messageBox(g.hwnd, "SplitWire — конфигурация", err.Error(), mbOK|mbIconError)
		return
	} else {
		setText(g.groupsEdit, formatGroups(info))
	}

	g.starting = true
	g.lastError = ""
	enableWindow(g.startBtn, false)
	enableWindow(g.browseBtn, false)
	enableWindow(g.configEdit, false)
	enableWindow(g.stopBtn, true) // Stop also cancels an in-progress start.
	g.refreshStatus()
	g.logger.Printf("UI: starting with config %s", path)

	ctx, cancel := context.WithCancel(g.rootCtx)
	g.startCancel = cancel
	exePath, _ := os.Executable()
	internalName := filepath.Base(exePath)
	go func() {
		s, err := app.Start(ctx, app.Options{
			ConfigPath:        path,
			AppDir:            g.appDir,
			InternalProcesses: []string{internalName},
			Logf:              g.logger.Printf,
		})
		if err != nil {
			cancel()
		}
		if g.rootCtx.Err() != nil && s != nil {
			_ = s.Close()
			cancel()
			s = nil
			if err == nil {
				err = context.Canceled
			}
		}
		g.startResults <- startResult{s: s, err: err, cancel: cancel}
		postMessage(g.hwnd, wmAppStartDone, 0, 0)
	}()
}

func (g *gui) finishStart() {
	var r startResult
	select {
	case r = <-g.startResults:
	default:
		return
	}
	g.starting = false
	g.stopping = false
	g.startCancel = nil
	if r.err != nil {
		cancelled := errors.Is(r.err, context.Canceled)
		if cancelled {
			g.lastError = ""
			g.logger.Printf("UI: start cancelled")
		} else {
			g.lastError = r.err.Error()
			g.logger.Printf("UI: start failed: %v", r.err)
		}
		enableWindow(g.startBtn, true)
		enableWindow(g.browseBtn, true)
		enableWindow(g.configEdit, true)
		enableWindow(g.stopBtn, false)
		if !cancelled {
			messageBox(g.hwnd, "SplitWire — ошибка запуска", r.err.Error(), mbOK|mbIconError)
		}
		g.refreshStatus()
		return
	}
	g.session = r.s
	g.sessionCancel = r.cancel
	g.lastError = ""
	info := r.s.Info()
	setText(g.configEdit, info.ConfigPath)
	setText(g.groupsEdit, formatGroups(info))
	enableWindow(g.stopBtn, true)
	g.logger.Printf("UI: connected; rules=%s", info.RuleSource)
	g.refreshStatus()
}

func (g *gui) beginStop() {
	if g.starting {
		if g.startCancel != nil {
			g.startCancel()
		}
		g.stopping = true
		g.refreshStatus()
		return
	}
	if g.stopping || g.session == nil {
		return
	}
	g.stopping = true
	enableWindow(g.stopBtn, false)
	g.refreshStatus()
	s := g.session
	cancel := g.sessionCancel
	g.logger.Printf("UI: stopping")
	go func() {
		err := s.Close()
		if cancel != nil {
			cancel()
		}
		g.stopResults <- err
		postMessage(g.hwnd, wmAppStopDone, 0, 0)
	}()
}

func (g *gui) finishStop() {
	var err error
	select {
	case err = <-g.stopResults:
	default:
		// A cancelled start reaches finishStart instead of finishStop.
		if g.starting {
			return
		}
	}
	g.session = nil
	g.sessionCancel = nil
	g.stopping = false
	if err != nil {
		g.lastError = err.Error()
		g.logger.Printf("UI: stop completed with error: %v", err)
	} else {
		g.lastError = ""
		g.logger.Printf("UI: stopped")
	}
	enableWindow(g.startBtn, true)
	enableWindow(g.browseBtn, true)
	enableWindow(g.configEdit, true)
	enableWindow(g.stopBtn, false)
	g.refreshStatus()
}

func (g *gui) refreshStatus() {
	if g.stateText == 0 {
		return
	}
	if g.starting {
		setText(g.stateText, "Состояние: запускается…")
		setText(g.handshakeText, "WireGuard: инициализация…")
		return
	}
	if g.stopping {
		setText(g.stateText, "Состояние: отключается…")
		return
	}
	if g.session == nil {
		state := "Состояние: остановлен"
		if g.lastError != "" {
			state = "Состояние: ошибка — " + oneLine(g.lastError, 90)
		}
		setText(g.stateText, state)
		setText(g.networkText, "Сеть: —")
		setText(g.handshakeText, "WireGuard: —")
		setText(g.proxyText, "Доменные правила: —")
		setText(g.trafficText, "Трафик WG: TX 0 B / RX 0 B")
		setText(g.packetsText, "Пакеты: tunnel 0 / bypass 0 / drop 0")
		return
	}

	info := g.session.Info()
	s := g.session.Status()
	if s.LastHandshake.IsZero() {
		setText(g.stateText, "Состояние: работает · handshake ещё не установлен")
		setText(g.handshakeText, "WireGuard: ожидает первый туннельный пакет")
	} else {
		age := time.Since(s.LastHandshake).Round(time.Second)
		if age < 0 {
			age = 0
		}
		if age <= 3*time.Minute {
			setText(g.stateText, "Состояние: подключено")
		} else {
			// An old handshake does not necessarily mean a broken idle tunnel, but
			// it is not enough evidence to claim that the peer is live right now.
			setText(g.stateText, "Состояние: работает · handshake давно не обновлялся")
		}
		setText(g.handshakeText, fmt.Sprintf("WireGuard: OK · %s · %s назад", s.LastHandshake.Format("15:04:05"), age))
	}
	setText(g.networkText, fmt.Sprintf("Сеть: %s · endpoint %s", info.Interface, info.Endpoint))
	setText(g.proxyText, "Доменные правила: "+oneLine(info.HostnameMode, 75))
	setText(g.trafficText, fmt.Sprintf("Трафик WG: TX %s / RX %s", humanBytes(s.WGTxBytes), humanBytes(s.WGRxBytes)))
	setText(g.packetsText, fmt.Sprintf("Пакеты: cap %d / WG %d / direct %d / drop %d · proxyWG %d · IP %d", s.Captured, s.Tunneled, s.Bypassed, s.Dropped, s.ProxyTunnel, s.DomainIPs))
}

func (g *gui) openRules() {
	path := strings.TrimSpace(getText(g.configEdit))
	if path == "" {
		messageBox(g.hwnd, "SplitWire", "Сначала выберите WireGuard config.", mbOK|mbIconInfo)
		return
	}
	info, err := app.Inspect(path, g.appDir)
	if err != nil {
		messageBox(g.hwnd, "SplitWire", err.Error(), mbOK|mbIconError)
		return
	}
	if err := openTextFile(info.RuleSource); err != nil {
		messageBox(g.hwnd, "SplitWire", err.Error(), mbOK|mbIconError)
	}
}

func (g *gui) closeWindow() {
	if g.closing {
		return
	}
	g.closing = true
	if g.startCancel != nil {
		g.startCancel()
	}
	if g.session != nil {
		// Session.Close restores the temporary PAC before it shuts down the
		// local proxy. Cancel its parent only after that ordered cleanup.
		_ = g.session.Close()
		if g.sessionCancel != nil {
			g.sessionCancel()
		}
	}
	g.rootCancel()
	destroyWindow(g.hwnd)
}

func formatGroups(info app.Info) string {
	var b strings.Builder
	if info.RuleSource != "" {
		if info.UsedDefaultRules {
			fmt.Fprintf(&b, "Правила: %s (default)\r\n\r\n", info.RuleSource)
		} else {
			fmt.Fprintf(&b, "Правила: %s\r\n\r\n", info.RuleSource)
		}
	}
	for i, gr := range info.Groups {
		fmt.Fprintf(&b, "[%s]\r\n", gr.Name)
		fmt.Fprintf(&b, "Apps: %s\r\n", strings.Join(gr.Apps, ", "))
		if len(gr.Domains) > 0 {
			fmt.Fprintf(&b, "Domains: %s\r\n", strings.Join(gr.Domains, ", "))
		}
		if len(gr.Networks) > 0 {
			parts := make([]string, len(gr.Networks))
			for j, n := range gr.Networks {
				parts[j] = n.String()
			}
			fmt.Fprintf(&b, "Networks: %s\r\n", strings.Join(parts, ", "))
		}
		if i != len(info.Groups)-1 {
			b.WriteString("\r\n")
		}
	}
	if len(info.Groups) == 0 {
		b.WriteString("Нет групп маршрутизации.")
	}
	return b.String()
}

func humanBytes(n uint64) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%d B", n)
	case n < k*k:
		return fmt.Sprintf("%.1f KiB", float64(n)/k)
	case n < k*k*k:
		return fmt.Sprintf("%.1f MiB", float64(n)/(k*k))
	default:
		return fmt.Sprintf("%.1f GiB", float64(n)/(k*k*k))
	}
}

func configArg() string {
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" || args[i] == "-c" {
			if i+1 < len(args) {
				return abs(args[i+1])
			}
			continue
		}
		if !strings.HasPrefix(args[i], "-") {
			return abs(args[i])
		}
	}
	return ""
}

func abs(p string) string {
	p = strings.Trim(strings.TrimSpace(p), "\"")
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > max && max > 1 {
		return string(r[:max-1]) + "…"
	}
	return s
}

func normalizeEditNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

func openLog(path string) (*os.File, error) {
	if st, err := os.Stat(path); err == nil && st.Size() > 5*1024*1024 {
		_ = os.Remove(path + ".1")
		_ = os.Rename(path, path+".1")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
}

func tailFile(path string, limit int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	start := st.Size() - limit
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(f, limit))
	if start > 0 {
		if i := strings.IndexByte(string(b), '\n'); i >= 0 && i+1 < len(b) {
			b = b[i+1:]
		}
	}
	return string(b)
}

type uiLogSink struct {
	mu      sync.Mutex
	hwnd    uintptr
	pending []string
}

func (s *uiLogSink) Write(p []byte) (int, error) {
	text := string(append([]byte(nil), p...))
	s.mu.Lock()
	s.pending = append(s.pending, text)
	hwnd := s.hwnd
	s.mu.Unlock()
	if hwnd != 0 {
		postMessage(hwnd, wmAppLog, 0, 0)
	}
	return len(p), nil
}

func (s *uiLogSink) Attach(hwnd uintptr) {
	s.mu.Lock()
	s.hwnd = hwnd
	has := len(s.pending) > 0
	s.mu.Unlock()
	if has {
		postMessage(hwnd, wmAppLog, 0, 0)
	}
}

func (s *uiLogSink) Drain() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.pending
	s.pending = nil
	return out
}

func (g *gui) drainLog() {
	if g.logEdit == 0 {
		return
	}
	for _, line := range g.logSink.Drain() {
		appendEdit(g.logEdit, normalizeEditNewlines(line))
	}
	// Keep the UI control bounded even if the on-disk log is very active.
	if len([]rune(getText(g.logEdit))) > 300000 {
		r := []rune(getText(g.logEdit))
		if len(r) > 180000 {
			setText(g.logEdit, string(r[len(r)-180000:]))
		}
	}
}

func appendEdit(hwnd uintptr, text string) {
	minusOne := ^uintptr(0)
	sendMessage(hwnd, emSetSel, minusOne, minusOne)
	p := utf16Ptr(text)
	sendMessage(hwnd, emReplaceSel, 0, uintptr(unsafe.Pointer(p)))
	sendMessage(hwnd, emScrollCaret, 0, 0)
}

func scrollEditToEnd(hwnd uintptr) {
	minusOne := ^uintptr(0)
	sendMessage(hwnd, emSetSel, minusOne, minusOne)
	sendMessage(hwnd, emScrollCaret, 0, 0)
}
