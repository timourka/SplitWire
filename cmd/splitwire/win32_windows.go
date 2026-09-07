//go:build windows

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	wsOverlappedWindow = 0x00CF0000
	wsChild            = 0x40000000
	wsVisible          = 0x10000000
	wsTabStop          = 0x00010000
	wsBorder           = 0x00800000
	wsVScroll          = 0x00200000
	wsHScroll          = 0x00100000

	esMultiline   = 0x0004
	esAutoVScroll = 0x0040
	esAutoHScroll = 0x0080
	esReadOnly    = 0x0800

	bsPushButton = 0x00000000
	bsGroupBox   = 0x00000007

	wmCreate  = 0x0001
	wmDestroy = 0x0002
	wmSize    = 0x0005
	wmClose   = 0x0010
	wmCommand = 0x0111
	wmTimer   = 0x0113
	wmSetFont = 0x0030
	wmApp     = 0x8000

	emSetSel      = 0x00B1
	emScrollCaret = 0x00B7
	emReplaceSel  = 0x00C2

	mbOK        = 0x00000000
	mbIconError = 0x00000010
	mbIconInfo  = 0x00000040

	ofNPathMustExist = 0x00000800
	ofNFileMustExist = 0x00001000
	ofNExplorer      = 0x00080000

	swShow = 5

	colorWindow    = 5
	defaultGUIFont = 17
	idcArrow       = 32512

	cwUseDefault = int32(-2147483648)
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	comdlg32 = syscall.NewLazyDLL("comdlg32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	procRegisterClassExW  = user32.NewProc("RegisterClassExW")
	procCreateWindowExW   = user32.NewProc("CreateWindowExW")
	procDefWindowProcW    = user32.NewProc("DefWindowProcW")
	procDestroyWindow     = user32.NewProc("DestroyWindow")
	procShowWindow        = user32.NewProc("ShowWindow")
	procUpdateWindow      = user32.NewProc("UpdateWindow")
	procGetMessageW       = user32.NewProc("GetMessageW")
	procTranslateMessage  = user32.NewProc("TranslateMessage")
	procDispatchMessageW  = user32.NewProc("DispatchMessageW")
	procPostQuitMessage   = user32.NewProc("PostQuitMessage")
	procPostMessageW      = user32.NewProc("PostMessageW")
	procSendMessageW      = user32.NewProc("SendMessageW")
	procSetWindowTextW    = user32.NewProc("SetWindowTextW")
	procGetWindowTextW    = user32.NewProc("GetWindowTextW")
	procGetWindowTextLenW = user32.NewProc("GetWindowTextLengthW")
	procEnableWindow      = user32.NewProc("EnableWindow")
	procMoveWindow        = user32.NewProc("MoveWindow")
	procGetClientRect     = user32.NewProc("GetClientRect")
	procSetTimer          = user32.NewProc("SetTimer")
	procKillTimer         = user32.NewProc("KillTimer")
	procLoadCursorW       = user32.NewProc("LoadCursorW")
	procMessageBoxW       = user32.NewProc("MessageBoxW")
	procSetFocus          = user32.NewProc("SetFocus")

	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procGetStockObject   = gdi32.NewProc("GetStockObject")
	procGetOpenFileNameW = comdlg32.NewProc("GetOpenFileNameW")
	procShellExecuteW    = shell32.NewProc("ShellExecuteW")
)

type point struct {
	X int32
	Y int32
}

type rect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

type msg struct {
	Hwnd     uintptr
	Message  uint32
	_        uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       point
	LPrivate uint32
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type openFilename struct {
	LStructSize       uint32
	HwndOwner         uintptr
	HInstance         uintptr
	LpstrFilter       *uint16
	LpstrCustomFilter *uint16
	NMaxCustFilter    uint32
	NFilterIndex      uint32
	LpstrFile         *uint16
	NMaxFile          uint32
	LpstrFileTitle    *uint16
	NMaxFileTitle     uint32
	LpstrInitialDir   *uint16
	LpstrTitle        *uint16
	Flags             uint32
	NFileOffset       uint16
	NFileExtension    uint16
	LpstrDefExt       *uint16
	LCustData         uintptr
	LpfnHook          uintptr
	LpTemplateName    *uint16
	PvReserved        uintptr
	DwReserved        uint32
	FlagsEx           uint32
}

func utf16Ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func moduleHandle() uintptr {
	r, _, _ := procGetModuleHandleW.Call(0)
	return r
}

func stockGUIFont() uintptr {
	r, _, _ := procGetStockObject.Call(defaultGUIFont)
	return r
}

func registerClass(name string, wndProc uintptr) error {
	cursor, _, _ := procLoadCursorW.Call(0, idcArrow)
	cls := wndClassEx{
		CbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		LpfnWndProc:   wndProc,
		HInstance:     moduleHandle(),
		HCursor:       cursor,
		HbrBackground: uintptr(colorWindow + 1),
		LpszClassName: utf16Ptr(name),
	}
	r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&cls)))
	if r == 0 {
		if err != syscall.Errno(0) {
			return err
		}
		return errors.New("RegisterClassExW failed")
	}
	return nil
}

func createWindow(exStyle uint32, class, title string, style uint32, x, y, w, h int32, parent, id uintptr) uintptr {
	r, _, _ := procCreateWindowExW.Call(
		uintptr(exStyle),
		uintptr(unsafe.Pointer(utf16Ptr(class))),
		uintptr(unsafe.Pointer(utf16Ptr(title))),
		uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent, id, moduleHandle(), 0,
	)
	return r
}

func defWindowProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
	return r
}

func destroyWindow(hwnd uintptr) { procDestroyWindow.Call(hwnd) }

func showWindow(hwnd uintptr) {
	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)
}

func postQuitMessage(code int32) { procPostQuitMessage.Call(uintptr(code)) }

func postMessage(hwnd uintptr, message uint32, wParam, lParam uintptr) {
	procPostMessageW.Call(hwnd, uintptr(message), wParam, lParam)
}

func sendMessage(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	r, _, _ := procSendMessageW.Call(hwnd, uintptr(message), wParam, lParam)
	return r
}

func setText(hwnd uintptr, s string) {
	procSetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(utf16Ptr(s))))
}

func getText(hwnd uintptr) string {
	n, _, _ := procGetWindowTextLenW.Call(hwnd)
	buf := make([]uint16, int(n)+1)
	if len(buf) == 0 {
		return ""
	}
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf)
}

func enableWindow(hwnd uintptr, enable bool) {
	var v uintptr
	if enable {
		v = 1
	}
	procEnableWindow.Call(hwnd, v)
}

func moveWindow(hwnd uintptr, x, y, w, h int32) {
	if hwnd == 0 {
		return
	}
	procMoveWindow.Call(hwnd, uintptr(x), uintptr(y), uintptr(w), uintptr(h), 1)
}

func clientRect(hwnd uintptr) rect {
	var r rect
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	return r
}

func setTimer(hwnd uintptr, id, ms uintptr) {
	procSetTimer.Call(hwnd, id, ms, 0)
}

func killTimer(hwnd uintptr, id uintptr) {
	procKillTimer.Call(hwnd, id)
}

func focus(hwnd uintptr) { procSetFocus.Call(hwnd) }

func setFont(hwnd, font uintptr) {
	if hwnd != 0 && font != 0 {
		sendMessage(hwnd, wmSetFont, font, 1)
	}
}

func messageBox(owner uintptr, title, text string, flags uint32) {
	procMessageBoxW.Call(owner, uintptr(unsafe.Pointer(utf16Ptr(text))), uintptr(unsafe.Pointer(utf16Ptr(title))), uintptr(flags))
}

func messageLoop() int {
	var m msg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) == -1 {
			return 1
		}
		if r == 0 {
			return int(m.WParam)
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func openConfigDialog(owner uintptr, initial string) (string, bool) {
	buf := make([]uint16, 32768)
	if initial != "" {
		u, _ := syscall.UTF16FromString(initial)
		copy(buf, u)
	}
	filter := multiUTF16("WireGuard config (*.conf)", "*.conf", "All files (*.*)", "*.*", "")
	title := utf16Ptr("Choose WireGuard configuration")
	defExt := utf16Ptr("conf")
	var initialDir *uint16
	if initial != "" {
		d := filepath.Dir(initial)
		initialDir = utf16Ptr(d)
	}
	of := openFilename{
		LStructSize:     uint32(unsafe.Sizeof(openFilename{})),
		HwndOwner:       owner,
		LpstrFilter:     &filter[0],
		NFilterIndex:    1,
		LpstrFile:       &buf[0],
		NMaxFile:        uint32(len(buf)),
		LpstrInitialDir: initialDir,
		LpstrTitle:      title,
		Flags:           ofNExplorer | ofNFileMustExist | ofNPathMustExist,
		LpstrDefExt:     defExt,
	}
	r, _, _ := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&of)))
	if r == 0 {
		return "", false
	}
	return syscall.UTF16ToString(buf), true
}

func multiUTF16(parts ...string) []uint16 {
	var out []uint16
	for _, p := range parts {
		out = append(out, utf16.Encode([]rune(p))...)
		out = append(out, 0)
	}
	if len(out) == 0 || out[len(out)-1] != 0 {
		out = append(out, 0)
	}
	return out
}

func openTextFile(path string) error {
	if path == "" {
		return errors.New("empty path")
	}
	verb := utf16Ptr("open")
	file := utf16Ptr("notepad.exe")
	params := utf16Ptr("\"" + path + "\"")
	r, _, callErr := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), 0, 1)
	if r <= 32 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return fmt.Errorf("ShellExecuteW failed: code %d", r)
	}
	return nil
}

func lowWord(v uintptr) uint16 { return uint16(v & 0xffff) }
func sizeFromLParam(v uintptr) (int32, int32) {
	return int32(uint16(v & 0xffff)), int32(uint16((v >> 16) & 0xffff))
}
