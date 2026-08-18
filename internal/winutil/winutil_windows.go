//go:build windows

package winutil

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)

func IsAdmin() bool { r, _, _ := procIsUserAnAdmin.Call(); return r != 0 }

func RelaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		args = append(args, syscall.EscapeArg(a))
	}
	param, _ := syscall.UTF16PtrFromString(strings.Join(args, " "))
	cwd, _ := os.Getwd()
	dir, _ := syscall.UTF16PtrFromString(cwd)
	r, _, callErr := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(param)), uintptr(unsafe.Pointer(dir)), 1)
	if r <= 32 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return fmt.Errorf("ShellExecuteW elevation failed: code %d", r)
	}
	return nil
}

func AppDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// EnsureAssets makes the application portable. If WinDivert is not already
// next to the EXE, the official signed 2.2.2 binary package is downloaded from
// reqrypt.org and only the x64 DLL/driver are extracted.
func EnsureAssets(dir string) error {
	dll := filepath.Join(dir, "WinDivert.dll")
	sys := filepath.Join(dir, "WinDivert64.sys")
	if regular(dll) && regular(sys) {
		return nil
	}
	urls := []string{
		"https://www.reqrypt.org/download/WinDivert-2.2.2-A.zip",
		"https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip",
	}
	var data []byte
	var last error
	client := &http.Client{Timeout: 30 * time.Second}
	for _, u := range urls {
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "SplitWire/1.1")
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			last = fmt.Errorf("%s: HTTP %s", u, resp.Status)
			resp.Body.Close()
			continue
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if len(data) == 0 {
			last = errors.New("empty WinDivert download")
			continue
		}
		last = nil
		break
	}
	if last != nil {
		return fmt.Errorf("download WinDivert 2.2.2: %w", last)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("WinDivert zip: %w", err)
	}
	foundDLL, foundSYS := false, false
	for _, f := range zr.File {
		n := strings.ToLower(strings.ReplaceAll(f.Name, "\\", "/"))
		var dst string
		switch {
		case strings.HasSuffix(n, "/x64/windivert.dll") || n == "x64/windivert.dll":
			dst = dll
			foundDLL = true
			if regular(dst) {
				continue
			}
		case strings.HasSuffix(n, "/x64/windivert64.sys") || n == "x64/windivert64.sys":
			dst = sys
			foundSYS = true
			// A loaded WinDivert driver can keep this file open. Reuse a valid
			// existing driver instead of trying to replace it and failing with
			// ERROR_ACCESS_DENIED.
			if regular(dst) {
				continue
			}
		case strings.HasSuffix(n, "/license") || strings.HasSuffix(n, "/license.txt"):
			if dst == "" {
				dst = filepath.Join(dir, "WinDivert-LICENSE.txt")
			}
		default:
			continue
		}
		rc, e := f.Open()
		if e != nil {
			return e
		}
		tmp := dst + ".tmp"
		out, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e == nil {
			_, e = io.Copy(out, io.LimitReader(rc, 32<<20))
			out.Close()
		}
		rc.Close()
		if e != nil {
			_ = os.Remove(tmp)
			return e
		}
		if e = os.Rename(tmp, dst); e != nil {
			_ = os.Remove(tmp)
			return e
		}
	}
	if !foundDLL || !foundSYS {
		return errors.New("official WinDivert archive did not contain x64/WinDivert.dll and x64/WinDivert64.sys")
	}
	return nil
}
func regular(p string) bool {
	st, e := os.Stat(p)
	return e == nil && st.Mode().IsRegular() && st.Size() > 0
}

type Interface struct {
	Index uint32
	Name  string
}

func SelectPhysicalInterface(spec string) (Interface, error) {
	spec = strings.TrimSpace(spec)
	if spec != "" {
		if n, err := strconv.ParseUint(spec, 10, 32); err == nil {
			return interfaceByIndex(uint32(n))
		}
		escaped := strings.ReplaceAll(spec, "'", "''")
		out, err := powershell("$a=Get-NetAdapter -InterfaceAlias '" + escaped + "' -ErrorAction Stop; $a.IfIndex")
		if err != nil {
			return Interface{}, fmt.Errorf("physical interface %q: %w", spec, err)
		}
		n, err := strconv.ParseUint(strings.TrimSpace(out), 10, 32)
		if err != nil {
			return Interface{}, fmt.Errorf("parse interface index %q: %w", out, err)
		}
		return interfaceByIndex(uint32(n))
	}
	script := `$x=Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.HardwareInterface } | Sort-Object { $_.NetIPv4Interface.InterfaceMetric } | Select-Object -First 1; if($null -eq $x){exit 2}; $x.InterfaceIndex`
	out, err := powershell(script)
	if err != nil {
		script = `$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | Select-Object -First 1; if($null -eq $r){exit 2}; $r.InterfaceIndex`
		out, err = powershell(script)
	}
	if err != nil {
		return Interface{}, fmt.Errorf("auto-select physical interface: %w", err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(out), 10, 32)
	if err != nil {
		return Interface{}, fmt.Errorf("parse physical interface index %q: %w", out, err)
	}
	return interfaceByIndex(uint32(n))
}

func interfaceByIndex(index uint32) (Interface, error) {
	if index == 0 {
		return Interface{}, errors.New("interface index is zero")
	}
	ni, err := net.InterfaceByIndex(int(index))
	if err != nil {
		return Interface{}, err
	}
	return Interface{Index: index, Name: ni.Name}, nil
}
func powershell(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	b, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(b)))
	}
	return strings.TrimSpace(string(b)), nil
}
