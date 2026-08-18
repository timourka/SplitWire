//go:build !windows

package winutil

import (
	"errors"
	"os"
	"path/filepath"
)

type Interface struct {
	Index uint32
	Name  string
}

func IsAdmin() bool           { return true }
func RelaunchElevated() error { return errors.New("Windows-only") }
func AppDir() (string, error) {
	e, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(e), nil
}
func EnsureAssets(string) error { return nil }
func SelectPhysicalInterface(string) (Interface, error) {
	return Interface{}, errors.New("Windows-only")
}
