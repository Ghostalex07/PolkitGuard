package parser

import (
	"math/rand"
	"os"
	"strings"
	"testing"
)

func FuzzParseRule(f *testing.F) {
	seedExamples := []string{
		`[any all]
result_any=yes`,
		`[unix-user:admin]
result_any=auth_admin`,
		`[unix-user:bob]
Action=org.freedesktop.systemd1.manage-units
ResultAny=auth_admin_keep`,
		`[unix-group:wheel]
Action=org.freedesktop.systemd1.reboot
ResultAny=auth_admin`,
	}
	for _, seed := range seedExamples {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 10000 {
			t.Skip()
		}

		file := "/tmp/fuzz-" + randomString(8) + ".rules"
		if err := os.WriteFile(file, []byte(data), 0644); err != nil {
			return
		}
		defer os.Remove(file)

		p := NewParser()
		_, err := p.ParseFile(file)
		if err != nil && !isValidError(err) {
			t.Logf("Parser error: %v", err)
		}
	})
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func isValidError(err error) bool {
	errStr := err.Error()
	validErrors := []string{
		"parse error",
		"invalid",
		"rule",
		"syntax",
		"cannot",
	}
	for _, v := range validErrors {
		if strings.Contains(errStr, v) {
			return true
		}
	}
	return false
}
