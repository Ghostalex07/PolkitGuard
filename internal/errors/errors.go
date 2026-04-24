package errors

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

type ErrorCode int

const (
	ErrScanFailed ErrorCode = iota + 1
	ErrParseError
	ErrConfigInvalid
	ErrPathNotFound
	ErrPermissionDenied
	ErrWebhookFailed
	ErrNetworkError
)

type PolkitError struct {
	Code    ErrorCode
	Message string
	Cause   error
	file    string
	line    int
}

func (e *PolkitError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%d] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

func (e *PolkitError) Unwrap() error {
	return e.Cause
}

func (e *PolkitError) Location() (string, int) {
	return e.file, e.line
}

func NewError(code ErrorCode, message string) *PolkitError {
	_, file, line, _ := runtime.Caller(1)
	return &PolkitError{
		Code:    code,
		Message: message,
		file:    file,
		line:    line,
	}
}

func WrapError(err error, message string) *PolkitError {
	_, file, line, _ := runtime.Caller(1)
	return &PolkitError{
		Code:    ErrScanFailed,
		Message: message,
		Cause:   err,
		file:    file,
		line:    line,
	}
}

type ErrorHandler struct {
	verbose bool
}

func NewErrorHandler(verbose bool) *ErrorHandler {
	return &ErrorHandler{verbose: verbose}
}

func (h *ErrorHandler) Handle(err error) {
	if err == nil {
		return
	}

	pe, ok := err.(*PolkitError)
	if !ok {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "ERROR [%d]: %s\n", pe.Code, pe.Message)

	if h.verbose && pe.Cause != nil {
		fmt.Fprintf(os.Stderr, "  Caused by: %v\n", pe.Cause)
	}

	if h.verbose {
		fmt.Fprintf(os.Stderr, "  Location: %s:%d\n", pe.file, pe.line)
	}
}

func (e *PolkitError) Is(target error) bool {
	te, ok := target.(*PolkitError)
	if !ok {
		return false
	}
	return e.Code == te.Code
}

func (e *PolkitError) IsCode(code ErrorCode) bool {
	return e.Code == code
}

func UserError(msg string) error {
	return &PolkitError{
		Code:    ErrScanFailed,
		Message: msg,
	}
}

func ParseError(filepath, msg string) error {
	return &PolkitError{
		Code:    ErrParseError,
		Message: fmt.Sprintf("parse error in %s: %s", filepath, msg),
	}
}

func ConfigError(msg string) error {
	return &PolkitError{
		Code:    ErrConfigInvalid,
		Message: "config error: " + msg,
	}
}

func PathError(path string) error {
	if !strings.Contains(path, "/") {
		return &PolkitError{
			Code:    ErrPathNotFound,
			Message: fmt.Sprintf("path not found: %s", path),
		}
	}
	return &PolkitError{
		Code:    ErrPathNotFound,
		Message: fmt.Sprintf("path not accessible: %s", path),
	}
}
