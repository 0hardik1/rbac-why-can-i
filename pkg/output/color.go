package output

import (
	"io"
	"os"
)

// ANSI color codes used for terminal output.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
)

// ResolveColor decides whether to emit ANSI color for the given setting
// ("auto", "always", "never") and output writer. "auto" (the default) enables
// color only when writing to a terminal and the NO_COLOR environment variable
// is unset (see https://no-color.org).
func ResolveColor(setting string, w io.Writer) bool {
	switch setting {
	case "always":
		return true
	case "never":
		return false
	default: // "auto" and anything unrecognized
		if os.Getenv("NO_COLOR") != "" {
			return false
		}
		return isTerminal(w)
	}
}

// isTerminal reports whether w is a character device (a terminal), without
// pulling in a dependency.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// colorize wraps s in the given ANSI code when enabled; otherwise returns s
// unchanged.
func colorize(enabled bool, code, s string) string {
	if !enabled || code == "" {
		return s
	}
	return code + s + colorReset
}
