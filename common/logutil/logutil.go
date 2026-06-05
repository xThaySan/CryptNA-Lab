package logutil

import (
	"log"
	"os"
)

func Enabled() bool {
	v := os.Getenv("CRYPTNA_DEBUG")
	return v == "1" || v == "true" || v == "TRUE" || v == "yes"
}

func Debugf(component string, format string, args ...any) {
	if !Enabled() {
		return
	}
	log.Printf("[DEBUG][%s] "+format, append([]any{component}, args...)...)
}

func Infof(component string, format string, args ...any) {
	log.Printf("[%s] "+format, append([]any{component}, args...)...)
}

func Short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:8] + "..." + s[len(s)-8:]
}
