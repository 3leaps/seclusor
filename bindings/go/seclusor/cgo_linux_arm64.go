//go:build linux && arm64

package seclusor

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib/local/linux-arm64 -L${SRCDIR}/lib/linux-arm64 -lseclusor_ffi -lm -lpthread -ldl
#include "seclusor.h"
*/
import "C"
