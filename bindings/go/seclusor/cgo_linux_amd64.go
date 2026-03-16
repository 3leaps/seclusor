//go:build linux && amd64

package seclusor

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib/local/linux-amd64 -L${SRCDIR}/lib/linux-amd64 -lseclusor_ffi -lm -lpthread -ldl
#include "seclusor.h"
*/
import "C"
