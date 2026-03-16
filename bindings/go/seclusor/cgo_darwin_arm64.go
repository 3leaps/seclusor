//go:build darwin && arm64

package seclusor

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib/local/darwin-arm64 -L${SRCDIR}/lib/darwin-arm64 -lseclusor_ffi -lm -lpthread
#include "seclusor.h"
*/
import "C"
