//go:build darwin && amd64

package seclusor

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo !seclusor_local LDFLAGS: -L${SRCDIR}/lib/darwin-amd64 -lseclusor_ffi -lm -lpthread
#cgo seclusor_local LDFLAGS: -L${SRCDIR}/lib/local/darwin-amd64 -lseclusor_ffi -lm -lpthread
#include "seclusor.h"
*/
import "C"
