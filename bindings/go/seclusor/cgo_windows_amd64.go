//go:build windows && amd64

package seclusor

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo !seclusor_local LDFLAGS: -L${SRCDIR}/lib/windows-amd64 -lseclusor_ffi -lm -lws2_32 -luserenv -lbcrypt -lkernel32 -lntdll -ladvapi32 -liphlpapi -lpsapi
#cgo seclusor_local LDFLAGS: -L${SRCDIR}/lib/local/windows-amd64 -lseclusor_ffi -lm -lws2_32 -luserenv -lbcrypt -lkernel32 -lntdll -ladvapi32 -liphlpapi -lpsapi
#include "seclusor.h"
*/
import "C"
