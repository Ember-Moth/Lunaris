// Derived from XTLS/Xray-core common/protocol at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.
package encryption

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

var hasAESGCMHardwareSupport = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3 ||
	cpu.ARM64.HasAES && cpu.ARM64.HasPMULL || runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" ||
	cpu.S390X.HasAES && cpu.S390X.HasAESCTR && cpu.S390X.HasGHASH ||
	runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le"
