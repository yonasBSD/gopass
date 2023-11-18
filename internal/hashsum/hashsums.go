package hashsum

import (
	"fmt"

	"github.com/zeebo/blake3"
)

func Blake3Hex(in string) string {
	return fmt.Sprintf("%x", blake3.Sum256([]byte(in)))
}
