package cipher

import E "github.com/metacubex/sing/common/exceptions"

var (
	ErrMissingPassword = E.New("missing password")
	ErrPacketTooShort  = E.New("packet too short")
)
