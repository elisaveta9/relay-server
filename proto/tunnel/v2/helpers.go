package tunnelpb

import "time"

func NewStreamOpenFrame(streamID uint64, sni string, remoteAddr string) *Frame {
	return &Frame{
		StreamId: streamID,
		Body: &Frame_StreamOpen{
			StreamOpen: &StreamOpen{
				Domain:         sni,
				Sni:            sni,
				RemoteAddr:     remoteAddr,
				OpenedAtUnixMs: nowUnixMilli(),
			},
		},
	}
}

func NewStreamDataFrame(streamID uint64, payload []byte) *Frame {
	return &Frame{
		StreamId: streamID,
		Body: &Frame_StreamData{
			StreamData: payload,
		},
	}
}

func NewStreamCloseFrame(streamID uint64, reason CloseReason, message string) *Frame {
	return &Frame{
		StreamId: streamID,
		Body: &Frame_StreamClose{
			StreamClose: &StreamClose{
				Reason:  reason,
				Message: message,
			},
		},
	}
}

func NewStreamOpenResultFrame(streamID uint64, success bool, code TunnelErrorCode, message string) *Frame {
	return &Frame{
		StreamId: streamID,
		Body: &Frame_StreamOpenResult{
			StreamOpenResult: &StreamOpenResult{
				Success:   success,
				ErrorCode: code,
				Message:   message,
			},
		},
	}
}

func NewPongFrame(opaque []byte) *Frame {
	return &Frame{
		Body: &Frame_Pong{
			Pong: &Pong{
				Opaque:       opaque,
				SentAtUnixMs: uint64(time.Now().UnixMilli()),
			},
		},
	}
}

func NewPongFrameForPing(ping *Ping) *Frame {
	if ping == nil {
		return NewPongFrame(nil)
	}
	return &Frame{
		Body: &Frame_Pong{
			Pong: &Pong{
				Opaque:           ping.GetOpaque(),
				PingSentAtUnixMs: ping.GetSentAtUnixMs(),
				SentAtUnixMs:     uint64(time.Now().UnixMilli()),
			},
		},
	}
}

func NewWelcomeFrame(welcome *Welcome) *Frame {
	return &Frame{
		Body: &Frame_Welcome{
			Welcome: welcome,
		},
	}
}

func NewTunnelErrorFrame(code TunnelErrorCode, message string, details string) *Frame {
	return &Frame{
		Body: &Frame_Error{
			Error: &TunnelError{
				Code:    code,
				Message: message,
				Details: details,
			},
		},
	}
}

func NewGoAwayFrame(code TunnelErrorCode, message string, reconnect bool, retryAfterSeconds uint32) *Frame {
	return NewGoAwayFrameWithReason(code, message, reconnect, retryAfterSeconds, DisconnectReason_DISCONNECT_REASON_UNSPECIFIED)
}

func NewGoAwayFrameWithReason(code TunnelErrorCode, message string, reconnect bool, retryAfterSeconds uint32, reason DisconnectReason) *Frame {
	return &Frame{
		Body: &Frame_Goaway{
			Goaway: &GoAway{
				Code:              code,
				Message:           message,
				Reconnect:         reconnect,
				RetryAfterSeconds: retryAfterSeconds,
				Reason:            reason,
			},
		},
	}
}

func NewBindResultFrame(domain string, success bool, code TunnelErrorCode, message string) *Frame {
	return &Frame{
		Body: &Frame_BindResult{
			BindResult: &BindResult{
				Domain:    domain,
				Success:   success,
				ErrorCode: code,
				Message:   message,
			},
		},
	}
}

func NewUnbindResultFrame(domain string, success bool, code TunnelErrorCode, message string) *Frame {
	return &Frame{
		Body: &Frame_UnbindResult{
			UnbindResult: &UnbindResult{
				Domain:    domain,
				Success:   success,
				ErrorCode: code,
				Message:   message,
			},
		},
	}
}

func NewDomainRevokedFrame(domain string, reason string) *Frame {
	return NewDomainRevokedFrameWithReason(domain, reason, DomainRevokeReason_DOMAIN_REVOKE_REASON_UNSPECIFIED)
}

func NewDomainRevokedFrameWithReason(domain string, reason string, revokeReason DomainRevokeReason) *Frame {
	return &Frame{
		Body: &Frame_DomainRevoked{
			DomainRevoked: &DomainRevoked{
				Domain:       domain,
				Reason:       reason,
				RevokeReason: revokeReason,
			},
		},
	}
}

func NewDomainSyncFrame(domains []*DomainBinding) *Frame {
	return &Frame{
		Body: &Frame_DomainSync{
			DomainSync: &DomainSync{
				Domains: domains,
			},
		},
	}
}

func NewDomainVerificationUpdateFrame(update *DomainVerificationUpdate) *Frame {
	return &Frame{
		Body: &Frame_DomainVerificationUpdate{
			DomainVerificationUpdate: update,
		},
	}
}

func IsControlFrame(f *Frame) bool {
	switch f.GetBody().(type) {
	case *Frame_Hello,
		*Frame_Welcome,
		*Frame_Ping,
		*Frame_Pong,
		*Frame_Goaway,
		*Frame_Error,
		*Frame_BindRequest,
		*Frame_BindResult,
		*Frame_UnbindRequest,
		*Frame_UnbindResult,
		*Frame_DomainSync,
		*Frame_DomainRevoked,
		*Frame_DomainVerificationUpdate:
		return true
	case *Frame_StreamOpenResult:
		return false
	default:
		return false
	}
}

func IsStreamDataFrame(f *Frame) bool {
	_, ok := f.GetBody().(*Frame_StreamData)
	return ok
}

func nowUnixMilli() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}
