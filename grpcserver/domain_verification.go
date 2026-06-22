package grpcserver

import (
	"context"
	"log"
	rand "math/rand/v2"
	"time"

	"relay/device"
	controlpb "relay/proto/control/v2"
	tunnelpb "relay/proto/tunnel/v2"
	"relay/registry"
	"relay/storage"
)

const (
	// Ждем немного, чтобы DNS успел обновиться.
	defaultDNSInitialVerificationDelay = 90 * time.Second
	defaultDNSMaxVerificationInterval  = 5 * time.Minute
	defaultDNSVerificationJitterPct    = 10
	domainVerificationEventsFeature    = "domain-verification-events"
)

func configuredDNSInitialVerificationDelay() time.Duration {
	return time.Duration(envInt(
		"RELAY_DNS_VERIFY_INITIAL_INTERVAL_SECONDS",
		int(defaultDNSInitialVerificationDelay/time.Second),
	)) * time.Second
}

func configuredDNSMaxVerificationInterval() time.Duration {
	return time.Duration(envInt(
		"RELAY_DNS_VERIFY_MAX_INTERVAL_SECONDS",
		int(defaultDNSMaxVerificationInterval/time.Second),
	)) * time.Second
}

func configuredDNSVerificationJitterPercent() int {
	return envInt("RELAY_DNS_VERIFY_JITTER_PERCENT", defaultDNSVerificationJitterPct)
}

func dnsVerificationRetryInterval(attempt uint32, initial time.Duration, maximum time.Duration) time.Duration {
	if initial <= 0 {
		initial = defaultDNSInitialVerificationDelay
	}
	if maximum < initial {
		maximum = initial
	}

	multipliers := [...]int64{1, 2, 4, 10, 20, 30}
	if attempt >= uint32(len(multipliers)) {
		return maximum
	}
	multiplier := multipliers[attempt]
	if initial > maximum/time.Duration(multiplier) {
		return maximum
	}
	interval := initial * time.Duration(multiplier)
	if interval > maximum {
		return maximum
	}
	return interval
}

func jitterDNSVerificationInterval(interval time.Duration, percent int) time.Duration {
	if interval <= 0 || percent <= 0 {
		return interval
	}
	if percent > 100 {
		percent = 100
	}
	spread := int64(interval) * int64(percent) / 100
	if spread <= 0 {
		return interval
	}
	return interval + time.Duration(rand.Int64N(2*spread+1)-spread)
}

func nextDNSVerificationAt(challenge *storage.DomainOwnershipChallenge, now time.Time) time.Time {
	interval := dnsVerificationRetryInterval(
		challenge.VerificationAttempts,
		configuredDNSInitialVerificationDelay(),
		configuredDNSMaxVerificationInterval(),
	)
	interval = jitterDNSVerificationInterval(interval, configuredDNSVerificationJitterPercent())
	next := now.Add(interval)
	if next.After(challenge.ExpiresAt) {
		return challenge.ExpiresAt
	}
	return next
}

func controlDomainVerificationInfos(
	challenges []storage.DomainOwnershipChallenge,
) []*controlpb.DomainVerificationInfo {
	out := make([]*controlpb.DomainVerificationInfo, 0, len(challenges))
	for i := range challenges {
		out = append(out, controlDomainVerificationInfo(&challenges[i]))
	}
	return out
}

func controlDomainVerificationInfo(
	challenge *storage.DomainOwnershipChallenge,
) *controlpb.DomainVerificationInfo {
	if challenge == nil {
		return nil
	}
	status := effectiveDomainOwnershipChallengeStatus(challenge)
	info := &controlpb.DomainVerificationInfo{
		Domain:                   challenge.FQDN,
		Status:                   controlDomainVerificationStatus(status),
		VerificationAttempts:     challenge.VerificationAttempts,
		NextVerificationAtUnixMs: unixMilli(challenge.NextVerificationAt),
		LastVerificationAtUnixMs: unixMilli(challenge.LastVerificationAt),
		LastError:                challenge.LastError,
		VerifiedAtUnixMs:         unixMilli(challenge.VerifiedAt),
		CanRequestNewChallenge:   status == storage.DomainOwnershipChallengeStatusExpired,
	}
	if status != storage.DomainOwnershipChallengeStatusVerified {
		info.DnsInstruction = controlDNSInstruction(challenge)
	}
	return info
}

func tunnelDomainVerificationUpdates(
	challenges []storage.DomainOwnershipChallenge,
) []*tunnelpb.DomainVerificationUpdate {
	out := make([]*tunnelpb.DomainVerificationUpdate, 0, len(challenges))
	for i := range challenges {
		out = append(out, tunnelDomainVerificationUpdate(&challenges[i]))
	}
	return out
}

func tunnelDomainVerificationUpdate(
	challenge *storage.DomainOwnershipChallenge,
) *tunnelpb.DomainVerificationUpdate {
	if challenge == nil {
		return nil
	}
	status := effectiveDomainOwnershipChallengeStatus(challenge)
	update := &tunnelpb.DomainVerificationUpdate{
		Domain:                   challenge.FQDN,
		Status:                   tunnelDomainVerificationStatus(status),
		VerificationAttempts:     challenge.VerificationAttempts,
		NextVerificationAtUnixMs: unixMilli(challenge.NextVerificationAt),
		LastVerificationAtUnixMs: unixMilli(challenge.LastVerificationAt),
		LastError:                challenge.LastError,
		VerifiedAtUnixMs:         unixMilli(challenge.VerifiedAt),
		CanRequestNewChallenge:   status == storage.DomainOwnershipChallengeStatusExpired,
		ExpiresAtUnixMs:          challenge.ExpiresAt.UnixMilli(),
	}
	if status != storage.DomainOwnershipChallengeStatusVerified {
		update.RecordName = challenge.RecordName
		update.RecordValue = challenge.RecordValue
	}
	return update
}

func controlDNSInstruction(challenge *storage.DomainOwnershipChallenge) *controlpb.DNSInstruction {
	return &controlpb.DNSInstruction{
		RecordName:      challenge.RecordName,
		RecordType:      controlpb.DNSRecordType_DNS_RECORD_TYPE_TXT,
		RecordValue:     challenge.RecordValue,
		Purpose:         "relay domain ownership verification",
		ExpiresAtUnixMs: challenge.ExpiresAt.UnixMilli(),
	}
}

func effectiveDomainOwnershipChallengeStatus(
	challenge *storage.DomainOwnershipChallenge,
) storage.DomainOwnershipChallengeStatus {
	if challenge.Status == storage.DomainOwnershipChallengeStatusPending &&
		!challenge.ExpiresAt.After(time.Now().UTC()) {
		return storage.DomainOwnershipChallengeStatusExpired
	}
	return challenge.Status
}

func controlDomainVerificationStatus(
	status storage.DomainOwnershipChallengeStatus,
) controlpb.DomainVerificationStatus {
	switch status {
	case storage.DomainOwnershipChallengeStatusPending:
		return controlpb.DomainVerificationStatus_DOMAIN_VERIFICATION_STATUS_PENDING
	case storage.DomainOwnershipChallengeStatusVerified:
		return controlpb.DomainVerificationStatus_DOMAIN_VERIFICATION_STATUS_VERIFIED
	case storage.DomainOwnershipChallengeStatusExpired:
		return controlpb.DomainVerificationStatus_DOMAIN_VERIFICATION_STATUS_EXPIRED
	default:
		return controlpb.DomainVerificationStatus_DOMAIN_VERIFICATION_STATUS_UNSPECIFIED
	}
}

func tunnelDomainVerificationStatus(
	status storage.DomainOwnershipChallengeStatus,
) tunnelpb.DomainVerificationStatus {
	switch status {
	case storage.DomainOwnershipChallengeStatusPending:
		return tunnelpb.DomainVerificationStatus_DOMAIN_VERIFICATION_STATUS_PENDING
	case storage.DomainOwnershipChallengeStatusVerified:
		return tunnelpb.DomainVerificationStatus_DOMAIN_VERIFICATION_STATUS_VERIFIED
	case storage.DomainOwnershipChallengeStatusExpired:
		return tunnelpb.DomainVerificationStatus_DOMAIN_VERIFICATION_STATUS_EXPIRED
	default:
		return tunnelpb.DomainVerificationStatus_DOMAIN_VERIFICATION_STATUS_UNSPECIFIED
	}
}

func unixMilli(value *time.Time) int64 {
	if value == nil {
		return 0
	}
	return value.UnixMilli()
}

func formatOptionalTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.Format(time.RFC3339)
}

func notifyDomainVerificationUpdate(
	repo *storage.Repository,
	challenge *storage.DomainOwnershipChallenge,
	syncDomains bool,
) {
	if challenge == nil || challenge.Device.CertFingerprint == "" {
		return
	}
	for _, dev := range registry.Global.DevicesForFingerprint(challenge.Device.CertFingerprint) {
		sendDomainVerificationUpdate(repo, dev, challenge, syncDomains)
	}
}

func sendDomainVerificationUpdate(
	repo *storage.Repository,
	dev *device.Device,
	challenge *storage.DomainOwnershipChallenge,
	syncDomains bool,
) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if dev.SupportsFeature(domainVerificationEventsFeature) {
		frame := tunnelpb.NewDomainVerificationUpdateFrame(tunnelDomainVerificationUpdate(challenge))
		if err := dev.SendFrame(ctx, frame); err != nil {
			log.Printf(
				"send domain verification update failed: domain=%s fingerprint=%s session=%s err=%v",
				challenge.FQDN,
				dev.Fingerprint,
				dev.SessionID,
				err,
			)
		} else {
			log.Printf(
				"sent domain verification update: domain=%s status=%s fingerprint=%s session=%s sync_domains=%t",
				challenge.FQDN,
				effectiveDomainOwnershipChallengeStatus(challenge),
				dev.Fingerprint,
				dev.SessionID,
				syncDomains,
			)
		}
	} else {
		log.Printf(
			"skip domain verification update: domain=%s fingerprint=%s session=%s reason=feature_not_supported",
			challenge.FQDN,
			dev.Fingerprint,
			dev.SessionID,
		)
	}
	if syncDomains {
		sendDomainSync(ctx, repo, dev)
	}
}
