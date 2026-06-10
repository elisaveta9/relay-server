package grpcserver

import (
	"testing"
	"time"

	controlpb "relay/proto/control/v2"
	tunnelpb "relay/proto/tunnel/v2"
	"relay/storage"
)

func TestDNSVerificationRetryIntervalUsesExponentialBackoffWithCap(t *testing.T) {
	initial := 30 * time.Second
	maximum := 15 * time.Minute
	tests := []struct {
		attempt uint32
		want    time.Duration
	}{
		{attempt: 0, want: 30 * time.Second},
		{attempt: 1, want: time.Minute},
		{attempt: 2, want: 2 * time.Minute},
		{attempt: 3, want: 5 * time.Minute},
		{attempt: 4, want: 10 * time.Minute},
		{attempt: 5, want: 15 * time.Minute},
		{attempt: 10, want: 15 * time.Minute},
	}

	for _, test := range tests {
		if got := dnsVerificationRetryInterval(test.attempt, initial, maximum); got != test.want {
			t.Fatalf("attempt %d interval = %s, want %s", test.attempt, got, test.want)
		}
	}
}

func TestJitterDNSVerificationIntervalStaysWithinConfiguredRange(t *testing.T) {
	base := 10 * time.Minute
	for i := 0; i < 100; i++ {
		got := jitterDNSVerificationInterval(base, 10)
		if got < 9*time.Minute || got > 11*time.Minute {
			t.Fatalf("jittered interval = %s, want within [9m, 11m]", got)
		}
	}
}

func TestControlDomainVerificationInfoTreatsOverduePendingChallengeAsExpired(t *testing.T) {
	challenge := &storage.DomainOwnershipChallenge{
		FQDN:        "example.test",
		RecordName:  "_relay-challenge.example.test",
		RecordValue: "relay-domain-verification=token",
		Status:      storage.DomainOwnershipChallengeStatusPending,
		ExpiresAt:   time.Now().UTC().Add(-time.Minute),
	}

	info := controlDomainVerificationInfo(challenge)

	if got, want := info.GetStatus(), controlpb.DomainVerificationStatus_DOMAIN_VERIFICATION_STATUS_EXPIRED; got != want {
		t.Fatalf("status = %s, want %s", got, want)
	}
	if !info.GetCanRequestNewChallenge() {
		t.Fatal("can_request_new_challenge = false, want true")
	}
	if info.GetDnsInstruction() == nil {
		t.Fatal("expired challenge DNS instruction is nil")
	}
}

func TestTunnelVerifiedUpdateDoesNotExposeOldToken(t *testing.T) {
	verifiedAt := time.Now().UTC()
	challenge := &storage.DomainOwnershipChallenge{
		FQDN:        "example.test",
		RecordName:  "_relay-challenge.example.test",
		RecordValue: "relay-domain-verification=token",
		Status:      storage.DomainOwnershipChallengeStatusVerified,
		ExpiresAt:   verifiedAt.Add(time.Hour),
		VerifiedAt:  &verifiedAt,
	}

	update := tunnelDomainVerificationUpdate(challenge)

	if got, want := update.GetStatus(), tunnelpb.DomainVerificationStatus_DOMAIN_VERIFICATION_STATUS_VERIFIED; got != want {
		t.Fatalf("status = %s, want %s", got, want)
	}
	if update.GetRecordName() != "" || update.GetRecordValue() != "" {
		t.Fatal("verified update exposes obsolete DNS proof")
	}
	if got, want := update.GetVerifiedAtUnixMs(), verifiedAt.UnixMilli(); got != want {
		t.Fatalf("verified_at = %d, want %d", got, want)
	}
}

func TestVerifiedChallengeRemainsVerifiedAfterOriginalExpiry(t *testing.T) {
	challenge := &storage.DomainOwnershipChallenge{
		FQDN:      "example.test",
		Status:    storage.DomainOwnershipChallengeStatusVerified,
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}

	info := controlDomainVerificationInfo(challenge)

	if got, want := info.GetStatus(), controlpb.DomainVerificationStatus_DOMAIN_VERIFICATION_STATUS_VERIFIED; got != want {
		t.Fatalf("status = %s, want %s", got, want)
	}
	if info.GetCanRequestNewChallenge() {
		t.Fatal("verified challenge can_request_new_challenge = true, want false")
	}
}
