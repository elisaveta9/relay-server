package grpcserver

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"relay/storage"
)

const (
	defaultDNSVerificationWorkerInterval = 5 * time.Second
	defaultDNSVerificationHeartbeat      = time.Minute
	defaultDNSVerificationClaimLease     = 30 * time.Second
	defaultDNSVerificationLookupTimeout  = 5 * time.Second
	defaultDNSVerificationBatchSize      = 32
	defaultDNSVerificationConcurrency    = 8
)

func runDomainVerificationWorker(
	repo *storage.Repository,
	resolver txtResolver,
	stop <-chan struct{},
) {
	interval := configuredDNSVerificationWorkerInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	heartbeat := time.NewTicker(defaultDNSVerificationHeartbeat)
	defer heartbeat.Stop()

	log.Printf(
		"DNS verification worker started: interval=%s heartbeat=%s batch_size=%d concurrency=%d claim_lease=%s lookup_timeout=%s",
		interval,
		defaultDNSVerificationHeartbeat,
		configuredDNSVerificationBatchSize(),
		configuredDNSVerificationConcurrency(),
		configuredDNSVerificationClaimLease(),
		configuredDNSVerificationLookupTimeout(),
	)

	processDomainVerificationWork(repo, resolver)
	for {
		select {
		case <-ticker.C:
			processDomainVerificationWork(repo, resolver)
		case <-heartbeat.C:
			log.Printf("DNS verification worker active: interval=%s", interval)
		case <-stop:
			log.Println("DNS verification worker stopped")
			return
		}
	}
}

func processDomainVerificationWork(repo *storage.Repository, resolver txtResolver) {
	startedAt := time.Now()
	batchSize := configuredDNSVerificationBatchSize()
	lease := configuredDNSVerificationClaimLease()
	lookupTimeout := configuredDNSVerificationLookupTimeout()
	if lease < lookupTimeout+time.Second {
		lease = lookupTimeout + time.Second
	}
	concurrency := configuredDNSVerificationConcurrency()
	claimLimit := minInt(batchSize, concurrency)

	ctx, cancel := context.WithTimeout(context.Background(), lease)
	expired, err := repo.ExpireDueDomainOwnershipChallenges(ctx, batchSize)
	cancel()
	if err != nil {
		log.Printf("expire DNS challenges failed: %v", err)
	} else {
		for i := range expired {
			log.Printf(
				"DNS verification challenge expired: domain=%s challenge_id=%s fingerprint=%s attempts=%d expires_at=%s",
				expired[i].FQDN,
				expired[i].ID,
				expired[i].Device.CertFingerprint,
				expired[i].VerificationAttempts,
				expired[i].ExpiresAt.Format(time.RFC3339),
			)
			notifyDomainVerificationUpdate(repo, &expired[i], false)
		}
	}

	ctx, cancel = context.WithTimeout(context.Background(), lease)
	challenges, err := repo.ClaimDueDomainOwnershipChallenges(ctx, claimLimit, lease)
	cancel()
	if err != nil {
		log.Printf("claim due DNS challenges failed: %v", err)
		return
	}
	if len(challenges) > 0 {
		log.Printf(
			"DNS verification worker claimed due challenges: count=%d claim_limit=%d lease=%s",
			len(challenges),
			claimLimit,
			lease,
		)
	}

	var wg sync.WaitGroup
	for i := range challenges {
		wg.Add(1)
		go func(challenge *storage.DomainOwnershipChallenge) {
			defer wg.Done()
			verifyClaimedDomainOwnershipChallenge(repo, resolver, challenge)
		}(&challenges[i])
	}
	wg.Wait()
	if len(expired) > 0 || len(challenges) > 0 {
		log.Printf(
			"DNS verification worker cycle completed: expired=%d claimed=%d duration=%s",
			len(expired),
			len(challenges),
			time.Since(startedAt).Round(time.Millisecond),
		)
	}
}

func verifyClaimedDomainOwnershipChallenge(
	repo *storage.Repository,
	resolver txtResolver,
	challenge *storage.DomainOwnershipChallenge,
) {
	timeout := configuredDNSVerificationLookupTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	records, lookupErr := resolver.LookupTXT(ctx, absoluteDNSName(challenge.RecordName))
	cancel()

	if lookupErr != nil || !containsTXTRecord(records, challenge.RecordValue) {
		message := "required DNS TXT record was not found"
		if lookupErr != nil {
			message = fmt.Sprintf("DNS TXT lookup failed: %v", lookupErr)
		}
		next := nextDNSVerificationAt(challenge, time.Now().UTC())
		updated, err := repo.RecordDomainOwnershipVerificationFailure(
			context.Background(),
			challenge.ID,
			challenge.RecordValue,
			message,
			next,
		)
		if err != nil {
			log.Printf("record DNS verification retry failed: domain=%s err=%v", challenge.FQDN, err)
			return
		}
		if updated {
			challenge.LastError = message
			challenge.NextVerificationAt = &next
			log.Printf(
				"DNS verification retry scheduled: domain=%s challenge_id=%s fingerprint=%s attempts=%d next_verification_at=%s expires_at=%s reason=%q",
				challenge.FQDN,
				challenge.ID,
				challenge.Device.CertFingerprint,
				challenge.VerificationAttempts,
				next.Format(time.RFC3339),
				challenge.ExpiresAt.Format(time.RFC3339),
				message,
			)
			notifyDomainVerificationUpdate(repo, challenge, false)
		} else {
			log.Printf(
				"DNS verification retry skipped because challenge changed: domain=%s challenge_id=%s fingerprint=%s",
				challenge.FQDN,
				challenge.ID,
				challenge.Device.CertFingerprint,
			)
		}
		return
	}

	_, err := repo.CompleteDomainOwnershipChallenge(
		context.Background(),
		challenge.Device.CertFingerprint,
		challenge.FQDN,
		challenge.RecordValue,
	)
	if err != nil {
		log.Printf("complete automatic DNS verification failed: domain=%s err=%v", challenge.FQDN, err)
		return
	}

	now := time.Now().UTC()
	challenge.Status = storage.DomainOwnershipChallengeStatusVerified
	challenge.NextVerificationAt = nil
	challenge.LastError = ""
	challenge.VerifiedAt = &now
	log.Printf(
		"DNS verification completed: domain=%s challenge_id=%s fingerprint=%s attempts=%d verified_at=%s",
		challenge.FQDN,
		challenge.ID,
		challenge.Device.CertFingerprint,
		challenge.VerificationAttempts,
		now.Format(time.RFC3339),
	)
	notifyDomainVerificationUpdate(repo, challenge, true)
}

func configuredDNSVerificationWorkerInterval() time.Duration {
	return time.Duration(envInt(
		"RELAY_DNS_VERIFY_WORKER_INTERVAL_SECONDS",
		int(defaultDNSVerificationWorkerInterval/time.Second),
	)) * time.Second
}

func configuredDNSVerificationBatchSize() int {
	return envInt("RELAY_DNS_VERIFY_WORKER_BATCH_SIZE", defaultDNSVerificationBatchSize)
}

func configuredDNSVerificationConcurrency() int {
	return envInt("RELAY_DNS_VERIFY_WORKER_CONCURRENCY", defaultDNSVerificationConcurrency)
}

func configuredDNSVerificationClaimLease() time.Duration {
	return time.Duration(envInt(
		"RELAY_DNS_VERIFY_CLAIM_LEASE_SECONDS",
		int(defaultDNSVerificationClaimLease/time.Second),
	)) * time.Second
}

func configuredDNSVerificationLookupTimeout() time.Duration {
	return time.Duration(envInt(
		"RELAY_DNS_VERIFY_LOOKUP_TIMEOUT_SECONDS",
		int(defaultDNSVerificationLookupTimeout/time.Second),
	)) * time.Second
}

func minInt(left int, right int) int {
	if left < right {
		return left
	}
	return right
}
