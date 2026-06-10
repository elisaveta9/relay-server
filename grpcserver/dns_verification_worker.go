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
	interval := time.Duration(envInt(
		"RELAY_DNS_VERIFY_WORKER_INTERVAL_SECONDS",
		int(defaultDNSVerificationWorkerInterval/time.Second),
	)) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	processDomainVerificationWork(repo, resolver)
	for {
		select {
		case <-ticker.C:
			processDomainVerificationWork(repo, resolver)
		case <-stop:
			return
		}
	}
}

func processDomainVerificationWork(repo *storage.Repository, resolver txtResolver) {
	batchSize := envInt("RELAY_DNS_VERIFY_WORKER_BATCH_SIZE", defaultDNSVerificationBatchSize)
	ctx, cancel := context.WithTimeout(context.Background(), defaultDNSVerificationClaimLease)
	expired, err := repo.ExpireDueDomainOwnershipChallenges(ctx, batchSize)
	cancel()
	if err != nil {
		log.Printf("expire DNS challenges failed: %v", err)
	} else {
		for i := range expired {
			notifyDomainVerificationUpdate(repo, &expired[i], false)
		}
	}

	lease := time.Duration(envInt(
		"RELAY_DNS_VERIFY_CLAIM_LEASE_SECONDS",
		int(defaultDNSVerificationClaimLease/time.Second),
	)) * time.Second
	lookupTimeout := configuredDNSVerificationLookupTimeout()
	if lease < lookupTimeout+time.Second {
		lease = lookupTimeout + time.Second
	}
	concurrency := envInt("RELAY_DNS_VERIFY_WORKER_CONCURRENCY", defaultDNSVerificationConcurrency)
	claimLimit := minInt(batchSize, concurrency)
	ctx, cancel = context.WithTimeout(context.Background(), lease)
	challenges, err := repo.ClaimDueDomainOwnershipChallenges(ctx, claimLimit, lease)
	cancel()
	if err != nil {
		log.Printf("claim due DNS challenges failed: %v", err)
		return
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
			notifyDomainVerificationUpdate(repo, challenge, false)
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
	notifyDomainVerificationUpdate(repo, challenge, true)
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
