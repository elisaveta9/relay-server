package storage

import (
	"log"
	"os"
	"strconv"
	"strings"
)

func NormalizeDomain(domain string) (string, error) {
	fqdn := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if !domainPattern.MatchString(fqdn) {
		return "", ErrDomainInvalid
	}
	if len(fqdn) < 3 || len(fqdn) > 253 {
		return "", ErrDomainInvalid
	}
	return fqdn, nil
}

func normalizeFingerprint(fingerprint string) (string, error) {
	fingerprint = normalizeFingerprintForQuery(fingerprint)
	if !fingerprintPattern.MatchString(fingerprint) {
		return "", ErrFingerprintInvalid
	}
	return fingerprint, nil
}

func normalizeFingerprintForQuery(fingerprint string) string {
	fingerprint = strings.TrimSpace(strings.ToLower(fingerprint))
	fingerprint = strings.ReplaceAll(fingerprint, ":", "")
	return fingerprint
}

func normalizePagination(page int, perPage int, maxPerPage int) (int, int) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}
	if perPage > maxPerPage {
		perPage = maxPerPage
	}
	return page, perPage
}

func configuredMaxDomainsPerDevice() int {
	raw := strings.TrimSpace(os.Getenv("RELAY_MAX_DOMAINS_PER_DEVICE"))
	if raw == "" {
		return defaultMaxDomainsPerDevice
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		log.Printf(
			"invalid RELAY_MAX_DOMAINS_PER_DEVICE=%q, using default=%d",
			raw,
			defaultMaxDomainsPerDevice,
		)
		return defaultMaxDomainsPerDevice
	}
	return value
}
