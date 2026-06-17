package storage

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (r *Repository) GetOrCreateDomainOwnershipChallenge(
	ctx context.Context,
	fingerprint string,
	fqdn string,
	ttl time.Duration,
	initialVerificationDelay time.Duration,
	maxActive int,
) (*DomainOwnershipChallenge, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	fqdn, err = NormalizeDomain(fqdn)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 || initialVerificationDelay < 0 {
		return nil, fmt.Errorf("create domain ownership challenge: invalid ttl")
	}
	if maxActive <= 0 {
		return nil, fmt.Errorf("create domain ownership challenge: invalid active challenge limit")
	}

	var challenge DomainOwnershipChallenge
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var device Device
		if err := upsertActiveDevice(tx, fingerprint, &device); err != nil {
			return err
		}

		var domain Domain
		err := tx.Where("fqdn = ?", fqdn).First(&domain).Error
		if err == nil {
			if domain.DeviceID != device.ID {
				return ErrDomainAlreadyUsed
			}
			return ErrDomainAlreadyRegistered
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("check domain registration: %w", err)
		}

		now := time.Now().UTC()
		err = tx.Where("device_id = ? AND fqdn = ?", device.ID, fqdn).First(&challenge).Error
		if err == nil &&
			challenge.Status == DomainOwnershipChallengeStatusPending &&
			challenge.ExpiresAt.After(now) {
			return nil
		}
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("load domain ownership challenge: %w", err)
		}
		if err == nil {
			if err := tx.Delete(&challenge).Error; err != nil {
				return fmt.Errorf("rotate domain ownership challenge: %w", err)
			}
		}

		var activeCount int64
		if err := tx.Model(&DomainOwnershipChallenge{}).
			Where(
				"device_id = ? AND status = ? AND expires_at > ?",
				device.ID,
				DomainOwnershipChallengeStatusPending,
				now,
			).
			Count(&activeCount).Error; err != nil {
			return fmt.Errorf("count active domain ownership challenges: %w", err)
		}
		if activeCount >= int64(maxActive) {
			return ErrDomainOwnershipChallengeLimit
		}

		token, err := newDomainOwnershipToken()
		if err != nil {
			return err
		}
		challenge = DomainOwnershipChallenge{
			DeviceID: device.ID,
			FQDN:     fqdn,
		}
		challenge.RecordName = domainOwnershipRecordPrefix + fqdn
		challenge.RecordValue = "relay-domain-verification=" + token
		challenge.Status = DomainOwnershipChallengeStatusPending
		challenge.ExpiresAt = now.Add(ttl)
		nextVerificationAt := now.Add(initialVerificationDelay)
		challenge.NextVerificationAt = &nextVerificationAt
		challenge.VerificationAttempts = 0
		challenge.LastVerificationAt = nil
		challenge.LastError = ""
		challenge.VerifiedAt = nil
		challenge.CreatedAt = now
		challenge.UpdatedAt = now
		if err := tx.Create(&challenge).Error; err != nil {
			return fmt.Errorf("create domain ownership challenge: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (r *Repository) BeginDomainOwnershipVerification(
	ctx context.Context,
	fingerprint string,
	fqdn string,
	recordValue string,
	maxAttempts uint32,
	minInterval time.Duration,
) (*DomainOwnershipChallenge, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	fqdn, err = NormalizeDomain(fqdn)
	if err != nil {
		return nil, err
	}
	if maxAttempts == 0 || minInterval < 0 {
		return nil, fmt.Errorf("begin domain ownership verification: invalid limits")
	}

	var challenge DomainOwnershipChallenge
	expired := false
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var device Device
		if err := tx.Where("cert_fingerprint = ?", fingerprint).First(&device).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrDomainOwnershipChallengeNotFound
			}
			return fmt.Errorf("load challenge device: %w", err)
		}

		challenge, err = lockPendingDomainOwnershipChallenge(tx, device.ID, fqdn)
		if err != nil {
			return err
		}

		now := time.Now().UTC()
		if !challenge.ExpiresAt.After(now) {
			if err := expireDomainOwnershipChallenge(tx, &challenge); err != nil {
				return err
			}
			expired = true
			return nil
		}
		if challenge.RecordValue != recordValue {
			return ErrDomainOwnershipProofInvalid
		}
		if challenge.VerificationAttempts >= maxAttempts {
			return ErrDomainOwnershipVerificationLimit
		}
		if challenge.LastVerificationAt != nil && now.Sub(*challenge.LastVerificationAt) < minInterval {
			return ErrDomainOwnershipVerificationWait
		}

		challenge.VerificationAttempts++
		challenge.LastVerificationAt = &now
		nextVerificationAt := now.Add(minInterval)
		challenge.NextVerificationAt = &nextVerificationAt
		if err := tx.Model(&challenge).Updates(map[string]any{
			"verification_attempts": challenge.VerificationAttempts,
			"last_verification_at":  challenge.LastVerificationAt,
			"next_verification_at":  challenge.NextVerificationAt,
			"last_error":            "",
		}).Error; err != nil {
			return fmt.Errorf("record domain ownership verification attempt: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if expired {
		return nil, ErrDomainOwnershipChallengeExpired
	}
	return &challenge, nil
}

func (r *Repository) DeleteExpiredDomainOwnershipChallenges(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).
		Model(&DomainOwnershipChallenge{}).
		Where(
			"status = ? AND expires_at <= ?",
			DomainOwnershipChallengeStatusPending,
			time.Now().UTC(),
		).
		Updates(map[string]any{
			"status":               DomainOwnershipChallengeStatusExpired,
			"next_verification_at": nil,
			"last_error":           "DNS challenge expired",
		})
	if result.Error != nil {
		return 0, fmt.Errorf("expire domain ownership challenges: %w", result.Error)
	}
	return result.RowsAffected, nil
}

func (r *Repository) ListDomainOwnershipChallengesForFingerprint(
	ctx context.Context,
	fingerprint string,
) ([]DomainOwnershipChallenge, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	var challenges []DomainOwnershipChallenge
	if err := r.db.WithContext(ctx).
		Joins("JOIN devices ON devices.id = domain_ownership_challenges.device_id").
		Where("devices.cert_fingerprint = ?", fingerprint).
		Order("domain_ownership_challenges.fqdn ASC").
		Find(&challenges).Error; err != nil {
		return nil, fmt.Errorf("list domain ownership challenges: %w", err)
	}
	return challenges, nil
}

func (r *Repository) ClaimDueDomainOwnershipChallenges(
	ctx context.Context,
	limit int,
	lease time.Duration,
) ([]DomainOwnershipChallenge, error) {
	if limit <= 0 || lease <= 0 {
		return nil, fmt.Errorf("claim DNS challenges: invalid limit or lease")
	}

	now := time.Now().UTC()
	leaseUntil := now.Add(lease)
	var claimed []DomainOwnershipChallenge
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var challenges []DomainOwnershipChallenge
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where(
				"status = ? AND expires_at > ? AND (next_verification_at IS NULL OR next_verification_at <= ?)",
				DomainOwnershipChallengeStatusPending,
				now,
				now,
			).
			Order("next_verification_at ASC NULLS FIRST").
			Limit(limit).
			Find(&challenges).Error; err != nil {
			return fmt.Errorf("lock due DNS challenges: %w", err)
		}

		for i := range challenges {
			challenges[i].VerificationAttempts++
			challenges[i].LastVerificationAt = &now
			challenges[i].NextVerificationAt = &leaseUntil
			if err := tx.Model(&challenges[i]).Updates(map[string]any{
				"verification_attempts": challenges[i].VerificationAttempts,
				"last_verification_at":  challenges[i].LastVerificationAt,
				"next_verification_at":  challenges[i].NextVerificationAt,
				"last_error":            "",
			}).Error; err != nil {
				return fmt.Errorf("claim DNS challenge: %w", err)
			}
		}

		claimed = challenges
		if len(claimed) == 0 {
			return nil
		}
		ids := make([]uuid.UUID, 0, len(claimed))
		for _, challenge := range claimed {
			ids = append(ids, challenge.ID)
		}
		if err := tx.Preload("Device").Find(&claimed, "id IN ?", ids).Error; err != nil {
			return fmt.Errorf("load claimed DNS challenge devices: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

func (r *Repository) RecordDomainOwnershipVerificationFailure(
	ctx context.Context,
	id uuid.UUID,
	recordValue string,
	lastError string,
	nextVerificationAt time.Time,
) (bool, error) {
	if id == uuid.Nil {
		return false, fmt.Errorf("record DNS verification failure: nil challenge id")
	}
	result := r.db.WithContext(ctx).
		Model(&DomainOwnershipChallenge{}).
		Where(
			"id = ? AND status = ? AND record_value = ?",
			id,
			DomainOwnershipChallengeStatusPending,
			recordValue,
		).
		Updates(map[string]any{
			"last_error":           strings.TrimSpace(lastError),
			"next_verification_at": nextVerificationAt.UTC(),
		})
	if result.Error != nil {
		return false, fmt.Errorf("record DNS verification failure: %w", result.Error)
	}
	return result.RowsAffected > 0, nil
}

func (r *Repository) ExpireDueDomainOwnershipChallenges(
	ctx context.Context,
	limit int,
) ([]DomainOwnershipChallenge, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("expire DNS challenges: invalid limit")
	}

	now := time.Now().UTC()
	var expired []DomainOwnershipChallenge
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where(
				"status = ? AND expires_at <= ?",
				DomainOwnershipChallengeStatusPending,
				now,
			).
			Order("expires_at ASC").
			Limit(limit).
			Find(&expired).Error; err != nil {
			return fmt.Errorf("lock expired DNS challenges: %w", err)
		}
		for i := range expired {
			expired[i].Status = DomainOwnershipChallengeStatusExpired
			expired[i].NextVerificationAt = nil
			expired[i].LastError = "DNS challenge expired"
			if err := tx.Model(&expired[i]).Updates(map[string]any{
				"status":               expired[i].Status,
				"next_verification_at": nil,
				"last_error":           expired[i].LastError,
			}).Error; err != nil {
				return fmt.Errorf("expire DNS challenge: %w", err)
			}
		}
		if len(expired) == 0 {
			return nil
		}
		ids := make([]uuid.UUID, 0, len(expired))
		for _, challenge := range expired {
			ids = append(ids, challenge.ID)
		}
		if err := tx.Preload("Device").Find(&expired, "id IN ?", ids).Error; err != nil {
			return fmt.Errorf("load expired DNS challenge devices: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return expired, nil
}

func (r *Repository) GetOwnedDomain(ctx context.Context, fingerprint string, fqdn string) (*Domain, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	fqdn, err = NormalizeDomain(fqdn)
	if err != nil {
		return nil, err
	}

	var domain Domain
	err = r.db.WithContext(ctx).
		Joins("JOIN devices ON devices.id = domains.device_id").
		Where("devices.cert_fingerprint = ? AND domains.fqdn = ?", fingerprint, fqdn).
		First(&domain).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrDomainNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load owned domain: %w", err)
	}
	return &domain, nil
}

func (r *Repository) GetDomainOwnershipChallenge(
	ctx context.Context,
	fingerprint string,
	fqdn string,
) (*DomainOwnershipChallenge, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	fqdn, err = NormalizeDomain(fqdn)
	if err != nil {
		return nil, err
	}

	var challenge DomainOwnershipChallenge
	err = r.db.WithContext(ctx).
		Joins("JOIN devices ON devices.id = domain_ownership_challenges.device_id").
		Where("devices.cert_fingerprint = ? AND domain_ownership_challenges.fqdn = ?", fingerprint, fqdn).
		First(&challenge).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrDomainOwnershipChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load domain ownership challenge: %w", err)
	}
	if challenge.Status != DomainOwnershipChallengeStatusPending {
		return nil, ErrDomainOwnershipChallengeNotFound
	}
	if !challenge.ExpiresAt.After(time.Now().UTC()) {
		result := r.db.WithContext(ctx).
			Model(&DomainOwnershipChallenge{}).
			Where("id = ? AND status = ?", challenge.ID, DomainOwnershipChallengeStatusPending).
			Updates(map[string]any{
				"status":               DomainOwnershipChallengeStatusExpired,
				"next_verification_at": nil,
				"last_error":           "DNS challenge expired",
			})
		if result.Error != nil {
			return nil, fmt.Errorf("expire domain ownership challenge: %w", result.Error)
		}
		return nil, ErrDomainOwnershipChallengeExpired
	}
	return &challenge, nil
}

func (r *Repository) CompleteDomainOwnershipChallenge(
	ctx context.Context,
	fingerprint string,
	fqdn string,
	recordValue string,
) (*Domain, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	fqdn, err = NormalizeDomain(fqdn)
	if err != nil {
		return nil, err
	}

	var out Domain
	expired := false
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var device Device
		if err := upsertActiveDevice(tx, fingerprint, &device); err != nil {
			return err
		}

		challenge, err := lockPendingDomainOwnershipChallenge(tx, device.ID, fqdn)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if !challenge.ExpiresAt.After(now) {
			if err := expireDomainOwnershipChallenge(tx, &challenge); err != nil {
				return err
			}
			expired = true
			return nil
		}
		if challenge.RecordValue != recordValue {
			return ErrDomainOwnershipProofInvalid
		}

		domain, err := registerDomainForDevice(tx, device.ID, fqdn)
		if err != nil {
			return err
		}
		out = domain

		if err := writeDomainHistory(tx, &domain.ID, &device.ID, domain.FQDN, DomainActionRegister); err != nil {
			return err
		}
		challenge.Status = DomainOwnershipChallengeStatusVerified
		challenge.NextVerificationAt = nil
		challenge.LastError = ""
		challenge.VerifiedAt = &now
		if err := tx.Model(&challenge).Updates(map[string]any{
			"status":               challenge.Status,
			"next_verification_at": nil,
			"last_error":           "",
			"verified_at":          challenge.VerifiedAt,
		}).Error; err != nil {
			return fmt.Errorf("complete domain ownership challenge: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if expired {
		return nil, ErrDomainOwnershipChallengeExpired
	}
	return &out, nil
}

func newDomainOwnershipToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate domain ownership token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func lockPendingDomainOwnershipChallenge(tx *gorm.DB, deviceID uuid.UUID, fqdn string) (DomainOwnershipChallenge, error) {
	var challenge DomainOwnershipChallenge
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("device_id = ? AND fqdn = ?", deviceID, fqdn).
		First(&challenge).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return DomainOwnershipChallenge{}, ErrDomainOwnershipChallengeNotFound
	}
	if err != nil {
		return DomainOwnershipChallenge{}, fmt.Errorf("lock domain ownership challenge: %w", err)
	}
	if challenge.Status != DomainOwnershipChallengeStatusPending {
		return DomainOwnershipChallenge{}, ErrDomainOwnershipChallengeNotFound
	}
	return challenge, nil
}

func expireDomainOwnershipChallenge(tx *gorm.DB, challenge *DomainOwnershipChallenge) error {
	challenge.Status = DomainOwnershipChallengeStatusExpired
	challenge.NextVerificationAt = nil
	challenge.LastError = "DNS challenge expired"
	if err := tx.Model(challenge).Updates(map[string]any{
		"status":               challenge.Status,
		"next_verification_at": nil,
		"last_error":           challenge.LastError,
	}).Error; err != nil {
		return fmt.Errorf("expire domain ownership challenge: %w", err)
	}
	return nil
}
