package storage

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrFingerprintInvalid               = errors.New("invalid certificate fingerprint")
	ErrDeviceRevoked                    = errors.New("device is revoked")
	ErrDomainInvalid                    = errors.New("invalid domain")
	ErrDomainAlreadyUsed                = errors.New("domain is already registered to another device")
	ErrDomainNotOwned                   = errors.New("domain is not registered to this device")
	ErrDomainDisabled                   = errors.New("domain is disabled")
	ErrDomainNotFound                   = errors.New("domain not found")
	ErrDomainAlreadyRegistered          = errors.New("domain is already registered to this device")
	ErrDomainOwnershipChallengeNotFound = errors.New("domain ownership challenge not found")
	ErrDomainOwnershipChallengeExpired  = errors.New("domain ownership challenge expired")
	ErrDomainOwnershipProofInvalid      = errors.New("domain ownership proof is invalid")
	ErrDomainOwnershipChallengeLimit    = errors.New("domain ownership challenge limit reached")
	ErrDomainOwnershipVerificationLimit = errors.New("domain ownership verification limit reached")
	ErrDomainOwnershipVerificationWait  = errors.New("domain ownership verification attempted too soon")

	fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	labelPattern       = `(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])`
	domainPattern      = regexp.MustCompile(`^` + labelPattern + `(\.` + labelPattern + `)*$`)
)

type Repository struct {
	db *gorm.DB
}

const domainOwnershipRecordPrefix = "_relay-challenge."

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

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

		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("device_id = ? AND fqdn = ?", device.ID, fqdn).
			First(&challenge).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrDomainOwnershipChallengeNotFound
		}
		if err != nil {
			return fmt.Errorf("lock domain ownership challenge: %w", err)
		}

		if challenge.Status != DomainOwnershipChallengeStatusPending {
			return ErrDomainOwnershipChallengeNotFound
		}
		now := time.Now().UTC()
		if !challenge.ExpiresAt.After(now) {
			challenge.Status = DomainOwnershipChallengeStatusExpired
			challenge.NextVerificationAt = nil
			challenge.LastError = "DNS challenge expired"
			if err := tx.Model(&challenge).Updates(map[string]any{
				"status":               challenge.Status,
				"next_verification_at": nil,
				"last_error":           challenge.LastError,
			}).Error; err != nil {
				return fmt.Errorf("expire domain ownership challenge: %w", err)
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

		var challenge DomainOwnershipChallenge
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("device_id = ? AND fqdn = ?", device.ID, fqdn).
			First(&challenge).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrDomainOwnershipChallengeNotFound
		}
		if err != nil {
			return fmt.Errorf("lock domain ownership challenge: %w", err)
		}
		if challenge.Status != DomainOwnershipChallengeStatusPending {
			return ErrDomainOwnershipChallengeNotFound
		}
		now := time.Now().UTC()
		if !challenge.ExpiresAt.After(now) {
			challenge.Status = DomainOwnershipChallengeStatusExpired
			challenge.NextVerificationAt = nil
			challenge.LastError = "DNS challenge expired"
			if err := tx.Model(&challenge).Updates(map[string]any{
				"status":               challenge.Status,
				"next_verification_at": nil,
				"last_error":           challenge.LastError,
			}).Error; err != nil {
				return fmt.Errorf("expire domain ownership challenge: %w", err)
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

		hist := DomainHistory{
			DomainID: &domain.ID,
			DeviceID: &device.ID,
			FQDN:     domain.FQDN,
			Action:   DomainActionRegister,
		}
		if err := tx.Create(&hist).Error; err != nil {
			return fmt.Errorf("write domain history: %w", err)
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

func (r *Repository) RegisterDeviceWithDomains(ctx context.Context, fingerprint string, domains []string) (*Device, []Domain, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, nil, err
	}

	var device Device
	registered := make([]Domain, 0, len(domains))

	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := upsertActiveDevice(tx, fingerprint, &device); err != nil {
			return err
		}

		for _, raw := range domains {
			fqdn, err := NormalizeDomain(raw)
			if err != nil {
				return err
			}

			domain, err := registerDomainForDevice(tx, device.ID, fqdn)
			if err != nil {
				return err
			}
			registered = append(registered, domain)

			hist := DomainHistory{
				DomainID: &domain.ID,
				DeviceID: &device.ID,
				FQDN:     domain.FQDN,
				Action:   DomainActionRegister,
			}
			if err := tx.Create(&hist).Error; err != nil {
				return fmt.Errorf("write domain history: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return &device, registered, nil
}

func (r *Repository) RegisterDomainForFingerprint(ctx context.Context, fingerprint string, fqdn string) (*Domain, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	fqdn, err = NormalizeDomain(fqdn)
	if err != nil {
		return nil, err
	}

	var out Domain
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var device Device
		if err := upsertActiveDevice(tx, fingerprint, &device); err != nil {
			return err
		}

		domain, err := registerDomainForDevice(tx, device.ID, fqdn)
		if err != nil {
			return err
		}
		out = domain

		hist := DomainHistory{
			DomainID: &domain.ID,
			DeviceID: &device.ID,
			FQDN:     domain.FQDN,
			Action:   DomainActionRegister,
		}
		if err := tx.Create(&hist).Error; err != nil {
			return fmt.Errorf("write domain history: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &out, nil
}

func (r *Repository) ListDomains(ctx context.Context) ([]Domain, error) {
	var domains []Domain
	if err := r.db.WithContext(ctx).
		Order("fqdn ASC").
		Find(&domains).Error; err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	return domains, nil
}

func (r *Repository) GetDomainByID(ctx context.Context, id uuid.UUID) (*Domain, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("get domain by id: nil id")
	}

	var domain Domain
	if err := r.db.WithContext(ctx).First(&domain, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDomainNotFound
		}
		return nil, fmt.Errorf("get domain by id: %w", err)
	}
	return &domain, nil
}

func (r *Repository) UpdateDomainStatus(ctx context.Context, id uuid.UUID, status DomainStatus) (*Domain, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("update domain status: nil id")
	}

	switch status {
	case DomainStatusRegistered, DomainStatusDisabled:
	default:
		return nil, fmt.Errorf("update domain status: unknown status")
	}

	var domain Domain
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&domain, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrDomainNotFound
			}
			return fmt.Errorf("load domain for update: %w", err)
		}

		if domain.Status == status {
			return nil
		}

		if err := tx.Model(&domain).Update("status", status).Error; err != nil {
			return fmt.Errorf("update domain status: %w", err)
		}

		domain.Status = status

		action := DomainActionEnable
		if status == DomainStatusDisabled {
			action = DomainActionDisable
		}

		hist := DomainHistory{
			DomainID: &domain.ID,
			DeviceID: &domain.DeviceID,
			FQDN:     domain.FQDN,
			Action:   action,
		}
		if err := tx.Create(&hist).Error; err != nil {
			return fmt.Errorf("write domain history: %w", err)
		}

		return nil
	})

	if err != nil {
		if errors.Is(err, ErrDomainNotFound) {
			return nil, ErrDomainNotFound
		}
		return nil, err
	}
	return &domain, nil
}

func (r *Repository) DisableDomainByID(ctx context.Context, id uuid.UUID) (*Domain, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("disable domain: nil id")
	}

	var domain Domain
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&domain, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrDomainNotFound
			}
			return fmt.Errorf("load domain for disable: %w", err)
		}

		if err := tx.Model(&domain).Update("status", DomainStatusDisabled).Error; err != nil {
			return fmt.Errorf("disable domain: %w", err)
		}
		domain.Status = DomainStatusDisabled

		hist := DomainHistory{
			DomainID: &domain.ID,
			DeviceID: &domain.DeviceID,
			FQDN:     domain.FQDN,
			Action:   DomainActionDisable,
		}
		if err := tx.Create(&hist).Error; err != nil {
			return fmt.Errorf("write domain history: %w", err)
		}

		return nil
	})

	if err != nil {
		if errors.Is(err, ErrDomainNotFound) {
			return nil, ErrDomainNotFound
		}
		return nil, err
	}
	return &domain, nil
}

func (r *Repository) DeleteDomainByID(ctx context.Context, id uuid.UUID) (*Domain, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("delete domain: nil id")
	}

	var out Domain
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var domain Domain
		if err := tx.First(&domain, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrDomainNotFound
			}
			return fmt.Errorf("load domain for delete: %w", err)
		}

		if err := tx.Delete(&domain).Error; err != nil {
			return fmt.Errorf("delete domain: %w", err)
		}
		if err := tx.Where(
			"device_id = ? AND fqdn = ?",
			domain.DeviceID,
			domain.FQDN,
		).Delete(&DomainOwnershipChallenge{}).Error; err != nil {
			return fmt.Errorf("delete domain ownership challenge: %w", err)
		}

		hist := DomainHistory{
			DomainID: &domain.ID,
			DeviceID: &domain.DeviceID,
			FQDN:     domain.FQDN,
			Action:   DomainActionDelete,
		}
		if err := tx.Create(&hist).Error; err != nil {
			return fmt.Errorf("write domain history: %w", err)
		}

		out = domain
		return nil
	})

	if err != nil {
		if errors.Is(err, ErrDomainNotFound) {
			return nil, ErrDomainNotFound
		}
		return nil, err
	}

	return &out, nil
}

func (r *Repository) ListDomainsForFingerprint(ctx context.Context, fingerprint string) ([]Domain, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	var domains []Domain
	if err := r.db.WithContext(ctx).
		Joins("JOIN devices ON devices.id = domains.device_id").
		Where("devices.cert_fingerprint = ?", fingerprint).
		Order("domains.fqdn ASC").
		Find(&domains).Error; err != nil {
		return nil, fmt.Errorf("list owned domains: %w", err)
	}
	return domains, nil
}

func (r *Repository) DeleteDomain(ctx context.Context, fqdn string) (*Domain, bool, error) {
	fqdn, err := NormalizeDomain(fqdn)
	if err != nil {
		return nil, false, err
	}

	var out Domain
	deleted := false

	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var domain Domain
		if err := tx.Where("fqdn = ?", fqdn).First(&domain).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return fmt.Errorf("find domain before delete: %w", err)
		}

		if err := tx.Delete(&domain).Error; err != nil {
			return fmt.Errorf("delete domain: %w", err)
		}
		if err := tx.Where(
			"device_id = ? AND fqdn = ?",
			domain.DeviceID,
			domain.FQDN,
		).Delete(&DomainOwnershipChallenge{}).Error; err != nil {
			return fmt.Errorf("delete domain ownership challenge: %w", err)
		}

		hist := DomainHistory{
			DomainID: &domain.ID,
			DeviceID: &domain.DeviceID,
			FQDN:     domain.FQDN,
			Action:   DomainActionDelete,
		}
		if err := tx.Create(&hist).Error; err != nil {
			return fmt.Errorf("write domain history: %w", err)
		}

		out = domain
		deleted = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}

	if !deleted {
		return nil, false, nil
	}
	return &out, true, nil
}

func (r *Repository) DeleteOwnedDomain(ctx context.Context, fingerprint string, fqdn string) (bool, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return false, err
	}

	fqdn, err = NormalizeDomain(fqdn)
	if err != nil {
		return false, err
	}

	deleted := false

	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var device Device
		if err := tx.Where("cert_fingerprint = ?", fingerprint).First(&device).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return fmt.Errorf("find device before deleting owned domain: %w", err)
		}

		var domain Domain
		domainErr := tx.
			Where("fqdn = ? AND device_id = ?", fqdn, device.ID).
			First(&domain).Error
		if domainErr != nil && !errors.Is(domainErr, gorm.ErrRecordNotFound) {
			return fmt.Errorf("find owned domain before delete: %w", domainErr)
		}

		if domainErr == nil {
			if err := tx.Delete(&domain).Error; err != nil {
				return fmt.Errorf("delete owned domain: %w", err)
			}

			hist := DomainHistory{
				DomainID: &domain.ID,
				DeviceID: &domain.DeviceID,
				FQDN:     domain.FQDN,
				Action:   DomainActionDelete,
			}
			if err := tx.Create(&hist).Error; err != nil {
				return fmt.Errorf("write domain history: %w", err)
			}
			deleted = true
		}

		result := tx.Where(
			"device_id = ? AND fqdn = ?",
			device.ID,
			fqdn,
		).Delete(&DomainOwnershipChallenge{})
		if result.Error != nil {
			return fmt.Errorf("delete owned domain challenge: %w", result.Error)
		}
		if result.RowsAffected > 0 {
			deleted = true
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	return deleted, nil
}

func (r *Repository) AuthorizeBind(ctx context.Context, fingerprint string, fqdn string) (*Domain, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	fqdn, err = NormalizeDomain(fqdn)
	if err != nil {
		return nil, err
	}

	var domain Domain
	err = r.db.WithContext(ctx).Where("fqdn = ?", fqdn).First(&domain).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrDomainNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("authorize bind: %w", err)
	}

	var device Device
	if err := r.db.WithContext(ctx).First(&device, "id = ?", domain.DeviceID).Error; err != nil {
		return nil, fmt.Errorf("load domain owner: %w", err)
	}
	if device.CertFingerprint != fingerprint {
		return nil, ErrDomainNotOwned
	}
	if domain.Status == DomainStatusDisabled {
		return nil, ErrDomainDisabled
	}
	if device.Status == DeviceStatusRevoked {
		return nil, ErrDeviceRevoked
	}

	return &domain, nil
}

func (r *Repository) AddDomainHistory(ctx context.Context, domainID *uuid.UUID, deviceID *uuid.UUID, fqdn string, action DomainHistoryAction) error {
	hist := DomainHistory{
		DomainID: domainID,
		DeviceID: deviceID,
		FQDN:     fqdn,
		Action:   action,
	}
	if err := r.db.WithContext(ctx).Create(&hist).Error; err != nil {
		return fmt.Errorf("write domain history: %w", err)
	}
	return nil
}

// AddDomainHistoryForFingerprint записывает историю, используя устройство, определенное по отпечатку
// Если устройство определить не удается, выполняется запись истории без DeviceID
func (r *Repository) AddDomainHistoryForFingerprint(
	ctx context.Context,
	fingerprint string,
	domain string,
	action DomainHistoryAction,
) error {
	fqdn, err := NormalizeDomain(domain)
	if err != nil {
		return err
	}

	fingerprint, err = normalizeFingerprint(fingerprint)
	if err != nil {
		return err
	}

	var ownedDomain Domain
	err = r.db.WithContext(ctx).
		Joins("JOIN devices ON devices.id = domains.device_id").
		Where("domains.fqdn = ? AND devices.cert_fingerprint = ?", fqdn, fingerprint).
		First(&ownedDomain).Error
	if err == nil {
		return r.AddDomainHistory(ctx, &ownedDomain.ID, &ownedDomain.DeviceID, ownedDomain.FQDN, action)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("lookup domain by fingerprint: %w", err)
	}

	deviceID, err := r.GetDeviceIDForFingerprint(ctx, fingerprint)
	if err == nil {
		return r.AddDomainHistory(ctx, nil, &deviceID, fqdn, action)
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.AddDomainHistory(ctx, nil, nil, fqdn, action)
	}

	return err
}

// GetDeviceIDForFingerprint определяет идентификатор устройства по отпечатку его сертификата
func (r *Repository) GetDeviceIDForFingerprint(ctx context.Context, fingerprint string) (uuid.UUID, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return uuid.Nil, err
	}
	var device Device
	if err := r.db.WithContext(ctx).Where("cert_fingerprint = ?", fingerprint).First(&device).Error; err != nil {
		return uuid.Nil, fmt.Errorf("lookup device by fingerprint: %w", err)
	}
	return device.ID, nil
}

func (r *Repository) TouchDeviceRegistration(ctx context.Context, fingerprint string) (*Device, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	var device Device
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return upsertActiveDevice(tx, fingerprint, &device)
	})
	if err != nil {
		return nil, err
	}
	return &device, nil
}

func (r *Repository) OpenDeviceSession(ctx context.Context, fingerprint string) (*DeviceSession, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	var session DeviceSession
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var device Device
		if err := upsertActiveDevice(tx, fingerprint, &device); err != nil {
			return err
		}

		session = DeviceSession{
			DeviceID: device.ID,
			OpenedAt: time.Now().UTC(),
		}
		if err := tx.Create(&session).Error; err != nil {
			return fmt.Errorf("create device session: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (r *Repository) CloseDeviceSession(ctx context.Context, sessionID uuid.UUID) error {
	if sessionID == uuid.Nil {
		return nil
	}

	now := time.Now().UTC()
	if err := r.db.WithContext(ctx).
		Model(&DeviceSession{}).
		Where("id = ? AND closed_at IS NULL", sessionID).
		Update("closed_at", now).Error; err != nil {
		return fmt.Errorf("close device session: %w", err)
	}
	return nil
}

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

func upsertActiveDevice(tx *gorm.DB, fingerprint string, out *Device) error {
	now := time.Now().UTC()
	err := tx.Where("cert_fingerprint = ?", fingerprint).First(out).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		*out = Device{
			CertFingerprint: fingerprint,
			Status:          DeviceStatusActive,
			LastSeenAt:      now,
		}
		if err := tx.Create(out).Error; err != nil {
			return fmt.Errorf("create device: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("load device: %w", err)
	}

	if out.Status == DeviceStatusRevoked {
		return ErrDeviceRevoked
	}

	if err := tx.Model(out).Update("last_seen_at", now).Error; err != nil {
		return fmt.Errorf("update device last seen: %w", err)
	}
	out.LastSeenAt = now
	return nil
}

func registerDomainForDevice(tx *gorm.DB, deviceID uuid.UUID, fqdn string) (Domain, error) {
	var domain Domain
	err := tx.Where("fqdn = ?", fqdn).First(&domain).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		domain = Domain{
			FQDN:     fqdn,
			DeviceID: deviceID,
			Status:   DomainStatusRegistered,
		}
		if err := tx.SavePoint("before_domain_create").Error; err != nil {
			return Domain{}, fmt.Errorf("create domain savepoint: %w", err)
		}
		if err := tx.Create(&domain).Error; err != nil {
			if isActiveDomainUniqueViolation(err) {
				if rollbackErr := tx.RollbackTo("before_domain_create").Error; rollbackErr != nil {
					return Domain{}, fmt.Errorf("rollback domain create conflict: %w", rollbackErr)
				}
				var existing Domain
				if loadErr := tx.Where("fqdn = ?", fqdn).First(&existing).Error; loadErr != nil {
					return Domain{}, fmt.Errorf("load domain after unique conflict: %w", loadErr)
				}
				if existing.DeviceID == deviceID {
					return existing, nil
				}
				return Domain{}, ErrDomainAlreadyUsed
			}
			return Domain{}, fmt.Errorf("create domain: %w", err)
		}
		return domain, nil
	}
	if err != nil {
		return Domain{}, fmt.Errorf("load domain: %w", err)
	}
	if domain.DeviceID != deviceID {
		return Domain{}, ErrDomainAlreadyUsed
	}
	if domain.Status == DomainStatusDisabled {
		if err := tx.Model(&domain).Update("status", DomainStatusRegistered).Error; err != nil {
			return Domain{}, fmt.Errorf("enable domain: %w", err)
		}
		domain.Status = DomainStatusRegistered
	}
	return domain, nil
}

func isActiveDomainUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505" && pgErr.ConstraintName == "domains_fqdn_active_unique"
}
