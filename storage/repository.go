package storage

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrFingerprintInvalid = errors.New("invalid certificate fingerprint")
	ErrDeviceRevoked      = errors.New("device is revoked")
	ErrDomainInvalid      = errors.New("invalid domain")
	ErrDomainAlreadyUsed  = errors.New("domain is already registered to another device")
	ErrDomainNotOwned     = errors.New("domain is not registered to this device")
	ErrDomainDisabled     = errors.New("domain is disabled")
	ErrDomainNotFound     = errors.New("domain not found")

	fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	labelPattern       = `[a-z0-9][a-z0-9-]{1,61}[a-z0-9]`
	domainPattern      = regexp.MustCompile(`^` + labelPattern + `(\.` + labelPattern + `)*$`)
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
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
	return r.UpdateDomainStatus(ctx, id, DomainStatusDisabled)
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
		var domain Domain
		if err := tx.
			Joins("JOIN devices ON devices.id = domains.device_id").
			Where("domains.fqdn = ? AND devices.cert_fingerprint = ?", fqdn, fingerprint).
			First(&domain).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return fmt.Errorf("find owned domain before delete: %w", err)
		}

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
	err = r.db.WithContext(ctx).
		Joins("JOIN devices ON devices.id = domains.device_id").
		Where("domains.fqdn = ? AND devices.cert_fingerprint = ?", fqdn, fingerprint).
		First(&domain).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrDomainNotOwned
	}
	if err != nil {
		return nil, fmt.Errorf("authorize bind: %w", err)
	}

	if domain.Status == DomainStatusDisabled {
		return nil, ErrDomainDisabled
	}

	var device Device
	if err := r.db.WithContext(ctx).First(&device, "id = ?", domain.DeviceID).Error; err != nil {
		return nil, fmt.Errorf("load domain owner: %w", err)
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

// AddDomainHistoryForFingerprint writes history using device resolved from fingerprint.
// If device can't be resolved, it falls back to writing history without DeviceID.
func (r *Repository) AddDomainHistoryForFingerprint(
	ctx context.Context,
	fingerprint string,
	domain string,
	action DomainHistoryAction,
) error {
	deviceID, err := r.GetDeviceIDForFingerprint(ctx, fingerprint)
	if err == nil {
		return r.AddDomainHistory(ctx, nil, &deviceID, domain, action)
	}

	// Fallback: only when device can't be resolved.
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.AddDomainHistory(ctx, nil, nil, domain, action)
	}

	return err
}

// GetDeviceIDForFingerprint resolves a device ID from its certificate fingerprint.
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
		if err := tx.Create(&domain).Error; err != nil {
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
