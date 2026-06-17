package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (r *Repository) ListDevices(ctx context.Context) ([]DeviceSummary, error) {
	var devices []Device
	if err := r.db.WithContext(ctx).
		Order("last_seen_at DESC, created_at DESC").
		Find(&devices).Error; err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}

	summaries, err := r.deviceSummaries(ctx, devices)
	if err != nil {
		return nil, err
	}
	return summaries, nil
}

func (r *Repository) ListDevicesFiltered(ctx context.Context, options DeviceListOptions) (*DeviceListPage, error) {
	page, perPage := normalizePagination(options.Page, options.PerPage, maxDeviceListPageSize)

	query := r.db.WithContext(ctx).Model(&Device{})
	if options.Status != nil {
		query = query.Where("status = ?", *options.Status)
	}
	if options.LastSeenFrom != nil {
		query = query.Where("last_seen_at >= ?", options.LastSeenFrom.UTC())
	}
	if options.LastSeenTo != nil {
		query = query.Where("last_seen_at < ?", options.LastSeenTo.UTC())
	}
	if options.Connected != nil {
		fingerprints := normalizedFingerprintSet(options.ConnectedFingerprints)
		if *options.Connected {
			if len(fingerprints) == 0 {
				return &DeviceListPage{Devices: nil, Total: 0, Page: page, PerPage: perPage}, nil
			}
			query = query.Where("cert_fingerprint IN ?", fingerprints)
		} else if len(fingerprints) > 0 {
			query = query.Where("cert_fingerprint NOT IN ?", fingerprints)
		}
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("count filtered devices: %w", err)
	}

	var devices []Device
	if err := query.
		Order("last_seen_at DESC, created_at DESC").
		Limit(perPage).
		Offset((page - 1) * perPage).
		Find(&devices).Error; err != nil {
		return nil, fmt.Errorf("list filtered devices: %w", err)
	}

	summaries, err := r.deviceSummaries(ctx, devices)
	if err != nil {
		return nil, err
	}
	return &DeviceListPage{Devices: summaries, Total: total, Page: page, PerPage: perPage}, nil
}

func (r *Repository) deviceSummaries(ctx context.Context, devices []Device) ([]DeviceSummary, error) {
	summaries := make([]DeviceSummary, 0, len(devices))
	for _, current := range devices {
		var domainCount int64
		if err := r.db.WithContext(ctx).
			Model(&Domain{}).
			Where("device_id = ?", current.ID).
			Count(&domainCount).Error; err != nil {
			return nil, fmt.Errorf("count device domains: %w", err)
		}

		var activeSessionCount int64
		if err := r.db.WithContext(ctx).
			Model(&DeviceSession{}).
			Where("device_id = ? AND closed_at IS NULL", current.ID).
			Count(&activeSessionCount).Error; err != nil {
			return nil, fmt.Errorf("count active device sessions: %w", err)
		}

		summaries = append(summaries, DeviceSummary{
			Device:             current,
			DomainCount:        domainCount,
			ActiveSessionCount: activeSessionCount,
		})
	}
	return summaries, nil
}

func (r *Repository) ListOpenDeviceSessions(ctx context.Context) ([]DeviceSession, error) {
	var sessions []DeviceSession
	if err := r.db.WithContext(ctx).
		Preload("Device").
		Where("closed_at IS NULL").
		Order("opened_at DESC").
		Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("list open device sessions: %w", err)
	}
	return sessions, nil
}

func (r *Repository) ListDeviceSessionsForFingerprint(ctx context.Context, fingerprint string) ([]DeviceSession, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	var sessions []DeviceSession
	if err := r.db.WithContext(ctx).
		Joins("JOIN devices ON devices.id = device_sessions.device_id").
		Preload("Device").
		Where("devices.cert_fingerprint = ?", fingerprint).
		Order("device_sessions.opened_at DESC").
		Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("list device sessions: %w", err)
	}
	return sessions, nil
}

func (r *Repository) RevokeDevice(ctx context.Context, fingerprint string) (*Device, error) {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	var device Device
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("cert_fingerprint = ?", fingerprint).
			First(&device).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrDeviceNotFound
			}
			return fmt.Errorf("load device for revoke: %w", err)
		}

		if device.Status != DeviceStatusRevoked {
			if err := tx.Model(&device).Update("status", DeviceStatusRevoked).Error; err != nil {
				return fmt.Errorf("revoke device: %w", err)
			}
			device.Status = DeviceStatusRevoked
		}

		now := time.Now().UTC()
		if err := tx.Model(&DeviceSession{}).
			Where("device_id = ? AND closed_at IS NULL", device.ID).
			Update("closed_at", now).Error; err != nil {
			return fmt.Errorf("close revoked device sessions: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &device, nil
}

func normalizedFingerprintSet(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizeFingerprintForQuery(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

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

func (r *Repository) VerifyDeviceFingerprint(ctx context.Context, fingerprint string) error {
	fingerprint, err := normalizeFingerprint(fingerprint)
	if err != nil {
		return err
	}

	var device Device
	err = r.db.WithContext(ctx).
		Select("id", "status").
		Where("cert_fingerprint = ?", fingerprint).
		First(&device).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrDeviceNotFound
	}
	if err != nil {
		return fmt.Errorf("verify device fingerprint: %w", err)
	}
	if device.Status == DeviceStatusRevoked {
		return ErrDeviceRevoked
	}
	return nil
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
