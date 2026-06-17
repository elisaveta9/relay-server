package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

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

			if err := writeDomainHistory(tx, &domain.ID, &device.ID, domain.FQDN, DomainActionRegister); err != nil {
				return err
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

		if err := writeDomainHistory(tx, &domain.ID, &device.ID, domain.FQDN, DomainActionRegister); err != nil {
			return err
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

func (r *Repository) ListDomainsFiltered(ctx context.Context, options DomainListOptions) (*DomainListPage, error) {
	page, perPage := normalizePagination(options.Page, options.PerPage, maxDomainListPageSize)

	query := r.db.WithContext(ctx).Model(&Domain{})
	if options.Status != nil {
		query = query.Where("domains.status = ?", *options.Status)
	}
	if options.DeviceID != nil || options.Fingerprint != "" {
		query = query.Joins("JOIN devices ON devices.id = domains.device_id")
	}
	if options.DeviceID != nil {
		query = query.Where("devices.id = ?", *options.DeviceID)
	}
	if options.Fingerprint != "" {
		fingerprint, err := normalizeFingerprint(options.Fingerprint)
		if err != nil {
			return nil, err
		}
		query = query.Where("devices.cert_fingerprint = ?", fingerprint)
	}
	if search := strings.TrimSpace(strings.ToLower(options.Search)); search != "" {
		search = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(search)
		query = query.Where(`domains.fqdn LIKE ? ESCAPE '\'`, "%"+search+"%")
	}
	if options.CreatedFrom != nil {
		query = query.Where("domains.created_at >= ?", options.CreatedFrom.UTC())
	}
	if options.CreatedTo != nil {
		query = query.Where("domains.created_at < ?", options.CreatedTo.UTC())
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("count filtered domains: %w", err)
	}

	var domains []Domain
	if err := query.
		Preload("Device").
		Order("domains.created_at DESC, domains.fqdn ASC").
		Limit(perPage).
		Offset((page - 1) * perPage).
		Find(&domains).Error; err != nil {
		return nil, fmt.Errorf("list filtered domains: %w", err)
	}

	return &DomainListPage{
		Domains: domains,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}, nil
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

		if err := writeDomainHistory(tx, &domain.ID, &domain.DeviceID, domain.FQDN, action); err != nil {
			return err
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

		if err := writeDomainHistory(tx, &domain.ID, &domain.DeviceID, domain.FQDN, DomainActionDisable); err != nil {
			return err
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

		if err := deleteDomainWithCleanup(tx, &domain); err != nil {
			return err
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

		if err := deleteDomainWithCleanup(tx, &domain); err != nil {
			return err
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

			if err := writeDomainHistory(tx, &domain.ID, &domain.DeviceID, domain.FQDN, DomainActionDelete); err != nil {
				return err
			}
			deleted = true
		}

		rowsAffected, err := deleteDomainOwnershipChallenges(
			tx,
			device.ID,
			fqdn,
			"delete owned domain challenge",
		)
		if err != nil {
			return err
		}
		if rowsAffected > 0 {
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
	return writeDomainHistory(r.db.WithContext(ctx), domainID, deviceID, fqdn, action)
}

func writeDomainHistory(tx *gorm.DB, domainID *uuid.UUID, deviceID *uuid.UUID, fqdn string, action DomainHistoryAction) error {
	hist := DomainHistory{
		DomainID: domainID,
		DeviceID: deviceID,
		FQDN:     fqdn,
		Action:   action,
	}
	if err := tx.Create(&hist).Error; err != nil {
		return fmt.Errorf("write domain history: %w", err)
	}
	return nil
}

// Пишем историю по fingerprint. Если устройство не нашли, оставляем device_id пустым.
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

func registerDomainForDevice(tx *gorm.DB, deviceID uuid.UUID, fqdn string) (Domain, error) {
	var domain Domain
	err := tx.Where("fqdn = ?", fqdn).First(&domain).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		var device Device
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id").
			First(&device, "id = ?", deviceID).Error; err != nil {
			return Domain{}, fmt.Errorf("lock device for domain registration: %w", err)
		}

		var domainCount int64
		if err := tx.Model(&Domain{}).
			Where("device_id = ?", deviceID).
			Count(&domainCount).Error; err != nil {
			return Domain{}, fmt.Errorf("count device domains: %w", err)
		}
		if domainCount >= int64(configuredMaxDomainsPerDevice()) {
			return Domain{}, ErrDomainLimitReached
		}

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

func deleteDomainWithCleanup(tx *gorm.DB, domain *Domain) error {
	if err := tx.Delete(domain).Error; err != nil {
		return fmt.Errorf("delete domain: %w", err)
	}
	if _, err := deleteDomainOwnershipChallenges(
		tx,
		domain.DeviceID,
		domain.FQDN,
		"delete domain ownership challenge",
	); err != nil {
		return err
	}
	return writeDomainHistory(tx, &domain.ID, &domain.DeviceID, domain.FQDN, DomainActionDelete)
}

func deleteDomainOwnershipChallenges(tx *gorm.DB, deviceID uuid.UUID, fqdn string, errorContext string) (int64, error) {
	result := tx.Where(
		"device_id = ? AND fqdn = ?",
		deviceID,
		fqdn,
	).Delete(&DomainOwnershipChallenge{})
	if result.Error != nil {
		return 0, fmt.Errorf("%s: %w", errorContext, result.Error)
	}
	return result.RowsAffected, nil
}

func isActiveDomainUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505" && pgErr.ConstraintName == "domains_fqdn_active_unique"
}
