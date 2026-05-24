package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func OpenPostgres(dsn string) (*gorm.DB, error) {
	if dsn == "" {
		return nil, errors.New("empty PostgreSQL DSN")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("unwrap PostgreSQL handle: %w", err)
	}
	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	return db, nil
}

func AutoMigrate(ctx context.Context, db *gorm.DB) error {
	if err := db.WithContext(ctx).AutoMigrate(
		&Device{},
		&Domain{},
		&DeviceSession{},
		&CertificateOrder{},
		&DomainHistory{},
	); err != nil {
		return fmt.Errorf("auto migrate relay schema: %w", err)
	}

	if err := ensureCheckConstraints(ctx, db); err != nil {
		return err
	}

	return nil
}

type checkConstraint struct {
	table      string
	name       string
	expression string
}

func ensureCheckConstraints(ctx context.Context, db *gorm.DB) error {
	checks := []checkConstraint{
		{
			table:      "devices",
			name:       "device_status_check",
			expression: "status IN ('device_status_active','device_status_revoked')",
		},
		{
			table:      "devices",
			name:       "device_cert_fingerprint_format",
			expression: "cert_fingerprint ~ '^[a-f0-9]{64}$'",
		},
		{
			table: "domains",
			name:  "domain_fqdn_format",
			expression: "length(fqdn) BETWEEN 3 AND 253 " +
				"AND fqdn = lower(fqdn) " +
				"AND fqdn ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9](\\.[a-z0-9][a-z0-9-]{1,61}[a-z0-9])*$'",
		},
		{
			table:      "domains",
			name:       "domain_status_check",
			expression: "status IN ('domain_status_registered','domain_status_bound','domain_status_disabled')",
		},
		{
			table:      "certificate_orders",
			name:       "certificate_order_status_check",
			expression: "status IN ('pending_csr','pending_dns','validating','issued','failed','expired')",
		},
	}

	for _, check := range checks {
		if err := addCheckConstraint(ctx, db, check); err != nil {
			return err
		}
	}
	return nil
}

func addCheckConstraint(ctx context.Context, db *gorm.DB, check checkConstraint) error {
	sql := fmt.Sprintf(`
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1
		FROM pg_constraint
		WHERE conname = '%s'
	) THEN
		ALTER TABLE %s ADD CONSTRAINT %s CHECK (%s);
	END IF;
END $$;`,
		check.name,
		check.table,
		check.name,
		check.expression,
	)

	if err := db.WithContext(ctx).Exec(sql).Error; err != nil {
		return fmt.Errorf("ensure check constraint %s: %w", check.name, err)
	}
	return nil
}
