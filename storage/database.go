package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
		&DomainOwnershipChallenge{},
		&DeviceSession{},
		&DomainHistory{},
	); err != nil {
		return fmt.Errorf("auto migrate relay schema: %w", err)
	}

	if err := dropCertificateOrdersTable(ctx, db); err != nil {
		return err
	}

	if err := ensureCheckConstraints(ctx, db); err != nil {
		return err
	}

	if err := ensureDomainIndexes(ctx, db); err != nil {
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
			table: "devices",
			name:  "device_status_check",
			expression: checkInExpression("status", []string{
				string(DeviceStatusActive),
				string(DeviceStatusRevoked),
			}),
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
				"AND fqdn ~ '^([a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])(\\.([a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9]))*$'",
		},
		{
			table:      "domains",
			name:       "domain_status_check",
			expression: checkInExpression("status", domainStatusValues()),
		},
		{
			table:      "domain_ownership_challenges",
			name:       "domain_ownership_challenge_status_check",
			expression: checkInExpression("status", domainOwnershipChallengeStatusValues()),
		},
	}

	for _, check := range checks {
		if err := addCheckConstraint(ctx, db, check); err != nil {
			return err
		}
	}
	if err := db.WithContext(ctx).Exec(`
UPDATE domain_ownership_challenges
SET next_verification_at = COALESCE(last_verification_at, created_at, NOW())
WHERE status = 'pending' AND next_verification_at IS NULL;`).Error; err != nil {
		return fmt.Errorf("backfill DNS challenge verification schedule: %w", err)
	}
	return nil
}

func dropCertificateOrdersTable(ctx context.Context, db *gorm.DB) error {
	if err := db.WithContext(ctx).Exec(`DROP TABLE IF EXISTS certificate_orders;`).Error; err != nil {
		return fmt.Errorf("drop legacy certificate_orders table: %w", err)
	}
	return nil
}

func addCheckConstraint(ctx context.Context, db *gorm.DB, check checkConstraint) error {
	if check.table == "domains" && check.name == "domain_fqdn_format" {
		if err := db.WithContext(ctx).
			Exec("ALTER TABLE domains DROP CONSTRAINT IF EXISTS domain_fqdn_format;").
			Error; err != nil {
			return fmt.Errorf("drop legacy check constraint %s: %w", check.name, err)
		}
	}

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

func ensureDomainIndexes(ctx context.Context, db *gorm.DB) error {
	var duplicateCount int64

	if err := db.WithContext(ctx).Raw(`
SELECT COUNT(*)
FROM (
	SELECT fqdn
	FROM domains
	WHERE deleted_at IS NULL
	GROUP BY fqdn
	HAVING COUNT(*) > 1
) dup;`).Scan(&duplicateCount).Error; err != nil {
		return fmt.Errorf("check active domain fqdn duplicates: %w", err)
	}
	if duplicateCount > 0 {
		return fmt.Errorf("cannot create active domain fqdn unique index: found %d duplicate active fqdn group(s)", duplicateCount)
	}

	if err := db.WithContext(ctx).Exec(`
CREATE UNIQUE INDEX IF NOT EXISTS domains_fqdn_active_unique
ON domains (fqdn)
WHERE deleted_at IS NULL;`).Error; err != nil {
		return fmt.Errorf("ensure active domain fqdn index: %w", err)
	}

	if err := db.WithContext(ctx).Exec(`DROP INDEX IF EXISTS idx_domains_fqdn;`).Error; err != nil {
		return fmt.Errorf("drop legacy domain fqdn index: %w", err)
	}

	return nil
}

func checkInExpression(column string, values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, "'"+strings.ReplaceAll(value, "'", "''")+"'")
	}
	return fmt.Sprintf("%s IN (%s)", column, strings.Join(quoted, ","))
}

func domainStatusValues() []string {
	values := make([]string, 0, len(allDomainStatuses))
	for _, status := range allDomainStatuses {
		values = append(values, string(status))
	}
	return values
}

func domainOwnershipChallengeStatusValues() []string {
	values := make([]string, 0, len(allDomainOwnershipChallengeStatuses))
	for _, status := range allDomainOwnershipChallengeStatuses {
		values = append(values, string(status))
	}
	return values
}
