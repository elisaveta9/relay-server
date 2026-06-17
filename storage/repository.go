package storage

import (
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrFingerprintInvalid               = errors.New("invalid certificate fingerprint")
	ErrDeviceNotFound                   = errors.New("device not found")
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
	ErrDomainLimitReached               = errors.New("device domain limit reached")

	fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	labelPattern       = `(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])`
	domainPattern      = regexp.MustCompile(`^` + labelPattern + `(\.` + labelPattern + `)*$`)
)

type Repository struct {
	db *gorm.DB
}

const (
	domainOwnershipRecordPrefix = "_relay-challenge."
	defaultMaxDomainsPerDevice  = 32
	maxDomainListPageSize       = 200
	maxDeviceListPageSize       = 200
)

type DomainListOptions struct {
	Status      *DomainStatus
	DeviceID    *uuid.UUID
	Fingerprint string
	Search      string
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	Page        int
	PerPage     int
}

type DomainListPage struct {
	Domains []Domain
	Total   int64
	Page    int
	PerPage int
}

type DeviceSummary struct {
	Device
	DomainCount        int64
	ActiveSessionCount int64
}

type DeviceListOptions struct {
	Status                *DeviceStatus
	Connected             *bool
	ConnectedFingerprints []string
	LastSeenFrom          *time.Time
	LastSeenTo            *time.Time
	Page                  int
	PerPage               int
}

type DeviceListPage struct {
	Devices []DeviceSummary
	Total   int64
	Page    int
	PerPage int
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}
