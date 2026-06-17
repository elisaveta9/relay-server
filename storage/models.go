package storage

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type DeviceStatus string

const (
	DeviceStatusActive  DeviceStatus = "device_status_active"
	DeviceStatusRevoked DeviceStatus = "device_status_revoked"
)

type DomainStatus string

const (
	DomainStatusRegistered DomainStatus = "domain_status_registered"
	DomainStatusBound      DomainStatus = "domain_status_bound"
	DomainStatusDisabled   DomainStatus = "domain_status_disabled"
)

var allDomainStatuses = []DomainStatus{
	DomainStatusRegistered,
	DomainStatusBound,
	DomainStatusDisabled,
}

type DomainOwnershipChallengeStatus string

const (
	DomainOwnershipChallengeStatusPending  DomainOwnershipChallengeStatus = "pending"
	DomainOwnershipChallengeStatusVerified DomainOwnershipChallengeStatus = "verified"
	DomainOwnershipChallengeStatusExpired  DomainOwnershipChallengeStatus = "expired"
)

var allDomainOwnershipChallengeStatuses = []DomainOwnershipChallengeStatus{
	DomainOwnershipChallengeStatusPending,
	DomainOwnershipChallengeStatusVerified,
	DomainOwnershipChallengeStatusExpired,
}

type Device struct {
	ID              uuid.UUID    `gorm:"type:uuid;primaryKey"`
	CertFingerprint string       `gorm:"size:64;not null;uniqueIndex"`
	Status          DeviceStatus `gorm:"type:text;not null;default:'device_status_active'"`
	LastSeenAt      time.Time    `gorm:"not null"`
	CreatedAt       time.Time
	UpdatedAt       time.Time

	Domains  []Domain
	Sessions []DeviceSession
}

func (d *Device) BeforeCreate(*gorm.DB) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	return nil
}

type Domain struct {
	ID        uuid.UUID      `gorm:"type:uuid;primaryKey"`
	FQDN      string         `gorm:"column:fqdn;size:253;not null"`
	DeviceID  uuid.UUID      `gorm:"type:uuid;not null;index"`
	Device    Device         `gorm:"constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	Status    DomainStatus   `gorm:"type:text;not null;default:'domain_status_registered'"`
	DeletedAt gorm.DeletedAt `gorm:"index"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (d *Domain) BeforeCreate(*gorm.DB) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	return nil
}

type DomainOwnershipChallenge struct {
	ID                   uuid.UUID                      `gorm:"type:uuid;primaryKey"`
	DeviceID             uuid.UUID                      `gorm:"type:uuid;not null;index;uniqueIndex:domain_ownership_challenges_device_domain"`
	Device               Device                         `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	FQDN                 string                         `gorm:"column:fqdn;size:253;not null;uniqueIndex:domain_ownership_challenges_device_domain"`
	RecordName           string                         `gorm:"size:253;not null"`
	RecordValue          string                         `gorm:"size:255;not null"`
	Status               DomainOwnershipChallengeStatus `gorm:"type:text;not null;default:'pending';index"`
	ExpiresAt            time.Time                      `gorm:"not null;index"`
	NextVerificationAt   *time.Time                     `gorm:"index"`
	VerificationAttempts uint32
	LastVerificationAt   *time.Time
	LastError            string `gorm:"type:text;not null;default:''"`
	VerifiedAt           *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func (c *DomainOwnershipChallenge) BeforeCreate(*gorm.DB) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	return nil
}

type DeviceSession struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey"`
	DeviceID  uuid.UUID  `gorm:"type:uuid;not null;index"`
	Device    Device     `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	OpenedAt  time.Time  `gorm:"not null;index"`
	ClosedAt  *time.Time `gorm:"index"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (s *DeviceSession) BeforeCreate(*gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

type DomainHistoryAction string

const (
	DomainActionRegister DomainHistoryAction = "REGISTER"
	DomainActionBind     DomainHistoryAction = "BIND"
	DomainActionUnbind   DomainHistoryAction = "UNBIND"
	DomainActionDelete   DomainHistoryAction = "DELETE"
	DomainActionEnable   DomainHistoryAction = "ENABLE"
	DomainActionDisable  DomainHistoryAction = "DISABLE"
)

type DomainHistory struct {
	ID        uuid.UUID           `gorm:"type:uuid;primaryKey"`
	DomainID  *uuid.UUID          `gorm:"type:uuid;index;null"`
	DeviceID  *uuid.UUID          `gorm:"type:uuid;index;null"`
	FQDN      string              `gorm:"size:253;not null;index"`
	Action    DomainHistoryAction `gorm:"size:32;not null;index"`
	CreatedAt time.Time
}

func (h *DomainHistory) BeforeCreate(*gorm.DB) error {
	if h.ID == uuid.Nil {
		h.ID = uuid.New()
	}
	return nil
}
