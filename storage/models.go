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

type CertificateOrderStatus string

const (
	CertificateOrderStatusPendingCSR CertificateOrderStatus = "pending_csr"
	CertificateOrderStatusPendingDNS CertificateOrderStatus = "pending_dns"
	CertificateOrderStatusValidating CertificateOrderStatus = "validating"
	CertificateOrderStatusIssued     CertificateOrderStatus = "issued"
	CertificateOrderStatusFailed     CertificateOrderStatus = "failed"
	CertificateOrderStatusExpired    CertificateOrderStatus = "expired"
)

var allCertificateOrderStatuses = []CertificateOrderStatus{
	CertificateOrderStatusPendingCSR,
	CertificateOrderStatusPendingDNS,
	CertificateOrderStatusValidating,
	CertificateOrderStatusIssued,
	CertificateOrderStatusFailed,
	CertificateOrderStatusExpired,
}

type Device struct {
	ID              uuid.UUID    `gorm:"type:uuid;primaryKey"`
	CertFingerprint string       `gorm:"size:64;not null;uniqueIndex"`
	Status          DeviceStatus `gorm:"type:text;not null;default:'device_status_active'"`
	LastSeenAt      time.Time    `gorm:"not null"`
	CreatedAt       time.Time
	UpdatedAt       time.Time

	Domains           []Domain
	Sessions          []DeviceSession
	CertificateOrders []CertificateOrder
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

	CertificateOrders []CertificateOrder
}

func (d *Domain) BeforeCreate(*gorm.DB) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
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

type CertificateOrder struct {
	ID        uuid.UUID              `gorm:"type:uuid;primaryKey"`
	DomainID  uuid.UUID              `gorm:"type:uuid;not null;index"`
	Domain    Domain                 `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	DeviceID  uuid.UUID              `gorm:"type:uuid;not null;index"`
	Device    Device                 `gorm:"constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
	Status    CertificateOrderStatus `gorm:"type:text;not null;default:'pending_csr'"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (o *CertificateOrder) BeforeCreate(*gorm.DB) error {
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
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
