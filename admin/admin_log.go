package admin

import "relay/auditlog"

func InitLogger() error {
	return auditlog.Init()
}
