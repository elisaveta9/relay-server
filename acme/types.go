package acme

import "time"

type Directory struct {
	NewNonce   string        `json:"newNonce"`
	NewAccount string        `json:"newAccount"`
	NewOrder   string        `json:"newOrder"`
	RevokeCert string        `json:"revokeCert,omitempty"`
	KeyChange  string        `json:"keyChange,omitempty"`
	Meta       DirectoryMeta `json:"meta,omitempty"`
}

type DirectoryMeta struct {
	TermsOfService          string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CAAIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

type Account struct {
	Status                 string   `json:"status,omitempty"`
	Contact                []string `json:"contact,omitempty"`
	TermsOfServiceAgreed   bool     `json:"termsOfServiceAgreed,omitempty"`
	Orders                 string   `json:"orders,omitempty"`
	ExternalAccountBinding any      `json:"externalAccountBinding,omitempty"`
}

type AccountRequest struct {
	Contact              []string `json:"contact,omitempty"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed,omitempty"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting,omitempty"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type OrderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   time.Time    `json:"notBefore,omitempty"`
	NotAfter    time.Time    `json:"notAfter,omitempty"`
}

type Order struct {
	Status         string       `json:"status,omitempty"`
	Expires        time.Time    `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers,omitempty"`
	NotBefore      time.Time    `json:"notBefore,omitempty"`
	NotAfter       time.Time    `json:"notAfter,omitempty"`
	Error          *Problem     `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations,omitempty"`
	Finalize       string       `json:"finalize,omitempty"`
	Certificate    string       `json:"certificate,omitempty"`
	Location       string       `json:"-"`
}

type Authorization struct {
	Status     string      `json:"status,omitempty"`
	Expires    time.Time   `json:"expires,omitempty"`
	Identifier Identifier  `json:"identifier,omitempty"`
	Challenges []Challenge `json:"challenges,omitempty"`
	Wildcard   bool        `json:"wildcard,omitempty"`
	Location   string      `json:"-"`
}

type Challenge struct {
	Type      string   `json:"type,omitempty"`
	URL       string   `json:"url,omitempty"`
	Status    string   `json:"status,omitempty"`
	Token     string   `json:"token,omitempty"`
	Validated string   `json:"validated,omitempty"`
	Error     *Problem `json:"error,omitempty"`
}

type FinalizeRequest struct {
	CSR string `json:"csr"`
}

type Problem struct {
	Type        string `json:"type,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Status      int    `json:"status,omitempty"`
	Instance    string `json:"instance,omitempty"`
	Subproblems []any  `json:"subproblems,omitempty"`
}
