package core

import (
	"context"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type liveSettings struct {
	SDKMode                            string    `json:"sdk_mode,omitempty"`
	SDKHome                            string    `json:"sdk_home,omitempty"`
	SDKCredentialsFile                 string    `json:"sdk_credentials_file,omitempty"`
	SDKQuotaProject                    string    `json:"sdk_quota_project,omitempty"`
	SDKProfile                         string    `json:"sdk_profile,omitempty"`
	QuotaProject                       string    `json:"quota_project,omitempty"`
	Provider                           string    `json:"provider"`
	Project                            string    `json:"project,omitempty"`
	ProjectNumber                      string    `json:"project_number,omitempty"`
	Account                            string    `json:"account,omitempty"`
	Region                             string    `json:"region"`
	Bucket                             string    `json:"bucket"`
	KeyID                              string    `json:"key_id"`
	PublicKeyPEM                       string    `json:"public_key_pem"`
	RecoveryMode                       string    `json:"recovery_mode"`
	AuthorityKEKID                     string    `json:"authority_kek_id"`
	AuthorityKEKPublicKeyPEM           string    `json:"authority_kek_public_key_pem"`
	ReaderKEKID                        string    `json:"reader_kek_id"`
	ReaderKEKPublicKeyPEM              string    `json:"reader_kek_public_key_pem"`
	RecoveryKeyID                      string    `json:"recovery_key_id,omitempty"`
	RecoveryPublicKeyPEM               string    `json:"recovery_public_key_pem,omitempty"`
	RecoveryKEKID                      string    `json:"recovery_kek_id,omitempty"`
	RecoveryKEKPublicKeyPEM            string    `json:"recovery_kek_public_key_pem,omitempty"`
	NormalSuccessor2KeyID              string    `json:"normal_successor_2_key_id,omitempty"`
	NormalSuccessor2PublicKeyPEM       string    `json:"normal_successor_2_public_key_pem,omitempty"`
	NormalSuccessorKeyID               string    `json:"normal_successor_key_id,omitempty"`
	NormalSuccessorPublicKeyPEM        string    `json:"normal_successor_public_key_pem,omitempty"`
	ReaderSuccessorKEKID               string    `json:"reader_successor_kek_id,omitempty"`
	ReaderSuccessorKEKPublicKeyPEM     string    `json:"reader_successor_kek_public_key_pem,omitempty"`
	AuthoritySuccessor1KEKID           string    `json:"authority_successor_1_kek_id,omitempty"`
	AuthoritySuccessor1KEKPublicKeyPEM string    `json:"authority_successor_1_kek_public_key_pem,omitempty"`
	AuthoritySuccessor2KEKID           string    `json:"authority_successor_2_kek_id,omitempty"`
	AuthoritySuccessor2KEKPublicKeyPEM string    `json:"authority_successor_2_kek_public_key_pem,omitempty"`
	RecoverySuccessorKeyID             string    `json:"recovery_successor_key_id,omitempty"`
	RecoverySuccessorPublicKeyPEM      string    `json:"recovery_successor_public_key_pem,omitempty"`
	RecoverySuccessor1KEKID            string    `json:"recovery_successor_1_kek_id,omitempty"`
	RecoverySuccessor1KEKPublicKeyPEM  string    `json:"recovery_successor_1_kek_public_key_pem,omitempty"`
	RecoverySuccessor2KEKID            string    `json:"recovery_successor_2_kek_id,omitempty"`
	RecoverySuccessor2KEKPublicKeyPEM  string    `json:"recovery_successor_2_kek_public_key_pem,omitempty"`
	CredentialsFile                    string    `json:"credentials_file"`
	Profile                            string    `json:"profile,omitempty"`
	CredentialExpires                  time.Time `json:"credential_expires,omitempty"`
}

type liveBackend struct {
	Store         contract.Store
	Trust         contract.Trust
	PublicKey     []byte
	Put           func(context.Context, string, []byte) contract.WriteResult
	Delete        func(context.Context, string, contract.Token) error
	Check         func(context.Context) error
	AccessRefused func() bool
}

type liveLimits = records.LiveLimits

type liveRunInput struct {
	PublicConfiguration    *publicConfigurationInput             `json:"public_configuration,omitempty"`
	Outputs                *records.OutputFixtureInput           `json:"outputs,omitempty"`
	ConfigurationRecovery  *installedarchive.RecoveryWriterInput `json:"configuration_recovery,omitempty"`
	Settings               liveSettings                          `json:"settings"`
	ObserverSettings       *liveSettings                         `json:"observer_settings,omitempty"`
	DeniedObserverSettings *liveSettings                         `json:"denied_observer_settings,omitempty"`
	ReaderSettings         *liveSettings                         `json:"reader_settings,omitempty"`
	RecoverySettings       *liveSettings                         `json:"recovery_settings,omitempty"`
	DeniedReaderSettings   *liveSettings                         `json:"denied_reader_settings,omitempty"`
	ReplacementSettings    map[string]liveSettings               `json:"replacement_settings,omitempty"`
	Generator              *liveGeneratorSettings                `json:"generator,omitempty"`
	GeneratorCleanupLedger string                                `json:"generator_cleanup_ledger,omitempty"`
	CleanupRetry           *liveCleanupRetry                     `json:"cleanup_retry,omitempty"`
	CleanupGrant           *liveCleanupGrant                     `json:"cleanup_grant,omitempty"`
	StockRecovery          *records.StockPluginRecoveryInput     `json:"stock_recovery,omitempty"`
	OutputRecovery         *records.PublicOutputRecoveryInput    `json:"output_recovery,omitempty"`
	RecoveryMode           string                                `json:"recovery_mode"`

	Participants map[string]string `json:"participants"`
	Limits       liveLimits        `json:"limits"`
	Scenarios    []string          `json:"scenarios"`
	MemberCount  int               `json:"member_count,omitempty"`
	Repetitions  uint64            `json:"repetitions"`
	RunID        string            `json:"run_id"`
	Prefix       string            `json:"prefix"`
}

type liveCleanupRetry struct {
	TargetIndex uint32 `json:"target_index"`
	Ordinal     uint8  `json:"ordinal"`
}

type liveCleanupGrant struct {
	TargetIndex               uint32 `json:"target_index"`
	Ordinal                   uint8  `json:"ordinal"`
	OriginalCaseReceiptSHA256 string `json:"original_case_receipt_sha256"`
	GrantRunID                string `json:"grant_run_id"`
	GrantLimitsSHA256         string `json:"grant_limits_sha256"`
	InventorySHA256           string `json:"inventory_sha256,omitempty"`
}

type liveGeneratorSettings struct {
	Account         string `json:"account"`
	PermissionGroup string `json:"permission_group"`
	CredentialsFile string `json:"credentials_file"`
	Artifact        string `json:"artifact"`
}
