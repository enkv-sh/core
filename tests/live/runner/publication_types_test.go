package core

import (
	"context"
	"time"

	"enkv.sh/core/contract"
	protocol "enkv.sh/sdk/protocols/output"
)

type liveOutputActor struct {
	CredentialsFile string `json:"credentials_file"`
	Profile         string `json:"profile,omitempty"`
	ServiceAccount  string `json:"service_account,omitempty"`
	Principal       string `json:"principal,omitempty"`
}

type liveOutputLocation struct {
	Provider         string `json:"provider"`
	Region           string `json:"region,omitempty"`
	Account          string `json:"account,omitempty"`
	ProjectNumber    string `json:"project_number,omitempty"`
	SecretNamePrefix string `json:"secret_name_prefix"`
}

type liveCloudOutputSpec struct {
	Location             liveOutputLocation
	Writer, Cleaner      *liveOutputActor
	ConsumerA, ConsumerB *liveOutputActor
	OtherActorPrincipals []string
	Budget               *runBudget
}

type liveOutputConsumer uint8

const (
	liveOutputConsumerA liveOutputConsumer = iota + 1
	liveOutputConsumerB
)

type liveOutputCredentialFacts struct {
	Principal string
	Expires   time.Time
}

type liveOutputRead struct {
	HTTPStatus    int
	AccessRefused bool
	Bytes         []byte
}

type liveOutputCleanupTarget struct {
	Index         uint32
	PlannedSlot   string
	OwnedInstance string
	CreateAttempt contract.ID
}

type liveOutputCleanupDisposition uint8

const (
	liveOutputAbsent liveOutputCleanupDisposition = iota + 1
	liveOutputDeleteAcknowledged
	liveOutputDeletionScheduled
)

type liveOutputCleanupResult struct {
	Disposition      liveOutputCleanupDisposition
	ResolvedInstance string
}

type liveCloudOutput interface {
	PrepareWriter(context.Context, liveOutputCredentialRoute, time.Time) (liveOutputCredentialFacts, error)
	BindWriterEnvironment(func(string, string)) error
	ReadConsumer(context.Context, liveOutputConsumer, string, uint32) (liveOutputRead, error)
	DeleteFixture(context.Context, liveOutputCleanupTarget) (liveOutputCleanupResult, error)
}

// liveOutputCredentialRoute identifies one owned fixture credential snapshot.
type liveOutputCredentialRoute struct {
	Path string
	ID   protocol.ID
}
