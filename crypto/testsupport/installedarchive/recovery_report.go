package installedarchive

type RecoveryCounts struct {
	Reads, PublicLookups, AuthorityDecrypts, NormalLookups, RecoveryLookups, RecoveryMetadata uint64
	Authentication, OtherDecrypts                                                             uint64
	StoreWrites, CAS, Delete, Discovery, Sign, KeyChanges, GrantChanges, IAMChanges           uint64
	Generator, Publisher, Succession, Resume, GC, Cleanup, Unknown                            uint64
}

// RecoveryReport contains bounded parent assertions after child exit. Raw child
// terminals remain separate private execution evidence.
type RecoveryResult struct{ Outcome, Reason, Evidence uint8 }

type RecoveryReport struct {
	ProviderDenial                          bool
	ChildStarted, ChildJoined               bool
	ChildTerminalsSHA256                    string
	Result                                  RecoveryResult
	Refused                                 bool
	Counts                                  RecoveryCounts
	OracleCounts                            RecoveryCounts
	Attempted, RefusedRequests, Injected    RecoveryCounts
	ReservedRequests, ReservedBytes         uint64
	SnapshotReadsBefore, SnapshotReadsAfter uint64
	Opened                                  int
	RemoteEffectsZero                       bool
	OracleEpochSeparate                     bool
	ExternalMutations                       uint8
	MutationJoined                          bool
	MutationCounts                          RecoveryCounts
}
