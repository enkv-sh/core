package core

func readerReadOutcome(result Result, accessRefused bool) string {
	switch result.Outcome {
	case ObservedCurrent:
		if result.Evidence == AuthenticatedClosure {
			return "success"
		}
	case EvidenceUnavailable:
		if accessRefused && result.Reason == ReadUnavailable {
			return "access-refused"
		}
		return "unavailable"
	case IntegrityFailure:
		return "integrity-failure"
	case RootLossUnsupported:
		return "unavailable"
	}
	return "failed"
}
