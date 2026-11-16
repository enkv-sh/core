package compositionfull

import (
	"encoding/base64"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func inspectionOutput(o *queryObject, v core.InspectionOutput) {
	o.object("configuration_descriptor", func(q *queryObject) {
		p := v.ConfigurationDescriptor
		q.field("schema", p.Schema)
		q.id("configuration_digest", p.ConfigurationDigest)
		q.field("total_length", p.TotalLength)
		q.field("slice_count", p.SliceCount)
		q.field("binding_count", p.BindingCount)
		q.field("routing_length", p.RoutingLength)
	})
	o.object("configuration", func(q *queryObject) { inspectionOutputConfiguration(q, v.Configuration) })
	o.array("current_targets", len(v.CurrentTargets), func(i int) {
		p := v.CurrentTargets[i]
		q := o.begin()
		q.field("binding_index", p.BindingIndex)
		q.field("target_index", p.TargetIndex)
		q.id("coordinate_id", p.CoordinateID)
		q.field("coordinate_index", p.CoordinateIndex)
		q.field("resolved_consumer_locator", p.ResolvedConsumerLocator)
		q.field("locator_basis", p.LocatorBasis)
		q.end()
	})
	o.array("coordinates", len(v.Coordinates), func(i int) { q := o.begin(); inspectionCoordinate(q, v.Coordinates[i]); q.end() })
	o.array("markers", len(v.Markers), func(i int) { q := o.begin(); inspectionMarker(q, v.Markers[i]); q.end() })
	o.array("current_blockers", len(v.CurrentBlockers), func(i int) {
		p := v.CurrentBlockers[i]
		q := o.begin()
		q.field("coordinate_index", p.CoordinateIndex)
		queryIndexes(q, "marker_indexes", p.MarkerIndexes)
		q.end()
	})
	o.object("warnings", func(q *queryObject) { inspectionOutputWarnings(q, v.Warnings) })
}
func inspectionOutputWarnings(q *queryObject, p core.InspectionOutputWarnings) {
	q.field("domain_wide_warning", p.DomainWideWarning)
	q.field("unresolved_publication", p.UnresolvedPublication)
	q.field("late_write_risk", p.LateWriteRisk)
}
func inspectionOutputConfiguration(q *queryObject, v contract.OutputConfiguration) {
	q.field("schema", v.Schema)
	q.id("domain_id", v.DomainID)
	q.array("bindings", len(v.Bindings), func(i int) {
		p := v.Bindings[i]
		o := q.begin()
		o.id("incarnation_id", p.IncarnationID)
		o.field("destination_id", p.DestinationID)
		o.object("destination", func(d *queryObject) { inspectionDestination(d, p.Destination) })

		o.array("targets", len(p.Targets), func(i int) { d := o.begin(); inspectionOutputTarget(d, p.Targets[i]); d.end() })
		o.end()
	})
	q.array("default_destinations", len(v.DefaultDestinations), func(i int) { q.value(v.DefaultDestinations[i]) })
	q.array("routes", len(v.Routes), func(i int) {
		p := v.Routes[i]
		o := q.begin()
		o.id("entry_incarnation_id", p.EntryIncarnationID)
		o.array("destinations", len(p.Destinations), func(i int) { o.value(p.Destinations[i]) })
		o.end()
	})
	q.array("groups", len(v.Groups), func(i int) {
		q.w.text("[")
		for j, id := range v.Groups[i] {
			if j != 0 {
				q.w.text(",")
			}
			q.value(queryHexID(id))
		}
		q.w.text("]")
	})
}
func inspectionDestination(q *queryObject, p contract.OutputDestination) {
	q.field("config_contract_id", p.ConfigContractID)
	q.field("service_contract_id", p.ServiceContractID)
	q.field("canonical_settings_base64", base64.StdEncoding.EncodeToString(p.CanonicalSettings))
	q.field("capabilities", p.Capabilities)
	q.object("policy", func(o *queryObject) { inspectionPolicy(o, p.Policy) })
}
func inspectionOutputTarget(q *queryObject, p contract.OutputTarget) {
	q.id("entry_incarnation_id", p.EntryIncarnationID)
	q.field("service_contract_id", p.ServiceContractID)
	q.field("target_contract_id", p.TargetContractID)
	q.field("canonical_target", p.CanonicalTarget)
	q.field("consumer_locator", p.ConsumerLocator)
	q.field("target_data_base64", base64.StdEncoding.EncodeToString(p.TargetData))
	q.field("payload_encoding", p.PayloadEncoding)
	q.field("locator_requires_creation", p.LocatorRequiresCreation)
	q.field("capabilities", p.Capabilities)
	q.object("create_value_bounds", func(o *queryObject) { inspectionPayloadBounds(o, p.CreateValueBounds) })
	q.object("write_value_bounds", func(o *queryObject) { inspectionPayloadBounds(o, p.WriteValueBounds) })
	q.object("policy", func(o *queryObject) { inspectionPolicy(o, p.Policy) })
}
func inspectionPayloadBounds(q *queryObject, p contract.OutputPayloadBounds) {
	q.field("minimum", p.Minimum)
	q.field("maximum", p.Maximum)
}
func inspectionPolicy(q *queryObject, p contract.OutputPolicy) {
	q.field("contract_id", p.ContractID)
	q.field("data_base64", base64.StdEncoding.EncodeToString(p.Data))
}

func inspectionCoordinate(q *queryObject, p contract.PublicationCoordinate) {
	q.field("schema", p.Schema)
	q.id("domain_id", p.DomainID)
	q.id("coordinate_id", p.CoordinateID)
	q.field("service_contract_id", p.ServiceContractID)
	q.field("canonical_target", p.CanonicalTarget)
	q.field("binding_state", p.BindingState)
	q.field("owner_state", p.OwnerState)
	q.id("active_binding_incarnation_id", p.ActiveBindingIncarnationID)
	q.id("last_binding_incarnation_id", p.LastBindingIncarnationID)
	q.id("last_entry_incarnation_id", p.LastEntryIncarnationID)
	q.id("owned_birth_attempt_id", p.OwnedBirthAttemptID)
	q.id("owned_instance_digest", p.OwnedInstanceDigest)
	q.id("current_publication_incarnation_id", p.CurrentPublicationIncarnationID)
	q.field("last_admission_ordinal", p.LastAdmissionOrdinal)
	q.id("latest_unresolved_attempt_id", p.LatestUnresolvedAttemptID)
	q.id("last_value_ack_attempt_id", p.LastValueAckAttemptID)
	q.id("last_value_digest", p.LastValueDigest)
	q.id("last_policy_ack_attempt_id", p.LastPolicyAckAttemptID)
	q.id("last_policy_digest", p.LastPolicyDigest)
	q.id("last_delete_ack_attempt_id", p.LastDeleteAckAttemptID)
	q.id("last_value_ack_incarnation_id", p.LastValueAckIncarnationID)
	q.id("last_policy_ack_incarnation_id", p.LastPolicyAckIncarnationID)
	q.id("last_delete_ack_incarnation_id", p.LastDeleteAckIncarnationID)
	q.field("last_value_ack_ordinal", p.LastValueAckOrdinal)
	q.field("last_policy_ack_ordinal", p.LastPolicyAckOrdinal)
	q.field("last_delete_ack_ordinal", p.LastDeleteAckOrdinal)
	q.field("possible_remote_object", p.PossibleRemoteObject != 0)
	q.field("late_effect_risk", p.LateEffectRisk != 0)
	q.field("deletion_destination_id", p.DeletionDestinationID)
	q.field("deletion_consumer_locator", p.DeletionConsumerLocator)
	q.field("deletion_target_contract_id", p.DeletionTargetContractID)
	q.field("deletion_config_contract_id", p.DeletionConfigContractID)
	q.field("deletion_credential_route_contract_id", p.DeletionCredentialRouteContractID)
	q.field("deletion_target_data_base64", base64.StdEncoding.EncodeToString(p.DeletionTargetData))
	q.field("deletion_payload_encoding", p.DeletionPayloadEncoding)
	q.field("locator_requires_creation", p.LocatorRequiresCreation)
	q.id("deletion_target_row_digest", p.DeletionTargetRowDigest)
}

func inspectionMarker(q *queryObject, p contract.PublicationMarker) {
	q.field("schema", p.Schema)
	q.id("domain_id", p.DomainID)
	q.id("operation_id", p.OperationID)
	q.id("attempt_id", p.AttemptID)
	q.id("coordinate_id", p.CoordinateID)
	q.id("publication_incarnation_id", p.PublicationIncarnationID)
	q.field("admission_ordinal", p.AdmissionOrdinal)
	q.object("projection", func(o *queryObject) { inspectionPublicationProjection(o, p.Projection) })
	q.id("projection_commitment", p.ProjectionCommitment)
	q.id("authority_subject_digest", p.AuthoritySubjectDigest)
	q.field("executor_id", p.ExecutorID)
	q.field("credential_route_id", p.CredentialRouteID)
	q.field("blocker_count", p.BlockerCount)
	q.id("blocker_digest", p.BlockerDigest)
	q.field("state", p.State)
	q.field("late_effect_risk", p.LateEffectRisk != 0)
	q.object("evidence", func(o *queryObject) { inspectionPublicationEvidence(o, p.Evidence) })
	q.field("birth_service_contract_id", p.BirthServiceContractID)
	q.field("birth_target_contract_id", p.BirthTargetContractID)
}

func inspectionPublicationEvidence(q *queryObject, p contract.PublicationEvidence) {
	q.field("schema", p.Schema)
	q.field("entry", p.Entry)
	q.field("class", p.Class)
	q.id("response_contract_digest", p.ResponseContractDigest)
	q.field("normalized_status", p.NormalizedStatus)
	q.field("safe_request_id", p.SafeRequestID)
	q.field("safe_resource_id", p.SafeResourceID)
	q.field("consumer_locator", p.ConsumerLocator)
}

func inspectionPublicationProjection(q *queryObject, p contract.PublicationProjection) {
	q.field("schema", p.Schema)
	q.id("domain_id", p.DomainID)
	q.id("configuration_digest", p.ConfigurationDigest)
	q.id("coordinate_id", p.CoordinateID)
	q.id("binding_incarnation_id", p.BindingIncarnationID)
	q.id("entry_incarnation_id", p.EntryIncarnationID)
	q.id("target_row_digest", p.TargetRowDigest)
	q.field("action", p.Action)
	q.id("owned_birth_attempt_id", p.OwnedBirthAttemptID)
	q.id("uncertain_create_attempt_id", p.UncertainCreateAttemptID)
	q.id("exclusive_namespace_digest", p.ExclusiveNamespaceDigest)
	q.id("value_basis_digest", p.ValueBasisDigest)
	q.id("policy_digest", p.PolicyDigest)
	q.id("request_contract_digest", p.RequestContractDigest)
	q.id("acting_recipient_id", p.ActingRecipientID)
}
