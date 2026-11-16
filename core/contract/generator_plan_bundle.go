package contract

// GeneratorPlanBundle is the fixed immutable carrier for the request, graph
// rows and use plan. Its digest is storage support, not an effect permission.
type GeneratorPlanBundle struct {
	Request         GeneratorRequestCore
	Header          GeneratorGraphHeader
	ValueEntryPlans []GeneratorValueEntryPlan
	Lineages        []GeneratorLineageTemplate
	Edges           []GeneratorEdge
	ResultUses      []GeneratorResultUse
	SourceUses      []GeneratorSourceUse
	UsePlan         GeneratorUsePlanCore
}

func GeneratorPlanBundleLength(v GeneratorPlanBundle) (int, error) {
	if err := ValidateGeneratorGraphRequest(v.Request, v.Header); err != nil {
		return 0, err
	}
	graph, err := GeneratorGraphID(v.Header, v.ValueEntryPlans, v.Lineages, v.Edges)
	if err != nil {
		return 0, err
	}
	if err := ValidateGeneratorResultUses(v.Header, v.Lineages, v.ResultUses); err != nil {
		return 0, err
	}
	uses, err := GeneratorResultUsesDescriptor(v.ResultUses)
	if err != nil {
		return 0, err
	}
	sources, err := GeneratorSourceUsesDescriptor(v.SourceUses)
	if err != nil {
		return 0, err
	}
	if generatorUsePlanError(v.UsePlan) != nil || v.UsePlan.PlanGraphID != graph || v.UsePlan.DomainID != v.Header.DomainID ||
		v.UsePlan.OperationID != v.Header.OperationID || v.UsePlan.ValueDerivationID != generatorGraphValueDerivationID(v.Header.Schema) || v.UsePlan.MaterialID != v.Header.MaterialID || v.UsePlan.ResultUses != uses || v.UsePlan.SourceUses != sources {
		return 0, ErrRecord
	}
	length := 2 + 3*4 + generatorRequestCoreLength(v.Request) + GeneratorGraphHeaderLength + GeneratorUsePlanCoreLength + 5*4
	for _, row := range v.ValueEntryPlans {
		length += 4 + generatorValueEntryPlanEncodedLength(row)
	}
	for _, row := range v.Lineages {
		length += 4 + generatorLineageTemplateEncodedLength(row)
	}
	length += len(v.Edges)*(4+GeneratorEdgeLength) + len(v.ResultUses)*(4+GeneratorResultUseLength) + len(v.SourceUses)*(4+GeneratorSourceUseLength)
	if length+8 > GeneratorGraphMaxLength {
		return 0, ErrRecordCapacity
	}
	return length, nil
}

func writeGeneratorPlanBundle(w *cryptoWriter, v GeneratorPlanBundle) {
	w.u16(v.Header.Schema)
	w.u32(uint32(generatorRequestCoreLength(v.Request)))
	writeGeneratorRequestCore(w, v.Request)
	w.u32(GeneratorGraphHeaderLength)
	writeGeneratorGraphHeader(w, v.Header)
	w.u32(uint32(len(v.ValueEntryPlans)))
	for _, row := range v.ValueEntryPlans {
		w.u32(uint32(generatorValueEntryPlanEncodedLength(row)))
		writeGeneratorValueEntryPlan(w, row)
	}
	w.u32(uint32(len(v.Lineages)))
	for _, row := range v.Lineages {
		w.u32(uint32(generatorLineageTemplateEncodedLength(row)))
		writeGeneratorLineageTemplate(w, row)
	}
	w.u32(uint32(len(v.Edges)))
	for _, row := range v.Edges {
		w.u32(GeneratorEdgeLength)
		writeGeneratorEdge(w, row)
	}
	w.u32(uint32(len(v.ResultUses)))
	for _, row := range v.ResultUses {
		w.u32(GeneratorResultUseLength)
		writeGeneratorResultUse(w, row)
	}
	w.u32(uint32(len(v.SourceUses)))
	for _, row := range v.SourceUses {
		w.u32(GeneratorSourceUseLength)
		writeGeneratorSourceUse(w, row)
	}
	w.u32(GeneratorUsePlanCoreLength)
	writeGeneratorUsePlanCore(w, v.UsePlan)
}

func EncodeGeneratorPlanBundle(v GeneratorPlanBundle) ([]byte, error) {
	n, err := GeneratorPlanBundleLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratorPlanBundle(&w, v)
	return w.b, nil
}

func readGeneratorBundleRows[T any](r *cryptoReader, maxCount, minRow, maxRow int, read func([]byte) (T, error)) []T {
	n := uint64(r.u32())
	if r.err != nil {
		return nil
	}
	if n > uint64(maxCount) {
		r.err = ErrRecordCapacity
		return nil
	}
	if n*uint64(4+minRow) > uint64(len(r.b)-r.i) {
		r.err = ErrRecord
		return nil
	}
	rows := make([]T, int(n))
	for i := range rows {
		body := r.blob(maxRow)
		if r.err != nil {
			return nil
		}
		rows[i], r.err = read(body)
		if r.err != nil {
			return nil
		}
	}
	return rows
}

func DecodeGeneratorPlanBundle(b []byte) (GeneratorPlanBundle, error) {
	if len(b)+8 > GeneratorGraphMaxLength {
		return GeneratorPlanBundle{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	schema := r.u16()
	if schema != GeneratorPlanBundleSchema {
		return GeneratorPlanBundle{}, ErrRecord
	}
	var v GeneratorPlanBundle
	body := r.blob(GeneratorApplyRequestCoreLength)
	if r.err != nil {
		return v, r.failure()
	}
	v.Request, r.err = InspectGeneratorRequestCore(body)
	if r.err != nil {
		return GeneratorPlanBundle{}, r.failure()
	}
	body = r.blob(GeneratorGraphHeaderLength)
	if r.err != nil {
		return GeneratorPlanBundle{}, r.failure()
	}
	v.Header, r.err = InspectGeneratorGraphHeader(body)
	if r.err == nil && v.Header.Schema != schema {
		r.err = ErrRecord
	}
	if r.err != nil {
		return GeneratorPlanBundle{}, r.failure()
	}
	entryMinimum, lineageMinimum := 238, 208+4+GeneratorAttemptTemplateLength
	v.ValueEntryPlans = readGeneratorBundleRows(&r, CryptoMaxValueEntries, entryMinimum, GeneratorValueEntryPlanMaxLength, func(b []byte) (GeneratorValueEntryPlan, error) {
		view, err := InspectGeneratorValueEntryPlan(b)
		if err != nil {
			return GeneratorValueEntryPlan{}, err
		}
		return view.Own()
	})
	v.Lineages = readGeneratorBundleRows(&r, GeneratorMaxLineageTemplates, lineageMinimum, GeneratorLineageTemplateMaxLength, func(b []byte) (GeneratorLineageTemplate, error) {
		view, err := InspectGeneratorLineageTemplate(b)
		if err != nil {
			return GeneratorLineageTemplate{}, err
		}
		return view.Own()
	})
	v.Edges = readGeneratorBundleRows(&r, GeneratorMaxTemplates*4, GeneratorEdgeLength, GeneratorEdgeLength, InspectGeneratorEdge)
	v.ResultUses = readGeneratorBundleRows(&r, GeneratorMaxTemplates, GeneratorResultUseLength, GeneratorResultUseLength, InspectGeneratorResultUse)
	v.SourceUses = readGeneratorBundleRows(&r, CryptoMaxValueEntries, GeneratorSourceUseLength, GeneratorSourceUseLength, InspectGeneratorSourceUse)
	body = r.blob(GeneratorUsePlanCoreLength)
	if r.err != nil {
		return GeneratorPlanBundle{}, r.failure()
	}
	v.UsePlan, r.err = InspectGeneratorUsePlanCore(body)
	if err := r.end(); err != nil {
		return GeneratorPlanBundle{}, err
	}
	if _, err := GeneratorPlanBundleLength(v); err != nil {
		return GeneratorPlanBundle{}, err
	}
	return v, nil
}

func GeneratorPlanBundleDescriptor(v GeneratorPlanBundle) (GeneratorDescriptor, error) {
	n, err := GeneratorPlanBundleLength(v)
	if err != nil {
		return GeneratorDescriptor{}, err
	}
	w := generatorVectorHashWriter("graph-bundle", n+8, 1)
	w.u32(uint32(n))
	writeGeneratorPlanBundle(&w, v)
	return generatorVectorResult(&w, n+8, 1), nil
}

// GeneratorResultInputEncoding resolves the input class from the owning create
// plan. DELETE has no returned value and always uses the raw class.
func GeneratorResultInputEncoding(v GeneratorPlanBundle, t GeneratorAttemptTemplate) (uint8, error) {
	if t.Action == GeneratorActionDelete {
		return InputEncodingRaw, nil
	}
	if t.Action != GeneratorActionCreate || t.PlannedValueSlotID.IsZero() || t.LineageID.IsZero() {
		return 0, ErrRecord
	}
	var owningSlot ID
	for _, lineage := range v.Lineages {
		if lineage.LineageID != t.LineageID {
			continue
		}
		if !owningSlot.IsZero() || lineage.Purpose != GeneratorLineageCreate || lineage.TemplateCount == 0 || int(lineage.TemplateCount) > len(lineage.Templates) {
			return 0, ErrRecord
		}
		matched := false
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			matched = matched || template == t
		}
		if !matched {
			return 0, ErrRecord
		}
		owningSlot = lineage.Templates[0].PlannedValueSlotID
	}
	if owningSlot.IsZero() {
		return 0, ErrRecord
	}
	var encoding uint8
	for _, p := range v.ValueEntryPlans {
		if p.LineageID != t.LineageID {
			continue
		}
		if encoding != 0 || p.ValueSource != Generated || p.PlannedValueSlotID != owningSlot || p.InputEncoding != InputEncodingRaw && p.InputEncoding != InputEncodingBase64 {
			return 0, ErrRecord
		}
		encoding = p.InputEncoding
	}
	if encoding == 0 {
		return 0, ErrRecord
	}
	return encoding, nil
}
