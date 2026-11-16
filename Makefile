.PHONY: fmt fmt-check lint

fmt:
	@tests/scripts/test fmt

fmt-check:
	@tests/scripts/test fmt-check

lint:
	@tests/scripts/test lint
