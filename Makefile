.PHONY: integration-test

# Run all integration test scripts in tests/[0-9]*.sh.
# Each script runs as a separate bash process inside its own network namespace.
# Requires: bash, ip (iproute2), unshare (util-linux).
# Optional: dnsmasq (for DHCP tests).
integration-test:
	cargo build
	@if [ -n "$(SPEC)" ]; then \
		scripts=$$(ls tests/$(SPEC)-*.sh 2>/dev/null); \
	else \
		scripts=$$(ls tests/[0-9]*.sh 2>/dev/null); \
	fi; \
	if [ -z "$$scripts" ]; then \
		echo "No integration test scripts found in tests/[0-9]*.sh"; \
		exit 0; \
	fi; \
	failed=0; \
	for script in $$scripts; do \
		echo "Running $$script ..."; \
		if bash "$$script"; then \
			echo "PASS: $$script"; \
		else \
			echo "FAIL: $$script"; \
			failed=1; \
		fi; \
	done; \
	if [ "$$failed" -eq 1 ]; then \
		echo "One or more integration tests failed."; \
		exit 1; \
	else \
		echo "All integration tests passed."; \
	fi
