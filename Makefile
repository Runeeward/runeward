CARGO ?= cargo
PYTHON ?= python3
NPM ?= npm

.PHONY: build ci docker-test fleet-driver-test fmt fmt-check helm kind-e2e lint profiles sdk-test security test vet

build:
	$(CARGO) build --workspace --locked

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all --check

lint:
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

# Kept as an alias of lint for muscle memory.
vet: lint

test:
	$(CARGO) test --workspace --locked

# Opt-in tests against a real Docker engine (they remove only what they create).
docker-test:
	RUNEWARD_TEST_DOCKER=1 $(CARGO) test --locked -p runeward-backend --test docker_integration -- --test-threads=1
	RUNEWARD_TEST_DOCKER=1 $(CARGO) test --locked -p runeward-controlplane --test docker_workspaces --test docker_governance -- --test-threads=1

fleet-driver-test:
	./scripts/test-fleet-drivers.sh

kind-e2e:
	./scripts/e2e-kind.sh

profiles:
	$(CARGO) run --locked -q -p runeward-cli --bin runeward -- --config-dir examples/safe validate --strict

sdk-test:
	PYTHONPATH=adapters/python $(PYTHON) -m unittest discover -s adapters/python/tests
	cd adapters/typescript && $(NPM) ci --ignore-scripts && $(NPM) test

helm:
	helm lint deploy/helm/runeward
	helm template runeward deploy/helm/runeward --set server.enabled=true >/dev/null

# Needs cargo-deny and cargo-audit (`cargo install --locked cargo-deny cargo-audit`).
# RUSTSEC-2023-0071 only reaches a dev-dependency; see deny.toml.
security:
	$(CARGO) deny --locked check
	$(CARGO) audit --ignore RUSTSEC-2023-0071

# Mirrors the source, SDK, Charter, Helm, and dependency checks required
# before merge. Container scans, Docker integration and runtime E2E tests
# remain CI gates.
ci: fmt-check lint test build profiles fleet-driver-test sdk-test helm security
