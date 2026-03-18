# seclusor Makefile
# Git-trackable secrets management library (Rust + Go/TypeScript bindings)
#
# Quick Reference:
#   make help       - Show all available targets
#   make bootstrap  - Install tools (sfetch -> goneat)
#   make check      - Run all quality checks (fmt, lint, test, deny)
#   make fmt        - Format code (cargo fmt + goneat format)
#   make build      - Build all crates

.PHONY: all help bootstrap bootstrap-force tools check check-all test fmt fmt-check lint build build-release clean
.PHONY: ffi-header build-ffi go-bindings-sync go-bindings-ci go-build go-test go-test-committed ts-build ts-test embed-verify
.PHONY: precommit prepush repo-status deny deny-all audit miri msrv
.PHONY: check-windows check-windows-msvc check-windows-gnu
.PHONY: install dogfood-cli
.PHONY: version version-patch version-minor version-major version-set version-sync version-check
.PHONY: ci release-check release-preflight
.PHONY: release-clean release-download release-checksums release-sign release-export-keys
.PHONY: release-verify release-verify-checksums release-verify-signatures release-verify-keys
.PHONY: release-notes release-upload release

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

VERSION := $(shell cargo metadata --format-version 1 --no-deps 2>/dev/null | \
	grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "dev")

BIN_DIR := $(CURDIR)/bin

SFETCH_VERSION ?= v0.4.5
SFETCH_INSTALL_URL ?= https://github.com/3leaps/sfetch/releases/download/$(SFETCH_VERSION)/install-sfetch.sh
GONEAT_VERSION ?= v0.5.1

SFETCH = $(shell [ -x "$(BIN_DIR)/sfetch" ] && echo "$(BIN_DIR)/sfetch" || command -v sfetch 2>/dev/null)
GONEAT = $(shell command -v goneat 2>/dev/null)

CARGO = cargo
GO_BINDINGS_DIR := bindings/go/seclusor
TS_BINDINGS_DIR := bindings/typescript
GO_OS := $(shell go env GOOS 2>/dev/null || echo "unknown")
GO_ARCH := $(shell go env GOARCH 2>/dev/null || echo "unknown")
GO_PLATFORM := $(GO_OS)-$(GO_ARCH)

# -----------------------------------------------------------------------------
# Default and Help
# -----------------------------------------------------------------------------

all: check

help: ## Show available targets
	@echo "seclusor - Git-Trackable Secrets Management"
	@echo "Age-encrypted secrets with library-first design."
	@echo ""
	@echo "Development:"
	@echo "  help            Show this help message"
	@echo "  bootstrap       Install tools (sfetch -> goneat)"
	@echo "  build           Build all crates (debug)"
	@echo "  build-release   Build all crates (release)"
	@echo "  install         Install seclusor binary to ~/.local/bin"
	@echo "  ffi-header      Generate C header for seclusor-ffi"
	@echo "  build-ffi       Build seclusor-ffi static and shared libraries"
	@echo "  go-bindings-sync  Sync generated header + static lib into Go bindings"
	@echo "  go-bindings-ci    Dispatch Go bindings prep workflow for current VERSION"
	@echo "  go-build        Build Go bindings module"
	@echo "  go-test         Run Go bindings tests"
	@echo "  go-test-committed  Run Go bindings tests against committed prebuilt lib"
	@echo "  ts-build        Build TypeScript N-API bindings"
	@echo "  ts-test         Run TypeScript bindings tests"
	@echo "  embed-verify    Verify docs embed manifest/build pipeline"
	@echo "  dogfood-cli     Run end-to-end CLI dogfooding matrix"
	@echo "  clean           Remove build artifacts"
	@echo ""
	@echo "Quality gates:"
	@echo "  check           Run all quality checks (fmt, lint, test, deny)"
	@echo "  ci              Run exactly what CI runs (fmt, clippy, test, deny, version-check)"
	@echo "  test            Run test suite"
	@echo "  fmt             Format code (cargo fmt + goneat format)"
	@echo "  lint            Run linting (cargo clippy + goneat lint)"
	@echo "  precommit       Pre-commit checks (fast: fmt, clippy)"
	@echo "  prepush         Pre-push checks (thorough: fmt, clippy, test, deny, version-check)"
	@echo "  msrv            Verify build+test on MSRV toolchain"
	@echo "  miri            Run Miri UB detection on FFI crate (nightly)"
	@echo "  deny            Run cargo-deny license checks (offline-safe)"
	@echo "  deny-all        Run full cargo-deny checks (includes advisories)"
	@echo "  audit           Run cargo-audit security scan"
	@echo "  check-windows   Run Windows target cargo checks (no link)"
	@echo ""
	@echo "Release:"
	@echo "  release-preflight  Verify all pre-tag requirements (REQUIRED before tagging)"
	@echo "  release-check      Version consistency + package check"
	@echo "  release-clean      Remove dist/release contents"
	@echo "  release-download   Download release assets from GitHub"
	@echo "  release-checksums  Generate SHA256SUMS and SHA512SUMS"
	@echo "  release-sign       Sign checksum manifests (minisign + PGP)"
	@echo "  release-export-keys Export public signing keys"
	@echo "  release-verify     Verify checksums, signatures, and keys"
	@echo "  release-notes      Copy release notes to dist"
	@echo "  release-upload     Upload signed artifacts to GitHub"
	@echo "  release            Full signing workflow (clean -> upload)"
	@echo ""
	@echo "Version management:"
	@echo "  version         Print current version"
	@echo "  version-check   Validate version consistency across files"
	@echo "  version-patch   Bump patch version (0.1.0 -> 0.1.1)"
	@echo "  version-minor   Bump minor version (0.1.0 -> 0.2.0)"
	@echo "  version-major   Bump major version (0.1.0 -> 1.0.0)"
	@echo "  version-set     Set explicit version (V=X.Y.Z)"
	@echo "  version-sync    Sync VERSION to Cargo.toml and package.json"
	@echo ""
	@echo "Current version: $(VERSION)"

# -----------------------------------------------------------------------------
# Bootstrap
# -----------------------------------------------------------------------------

bootstrap: ## Install required tools (sfetch -> goneat)
	@echo "Bootstrapping seclusor development environment..."
	@echo ""
	@if ! command -v curl >/dev/null 2>&1; then \
		echo "[!!] curl not found (required for bootstrap)"; \
		exit 1; \
	fi
	@echo "[ok] curl found"
	@if ! command -v cargo >/dev/null 2>&1; then \
		echo "[!!] cargo not found (required)"; \
		echo ""; \
		echo "Install Rust toolchain:"; \
		echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
		exit 1; \
	fi
	@echo "[ok] cargo: $$(cargo --version)"
	@echo ""
	@mkdir -p "$(BIN_DIR)"
	@if [ ! -x "$(BIN_DIR)/sfetch" ] && ! command -v sfetch >/dev/null 2>&1; then \
		echo "[..] Installing sfetch (trust anchor)..."; \
		curl -fsSL "$(SFETCH_INSTALL_URL)" | bash -s -- --dir "$(BIN_DIR)" --yes; \
	else \
		echo "[ok] sfetch already installed"; \
	fi
	@SFETCH_BIN=""; \
	if [ -x "$(BIN_DIR)/sfetch" ]; then SFETCH_BIN="$(BIN_DIR)/sfetch"; \
	elif command -v sfetch >/dev/null 2>&1; then SFETCH_BIN="$$(command -v sfetch)"; fi; \
	if [ -z "$$SFETCH_BIN" ]; then echo "[!!] sfetch installation failed"; exit 1; fi; \
	echo "[ok] sfetch: $$SFETCH_BIN"
	@echo ""
	@SFETCH_BIN=""; \
	if [ -x "$(BIN_DIR)/sfetch" ]; then SFETCH_BIN="$(BIN_DIR)/sfetch"; \
	elif command -v sfetch >/dev/null 2>&1; then SFETCH_BIN="$$(command -v sfetch)"; fi; \
	if [ "$(FORCE)" = "1" ] || ! command -v goneat >/dev/null 2>&1; then \
		echo "[..] Installing goneat $(GONEAT_VERSION) via sfetch (user-space)..."; \
		$$SFETCH_BIN --repo fulmenhq/goneat --tag $(GONEAT_VERSION); \
	else \
		echo "[ok] goneat already installed"; \
	fi
	@if command -v goneat >/dev/null 2>&1; then \
		echo "[ok] goneat: $$(goneat version 2>&1 | head -n1)"; \
	else \
		echo "[!!] goneat installation failed"; exit 1; \
	fi
	@echo ""
	@echo "[..] Checking Rust dev tools..."
	@if ! command -v cargo-deny >/dev/null 2>&1; then \
		echo "[..] Installing cargo-deny..."; \
		cargo install cargo-deny --locked; \
	else \
		echo "[ok] cargo-deny installed"; \
	fi
	@if ! command -v cargo-audit >/dev/null 2>&1; then \
		echo "[..] Installing cargo-audit..."; \
		cargo install cargo-audit --locked; \
	else \
		echo "[ok] cargo-audit installed"; \
	fi
	@if ! command -v cbindgen >/dev/null 2>&1; then \
		echo "[..] Installing cbindgen..."; \
		cargo install cbindgen --locked; \
	else \
		echo "[ok] cbindgen installed"; \
	fi
	@if ! cargo set-version -V >/dev/null 2>&1; then \
		echo "[..] Installing cargo-edit..."; \
		cargo install cargo-edit --locked; \
	else \
		echo "[ok] cargo-edit installed"; \
	fi
	@echo ""
	@echo "[ok] Bootstrap complete"

bootstrap-force: ## Force reinstall all tools
	@$(MAKE) bootstrap FORCE=1

tools: ## Verify external tools are available
	@echo "Verifying tools..."
	@if command -v cargo >/dev/null 2>&1; then \
		echo "[ok] cargo: $$(cargo --version)"; \
	else \
		echo "[!!] cargo not found (required - install rustup)"; \
	fi
	@if cargo fmt --version >/dev/null 2>&1; then \
		echo "[ok] rustfmt: $$(cargo fmt --version)"; \
	else \
		echo "[!!] rustfmt not found (rustup component add rustfmt)"; \
	fi
	@if cargo clippy --version >/dev/null 2>&1; then \
		echo "[ok] clippy: $$(cargo clippy --version)"; \
	else \
		echo "[!!] clippy not found (rustup component add clippy)"; \
	fi
	@if command -v cargo-deny >/dev/null 2>&1; then \
		echo "[ok] cargo-deny: $$(cargo-deny --version)"; \
	else \
		echo "[!!] cargo-deny not found (cargo install cargo-deny)"; \
	fi
	@if command -v cargo-audit >/dev/null 2>&1; then \
		echo "[ok] cargo-audit: $$(cargo-audit --version)"; \
	else \
		echo "[!!] cargo-audit not found (cargo install cargo-audit)"; \
	fi
	@if command -v cbindgen >/dev/null 2>&1; then \
		echo "[ok] cbindgen: $$(cbindgen --version)"; \
	else \
		echo "[!!] cbindgen not found (cargo install cbindgen)"; \
	fi
	@if cargo set-version -V >/dev/null 2>&1; then \
		echo "[ok] cargo-edit: $$(cargo set-version -V)"; \
	else \
		echo "[!!] cargo-edit not found (cargo install cargo-edit)"; \
	fi
	@if [ -x "$(BIN_DIR)/sfetch" ]; then \
		echo "[ok] sfetch: $(BIN_DIR)/sfetch"; \
	elif command -v sfetch >/dev/null 2>&1; then \
		echo "[ok] sfetch: $$(command -v sfetch)"; \
	else \
		echo "[!!] sfetch not found (run 'make bootstrap')"; \
	fi
	@if command -v goneat >/dev/null 2>&1; then \
		echo "[ok] goneat: $$(goneat version 2>&1 | head -n1)"; \
	else \
		echo "[!!] goneat not found (run 'make bootstrap')"; \
	fi
	@echo ""

# -----------------------------------------------------------------------------
# Quality Gates
# -----------------------------------------------------------------------------

check: fmt-check lint test deny ## Run all quality checks
	@echo "[ok] All quality checks passed"

check-all: check ## Back-compat alias for older docs/tools

test: ## Run test suite
	@echo "Running tests..."
	$(CARGO) test --workspace --all-features
	@echo "[ok] Tests passed"

fmt: ## Format code (cargo fmt + goneat format)
	@echo "Formatting Rust..."
	$(CARGO) fmt --all
	@if command -v goneat >/dev/null 2>&1; then \
		echo "Formatting markdown, YAML, JSON..."; \
		goneat format --quiet; \
	else \
		echo "[!!] goneat not found — skipping non-Rust formatting (run 'make bootstrap')"; \
	fi
	@echo "[ok] Formatting complete"

fmt-check: ## Check formatting without modifying
	@echo "Checking Rust formatting..."
	$(CARGO) fmt --all -- --check
	@if command -v goneat >/dev/null 2>&1; then \
		echo "Checking markdown, YAML, JSON formatting..."; \
		goneat format --check --quiet; \
	else \
		echo "[!!] goneat not found — skipping non-Rust format check (run 'make bootstrap')"; \
	fi
	@echo "[ok] Formatting check passed"

lint: ## Run linting (cargo clippy + goneat lint)
	@echo "Linting Rust..."
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings
	@if command -v goneat >/dev/null 2>&1; then \
		echo "Linting YAML, shell, workflows..."; \
		goneat assess --categories lint --fail-on medium --ci-summary --log-level warn --output /dev/null --scope \
			--include '.github/workflows/**/*.yml' \
			--include '.github/workflows/**/*.yaml' \
			--include '.goneat/**/*.yaml' \
			--include '**/*.sh' \
			--include '**/Makefile'; \
	else \
		echo "[!!] goneat not found — skipping non-Rust linting (run 'make bootstrap')"; \
	fi
	@echo "[ok] Linting passed"

check-windows: check-windows-msvc check-windows-gnu ## Run Windows target cargo checks (no link)
	@echo "[ok] Windows target checks passed"

check-windows-msvc: ## Windows target check: x86_64-pc-windows-msvc
	@echo "Checking Windows target (x86_64-pc-windows-msvc)..."
	rustup target add x86_64-pc-windows-msvc
	RUSTFLAGS="-Dwarnings" $(CARGO) check --workspace --exclude seclusor-ffi --target x86_64-pc-windows-msvc
	@echo "[ok] x86_64-pc-windows-msvc check passed"

check-windows-gnu: ## Windows target check: x86_64-pc-windows-gnu
	@echo "Checking Windows target (x86_64-pc-windows-gnu)..."
	rustup target add x86_64-pc-windows-gnu
	RUSTFLAGS="-Dwarnings" $(CARGO) check --workspace --exclude seclusor-ffi --target x86_64-pc-windows-gnu
	@echo "[ok] x86_64-pc-windows-gnu check passed"

msrv: ## Verify build with Minimum Supported Rust Version
	@echo "Checking MSRV (core crates)..."
	@echo "[--] MSRV not yet declared — will set after D2 when external deps are locked"

miri: ## Run Miri to detect undefined behavior in FFI crate (requires nightly)
	@echo "Running Miri..."
	@if rustup run nightly cargo miri --version >/dev/null 2>&1; then \
		rustup run nightly cargo miri test -p seclusor-core --lib && \
		rustup run nightly cargo miri test -p seclusor-ffi --lib; \
	else \
		echo "[!!] Miri not installed. Install with:"; \
		echo "  rustup +nightly component add miri"; \
		exit 1; \
	fi
	@echo "[ok] Miri passed"

deny: ## Run cargo-deny license checks (offline-safe, no advisory db fetch)
	@echo "Running cargo-deny..."
	@if command -v cargo-deny >/dev/null 2>&1; then \
		cargo-deny check licenses bans sources; \
	else \
		echo "[!!] cargo-deny not found (run 'make bootstrap')"; \
		exit 1; \
	fi
	@echo "[ok] cargo-deny passed"

deny-all: ## Run full cargo-deny checks (includes advisories; may require network)
	@echo "Running cargo-deny (all checks)..."
	@if command -v cargo-deny >/dev/null 2>&1; then \
		cargo-deny check; \
	else \
		echo "[!!] cargo-deny not found (run 'make bootstrap')"; \
		exit 1; \
	fi
	@echo "[ok] cargo-deny (all) passed"

audit: ## Run cargo-audit security scan
	@echo "Running cargo-audit..."
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo-audit audit; \
	else \
		echo "[!!] cargo-audit not found (run 'make bootstrap')"; \
		exit 1; \
	fi
	@echo "[ok] cargo-audit passed"

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------

build: embed-verify ## Build all crates (debug)
	@echo "Building (debug)..."
	$(CARGO) build --workspace
	@echo "[ok] Build complete"

build-release: ## Build all crates (release)
	@echo "Building (release)..."
	$(CARGO) build --workspace --release
	@echo "[ok] Release build complete"

ffi-header: ## Generate C header from seclusor-ffi
	@echo "Generating FFI header..."
	@if command -v cbindgen >/dev/null 2>&1; then \
		cbindgen --config cbindgen.toml --crate seclusor-ffi --output crates/seclusor-ffi/seclusor.h; \
		echo "[ok] Generated crates/seclusor-ffi/seclusor.h"; \
	else \
		echo "[!!] cbindgen not found (cargo install cbindgen)"; \
		exit 1; \
	fi

build-ffi: ffi-header ## Build FFI library artifacts
	@echo "Building seclusor-ffi..."
	$(CARGO) build --release -p seclusor-ffi
	@echo "[ok] Built target/release/libseclusor_ffi.a and shared library variants"

go-bindings-sync: build-ffi ## Sync FFI header + static lib into Go bindings
	@echo "Syncing FFI artifacts for Go ($(GO_PLATFORM))..."
	@mkdir -p $(GO_BINDINGS_DIR)/include
	@mkdir -p $(GO_BINDINGS_DIR)/lib/local/$(GO_PLATFORM)
	@mkdir -p $(GO_BINDINGS_DIR)/lib/$(GO_PLATFORM)
	@cp crates/seclusor-ffi/seclusor.h $(GO_BINDINGS_DIR)/include/seclusor.h
	@cp target/release/libseclusor_ffi.a $(GO_BINDINGS_DIR)/lib/local/$(GO_PLATFORM)/libseclusor_ffi.a
	@echo "[ok] Synced Go binding artifacts into $(GO_BINDINGS_DIR)"

go-bindings-ci: ## Dispatch Go bindings prep workflow for current VERSION
	@echo "Dispatching Go bindings prep workflow for v$(VERSION)..."
	@gh workflow run go-bindings.yml -f version=$(VERSION)
	@echo "[ok] Workflow dispatched"

go-build: go-bindings-sync ## Build Go bindings
	@echo "Building Go bindings..."
	@cd $(GO_BINDINGS_DIR) && go build ./...
	@echo "[ok] Go bindings build complete"

go-test: go-bindings-sync ## Run Go bindings tests
	@echo "Running Go bindings tests..."
	@cd $(GO_BINDINGS_DIR) && go test ./...
	@echo "[ok] Go bindings tests passed"

go-test-committed: ## Run Go bindings tests against committed prebuilt lib
	@echo "Running Go bindings tests against committed lib ($(GO_PLATFORM))..."
	@committed_lib="$(GO_BINDINGS_DIR)/lib/$(GO_PLATFORM)/libseclusor_ffi.a"; \
	local_lib="$(GO_BINDINGS_DIR)/lib/local/$(GO_PLATFORM)/libseclusor_ffi.a"; \
	backup_lib="$$local_lib.bak"; \
	if [ ! -f "$$committed_lib" ]; then \
		echo "[!!] Missing committed FFI lib: $$committed_lib"; \
		exit 1; \
	fi; \
	restore() { \
		if [ -f "$$backup_lib" ]; then \
			mv "$$backup_lib" "$$local_lib"; \
		fi; \
	}; \
	trap restore EXIT INT TERM; \
	if [ -f "$$local_lib" ]; then \
		mv "$$local_lib" "$$backup_lib"; \
	fi; \
	cd $(GO_BINDINGS_DIR) && go test ./...
	@echo "[ok] Go bindings tests passed against committed lib"

ts-build: ## Build TypeScript bindings
	@echo "Building TypeScript bindings..."
	@cd $(TS_BINDINGS_DIR) && npm install && npm run build
	@echo "[ok] TypeScript bindings build complete"

ts-test: ## Run TypeScript bindings tests
	@echo "Running TypeScript bindings tests..."
	@cd $(TS_BINDINGS_DIR) && npm install && npm test
	@echo "[ok] TypeScript bindings tests passed"

embed-verify: ## Verify docs embed manifest/build pipeline
	@echo "Verifying embedded docs build pipeline..."
	@$(CARGO) check -p seclusor
	@$(CARGO) run -q -p seclusor -- docs list --format json >/dev/null
	@echo "[ok] Embedded docs verification passed"

clean: ## Remove build artifacts
	@echo "Cleaning..."
	$(CARGO) clean
	@rm -rf bin/
	@echo "[ok] Clean complete"

# -----------------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------------

INSTALL_BINDIR ?= $(HOME)/.local/bin

install: build-release ## Install seclusor binary to INSTALL_BINDIR
	@echo "Installing seclusor to $(INSTALL_BINDIR)..."
	@mkdir -p "$(INSTALL_BINDIR)"
	@cp target/release/seclusor "$(INSTALL_BINDIR)/seclusor"
	@chmod 755 "$(INSTALL_BINDIR)/seclusor"
	@echo "[ok] Installed seclusor to $(INSTALL_BINDIR)/seclusor"

dogfood-cli: ## Run end-to-end CLI dogfooding matrix
	@echo "Running CLI dogfooding matrix..."
	@bash scripts/dogfood/cli-matrix.sh
	@echo "[ok] CLI dogfooding matrix passed"

# -----------------------------------------------------------------------------
# Pre-commit / Pre-push Hooks
# -----------------------------------------------------------------------------

precommit: fmt-check lint ## Run pre-commit checks (fast)
	@echo "[ok] Pre-commit checks passed"

prepush: repo-status check version-check go-test ts-test ## Run pre-push checks (thorough)
	@echo "[ok] Pre-push checks passed"

repo-status: ## Fail if working tree has uncommitted changes (goneat assess repo-status)
	@if command -v goneat >/dev/null 2>&1; then \
		goneat assess --categories repo-status --fail-on high --ci-summary --log-level warn; \
	else \
		echo "Checking working tree..."; \
		if [ -n "$$(git status --porcelain 2>/dev/null)" ]; then \
			echo "[!!] Working tree not clean — commit or stash changes before pushing"; \
			git status --short; \
			exit 1; \
		fi; \
		echo "[ok] Working tree is clean"; \
	fi

# -----------------------------------------------------------------------------
# Version Management
# -----------------------------------------------------------------------------

VERSION_FILE := VERSION

version: ## Print current version
	@echo "$(VERSION)"

version-patch: ## Bump patch version (0.1.0 -> 0.1.1)
	@current=$$(cat $(VERSION_FILE)); \
	major=$$(echo $$current | cut -d. -f1); \
	minor=$$(echo $$current | cut -d. -f2); \
	patch=$$(echo $$current | cut -d. -f3); \
	new_patch=$$((patch + 1)); \
	new_version="$$major.$$minor.$$new_patch"; \
	echo "$$new_version" > $(VERSION_FILE); \
	echo "Version bumped: $$current -> $$new_version"
	@$(MAKE) version-sync

version-minor: ## Bump minor version (0.1.0 -> 0.2.0)
	@current=$$(cat $(VERSION_FILE)); \
	major=$$(echo $$current | cut -d. -f1); \
	minor=$$(echo $$current | cut -d. -f2); \
	new_minor=$$((minor + 1)); \
	new_version="$$major.$$new_minor.0"; \
	echo "$$new_version" > $(VERSION_FILE); \
	echo "Version bumped: $$current -> $$new_version"
	@$(MAKE) version-sync

version-major: ## Bump major version (0.1.0 -> 1.0.0)
	@current=$$(cat $(VERSION_FILE)); \
	major=$$(echo $$current | cut -d. -f1); \
	new_major=$$((major + 1)); \
	new_version="$$new_major.0.0"; \
	echo "$$new_version" > $(VERSION_FILE); \
	echo "Version bumped: $$current -> $$new_version"
	@$(MAKE) version-sync

version-set: ## Set explicit version (V=X.Y.Z)
	@if [ -z "$(V)" ]; then \
		echo "Usage: make version-set V=1.2.3"; \
		exit 1; \
	fi
	@echo "$(V)" > $(VERSION_FILE)
	@echo "Version set to $(V)"
	@$(MAKE) version-sync

version-sync: ## Sync VERSION file to Cargo.toml and package.json
	@ver=$$(cat $(VERSION_FILE)); \
	if command -v cargo-set-version >/dev/null 2>&1; then \
		cargo set-version --workspace "$$ver"; \
		echo "[ok] Synced Cargo.toml to $$ver"; \
	else \
		echo "[!!] cargo-edit not installed (cargo install cargo-edit)"; \
		echo "Manual update required: set version = \"$$ver\" in Cargo.toml"; \
	fi
	@ver=$$(cat $(VERSION_FILE)); \
	ts_root="$(TS_BINDINGS_DIR)"; \
	if [ -f "$$ts_root/package.json" ]; then \
		sed -i.bak 's/"version": "[^"]*"/"version": "'"$$ver"'"/' "$$ts_root/package.json"; \
		rm -f "$$ts_root/package.json.bak"; \
		echo "[ok] Synced $$ts_root/package.json to $$ver"; \
	fi

version-check: ## Validate version consistency across files
	@echo "Checking version consistency..."
	@file_ver=$$(cat $(VERSION_FILE) | tr -d '[:space:]'); \
	cargo_ver=$$($(CARGO) metadata --format-version 1 --no-deps 2>/dev/null | \
		grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4); \
	if [ "$$file_ver" != "$$cargo_ver" ]; then \
		echo "[!!] VERSION file ($$file_ver) != Cargo.toml ($$cargo_ver)"; \
		exit 1; \
	fi
	@echo "[ok] Version consistent: $(VERSION)"

# -----------------------------------------------------------------------------
# CI/CD
# -----------------------------------------------------------------------------

ci: fmt-check lint test deny version-check ## Run exactly what CI runs
	@echo "[ok] CI checks passed"

release-check: version-check ## Version consistency + package check
	@echo "Checking release readiness..."
	@echo ""
	@echo "Packaging all workspace crates..."
	@$(CARGO) package --workspace
	@echo "[ok] All crates package successfully"
	@echo ""
	@echo "Release checklist:"
	@echo "  + Version consistency validated"
	@echo "  + All crates pass package check"
	@echo ""
	@echo "Next steps:"
	@echo "  1. make release-preflight"
	@echo "  2. git tag v$$(cat $(VERSION_FILE))"
	@echo "  3. git push origin v$$(cat $(VERSION_FILE))"
	@echo "  4. Wait for CI + release workflow"
	@echo "  5. make release (sign + upload)"

# -----------------------------------------------------------------------------
# Release Signing
# -----------------------------------------------------------------------------
#
# Workflow:
# 1. Pre-tag: make release-preflight
# 2. Tag and push: git tag vX.Y.Z && git push origin vX.Y.Z
# 3. Wait for GitHub Actions release workflow to create draft release
# 4. Sign locally: make release (or individual steps below)
#
# Environment variables (source ~/devsecops/vars/3leaps-seclusor-cicd.sh):
#   SECLUSOR_MINISIGN_KEY  - Path to minisign secret key (required)
#   SECLUSOR_MINISIGN_PUB  - Path to minisign public key (optional, derived from KEY)
#   SECLUSOR_PGP_KEY_ID    - PGP key ID for GPG signing (optional)
#   SECLUSOR_GPG_HOMEDIR   - Custom GPG home directory (optional)
#
# --- Bindings release workflow ---
# Go bindings:
#   Before tagging, run go-bindings.yml workflow (manual dispatch).
#   Workflow builds FFI for all platforms and creates PR with prebuilt libs.
#   Merge the PR, then tag the merge commit.
#
# TypeScript bindings:
#   After tagging and signing, run typescript-napi-prebuilds.yml on the tag.
#   Then run typescript-npm-publish.yml with OIDC trusted publishing.

DIST_RELEASE := dist/release
SECLUSOR_RELEASE_TAG ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo v$(VERSION))

# Signing keys (set via environment or vars file)
SECLUSOR_MINISIGN_KEY ?=
SECLUSOR_MINISIGN_PUB ?=
SECLUSOR_PGP_KEY_ID ?=
SECLUSOR_GPG_HOMEDIR ?=

release-preflight: ## Verify all pre-tag requirements (REQUIRED before tagging)
	@echo "Running release preflight checks..."
	@echo ""
	@# Check 1: Working tree must be clean
	@if [ -n "$$(git status --porcelain 2>/dev/null)" ]; then \
		echo "[!!] Working tree not clean - commit or stash changes first"; \
		git status --short; \
		exit 1; \
	fi
	@echo "[ok] Working tree is clean"
	@# Check 2: Prepush quality gates
	@$(MAKE) prepush --silent
	@echo "[ok] Prepush checks passed"
	@# Check 3: Version sync (full check: VERSION, Cargo.toml)
	@$(MAKE) version-check --silent
	@echo "[ok] Version synced"
	@# Check 4: Release notes exist
	@version_file=$$(cat $(VERSION_FILE) 2>/dev/null); \
	release_notes="docs/releases/v$$version_file.md"; \
	if [ ! -f "$$release_notes" ]; then \
		echo "[!!] Release notes not found at $$release_notes"; \
		exit 1; \
	fi
	@echo "[ok] Release notes exist"
	@# Check 5: Local/remote sync
	@echo "[..] Verifying local/remote sync..."; \
	git fetch origin >/dev/null 2>&1; \
	local_only=$$(git log --oneline origin/main..HEAD 2>/dev/null | wc -l | tr -d ' '); \
	remote_only=$$(git log --oneline HEAD..origin/main 2>/dev/null | wc -l | tr -d ' '); \
	if [ "$$local_only" -gt 0 ] || [ "$$remote_only" -gt 0 ]; then \
		echo "[!!] Local and remote are out of sync"; \
		if [ "$$local_only" -gt 0 ]; then \
			echo "    $$local_only local commit(s) not pushed"; \
		fi; \
		if [ "$$remote_only" -gt 0 ]; then \
			echo "    $$remote_only remote commit(s) not pulled"; \
		fi; \
		exit 1; \
	fi
	@echo "[ok] Local and remote are in sync"
	@echo ""
	@echo "[ok] All preflight checks passed - ready to tag"
	@version_file=$$(cat $(VERSION_FILE) 2>/dev/null); \
	echo "    Next: git tag \"v$$version_file\" -m \"Release $$version_file\""

release-clean: ## Remove dist/release contents
	@echo "Cleaning release directory..."
	rm -rf $(DIST_RELEASE)
	@echo "[ok] Release directory cleaned"

release-download: ## Download release assets from GitHub
	@if [ -z "$(SECLUSOR_RELEASE_TAG)" ] || [ "$(SECLUSOR_RELEASE_TAG)" = "v" ]; then \
		echo "Error: No release tag found. Set SECLUSOR_RELEASE_TAG=vX.Y.Z"; \
		exit 1; \
	fi
	./scripts/download-release-assets.sh $(SECLUSOR_RELEASE_TAG) $(DIST_RELEASE)

release-checksums: ## Generate SHA256SUMS and SHA512SUMS
	./scripts/generate-checksums.sh $(DIST_RELEASE)

release-sign: ## Sign checksum manifests (requires SECLUSOR_MINISIGN_KEY)
	@if [ -z "$(SECLUSOR_MINISIGN_KEY)" ]; then \
		echo "Error: SECLUSOR_MINISIGN_KEY not set"; \
		echo ""; \
		echo "Source the vars file:"; \
		echo "  source ~/devsecops/vars/3leaps-seclusor-cicd.sh"; \
		exit 1; \
	fi
	SECLUSOR_MINISIGN_KEY=$(SECLUSOR_MINISIGN_KEY) \
	SECLUSOR_PGP_KEY_ID=$(SECLUSOR_PGP_KEY_ID) \
	SECLUSOR_GPG_HOMEDIR=$(SECLUSOR_GPG_HOMEDIR) \
	./scripts/sign-release-assets.sh $(SECLUSOR_RELEASE_TAG) $(DIST_RELEASE)

release-export-keys: ## Export public signing keys
	SECLUSOR_MINISIGN_KEY=$(SECLUSOR_MINISIGN_KEY) \
	SECLUSOR_MINISIGN_PUB=$(SECLUSOR_MINISIGN_PUB) \
	SECLUSOR_PGP_KEY_ID=$(SECLUSOR_PGP_KEY_ID) \
	SECLUSOR_GPG_HOMEDIR=$(SECLUSOR_GPG_HOMEDIR) \
	./scripts/export-release-keys.sh $(DIST_RELEASE)

release-verify-checksums: ## Verify checksums match artifacts
	@echo "Verifying checksums..."
	cd $(DIST_RELEASE) && shasum -a 256 -c SHA256SUMS
	@echo "[ok] Checksums verified"

release-verify-signatures: ## Verify minisign/PGP signatures
	./scripts/verify-signatures.sh $(DIST_RELEASE)

release-verify-keys: ## Verify exported keys are public-only
	./scripts/verify-public-keys.sh $(DIST_RELEASE)

release-verify: release-verify-checksums release-verify-signatures release-verify-keys ## Run all release verification
	@echo "[ok] All release verifications passed"

release-notes: ## Copy release notes to dist
	@src="docs/releases/$(SECLUSOR_RELEASE_TAG).md"; \
	if [ -f "$$src" ]; then \
		cp "$$src" "$(DIST_RELEASE)/release-notes-$(SECLUSOR_RELEASE_TAG).md"; \
		echo "[ok] Copied release notes"; \
	else \
		echo "[--] No release notes found at $$src"; \
	fi

release-upload: release-verify release-notes ## Upload signed artifacts to GitHub release
	./scripts/upload-release-assets.sh $(SECLUSOR_RELEASE_TAG) $(DIST_RELEASE)

release: release-clean release-download release-checksums release-sign release-export-keys release-upload ## Full signing workflow (after CI build)
	@echo "[ok] Release $(SECLUSOR_RELEASE_TAG) complete"
