.PHONY: help build run test test-verbose test-coverage-html lint fmt-check vet check \
        migrate-up migrate-down migrate-create sqlc docker-up docker-down docker-logs clean \
        frontend-dev frontend-test frontend-build frontend-install dev backend provision-admin

APP_NAME=go-clean-api
BUILD_DIR=./build

# Load local environment values for migration and runtime targets when present.
ifneq (,$(wildcard .env))
include .env
export
endif

help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the Go binary + frontend
	mkdir -p $(BUILD_DIR)
	$(MAKE) frontend-build
	go build -ldflags="-w -s" -o $(BUILD_DIR)/$(APP_NAME) ./cmd/api

run: ## Run the application locally (serves API + frontend)
	$(MAKE) frontend-build
	go run ./cmd/api

dev: ## Run both backend and frontend in dev mode
	@echo "Start the frontend dev server in another terminal:"
	@echo "  cd frontend && npm run dev"
	@echo "Then start the backend:"
	@echo "  go run ./cmd/api"
	@$(MAKE) -j2 backend frontend-dev

backend: ## Run backend with live reload (requires air)
	air

test: ## Run all tests with race detection
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-verbose: ## Run all tests with verbose output
	go test -v -race -count=1 ./...

test-coverage-html: ## Run tests and generate HTML coverage report
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

fmt-check: ## Check Go formatting without modifying files
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './frontend/*'))" || \
		(echo "gofmt required:"; gofmt -l $$(find . -name '*.go' -not -path './frontend/*'); exit 1)

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint when it is installed
	golangci-lint run ./...

check: fmt-check vet test frontend-test frontend-build ## Run the local verification suite

migrate-up: ## Run database migrations up
	migrate -path migrations -database "$(DATABASE_URL)" up

migrate-down: ## Run database migrations down
	migrate -path migrations -database "$(DATABASE_URL)" down 1

migrate-create: ## Create a new migration (usage: make migrate-create NAME=xxx)
	migrate create -ext sql -dir migrations -seq $(NAME)

sqlc: ## Generate Go code from SQL queries using sqlc
	sqlc generate

provision-admin: ## Explicitly create one administrator (requires ADMIN_* variables)
	go run ./cmd/admin

frontend-install: ## Install frontend dependencies from the lockfile
	cd frontend && npm ci --ignore-scripts

frontend-dev: ## Start frontend dev server with hot reload
	cd frontend && npm run dev

frontend-test: ## Run frontend tests with the Node.js built-in test runner
	cd frontend && npm test

frontend-build: ## Build frontend for production
	cd frontend && npm run build

docker-up: ## Start all Docker services (full stack)
	docker compose up -d --build

docker-down: ## Stop all Docker services
	docker compose down

docker-logs: ## Follow Docker logs
	docker compose logs -f api

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR) coverage.out coverage.html
	rm -rf frontend/dist frontend/node_modules
