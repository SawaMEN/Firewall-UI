.PHONY: build frontend test
frontend:
	cd frontend && npm ci --ignore-scripts && npm run build
build: frontend
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o firewall-ui ./cmd/firewall-ui
test:
	go test -race ./...
	go vet ./...
	cd frontend && npm run typecheck
