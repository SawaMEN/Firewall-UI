.PHONY: build frontend test
frontend:
	cd frontend && npm ci --ignore-scripts && npm run build
build: frontend
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o firewall-ui ./cmd/firewall-ui
test:
	go test -race ./...
	go vet ./...
	bash -n install.sh deploy/firewall-ui
	bash tests/installer.sh
	bash tests/manager.sh
	bash tests/access.sh
	bash tests/uninstall.sh
	cd frontend && npm run typecheck
