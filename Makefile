.PHONY: build frontend test test-go test-frontend test-shell

frontend/node_modules/.firewall-ui-installed: frontend/package.json frontend/package-lock.json
	cd frontend && npm ci --ignore-scripts
	touch $@

frontend: frontend/node_modules/.firewall-ui-installed
	cd frontend && npm run build

build: frontend
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o firewall-ui ./cmd/firewall-ui

# Independent groups can run concurrently with make -j3 test.
test: test-go test-frontend test-shell

test-go:
	go test -race -vet=off ./...
	go vet ./...

test-frontend: frontend/node_modules/.firewall-ui-installed
	cd frontend && npm test
	cd frontend && npm run typecheck

test-shell:
	bash -n install.sh deploy/firewall-ui deploy/firewall-ui-docker scripts/build-release.sh
	bash tests/installer.sh
	bash tests/manager.sh
	bash tests/access.sh
	bash tests/uninstall.sh
	bash tests/install-menu.sh
	bash tests/docker-installer.sh
