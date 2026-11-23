PODMAN        ?= podman
PROXY_IMAGE   ?= localhost/hobgoblin-proxy:latest
AGENT_IMAGE   ?= localhost/hobgoblin-agent:latest
UDICA         ?= /usr/share/udica/templates
PYTHON        ?= python3
UV            ?= uv

.PHONY: help install dev images proxy-image agent-image selinux-install selinux-remove test e2e clean

help:
	@echo "make install          install the hobgobs launcher for this user (stdlib only)"
	@echo "make dev              sync the local development environment with uv"
	@echo "make images           build proxy and example agent images"
	@echo "make selinux-install  load the hobgoblin_proxy SELinux module (sudo)"
	@echo "make test             unit + proxy end-to-end tests (via uv)"
	@echo "make e2e              full sandbox check on a Fedora/RHEL host with KVM"

install:
	$(PYTHON) -m pip install --user .

dev:
	$(UV) sync --locked

images: proxy-image agent-image

proxy-image:
	$(PODMAN) build -t $(PROXY_IMAGE) -f containers/proxy/Containerfile .

agent-image:
	$(PODMAN) build -t $(AGENT_IMAGE) containers/agent

selinux-install:
	sudo semodule -i selinux/hobgoblin_proxy.cil $(UDICA)/base_container.cil $(UDICA)/net_container.cil

selinux-remove:
	sudo semodule -r hobgoblin_proxy

test:
	$(UV) run --locked python -m pytest -q

e2e:
	$(UV) run --locked scripts/e2e-fedora.sh

clean:
	rm -rf build dist src/*.egg-info .pytest_cache
