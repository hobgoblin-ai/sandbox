#!/usr/bin/env bash
# Full sandbox check on a real host: Fedora/RHEL, rootless podman >= 5,
# crun-krun, /dev/kvm, network access. Build images first: make images.
#
# Every check below is an attempt the agent might make; each must fail for
# the right reason (or, for allowed traffic, succeed).
set -euo pipefail
cd "$(dirname "$0")/.."

SELINUX_FLAG=()
if [[ "${HOBGOBLIN_E2E_SELINUX:-}" == hobgoblin ]]; then SELINUX_FLAG=(--selinux hobgoblin); fi

ws=$(mktemp -d)
trap 'rm -rf "$ws"' EXIT

read -r -d '' CHECKS <<'EOF' || true
set -u
fail=0
pass() { printf '  PASS  %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fail=1; }
proxy=${HTTPS_PROXY#http://}; proxy_ip=${proxy%:*}
code() { curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$@" 2>/dev/null || true; }

echo "inside agent: kernel $(uname -r), proxy $proxy"

[[ "$(uname -r)" != "$HOST_KERNEL" ]] && pass "runs on its own kernel (microVM)" || bad "same kernel as host: not a microVM"

[[ $(code https://pypi.org/simple/requests/) == 200 ]] && pass "allowed tunnel host (pypi.org) works" || bad "pypi.org via proxy"
c=$(code https://example.com/); [[ $c == 000 || $c == 403 ]] && pass "unlisted host refused (example.com)" || bad "example.com returned $c"

curl -sS --noproxy '*' --max-time 5 -o /dev/null https://1.1.1.1/ 2>/dev/null && bad "direct egress bypassing proxy" || pass "no direct egress (--noproxy)"
curl -sS --noproxy '*' --max-time 5 -o /dev/null http://[2606:4700:4700::1111]/ 2>/dev/null && bad "direct IPv6 egress" || pass "no direct IPv6 egress"
getent hosts pypi.org >/dev/null 2>&1 && bad "guest can resolve DNS (exfil channel)" || pass "no DNS resolution in guest"
dig +time=2 +tries=1 @1.1.1.1 example.com >/dev/null 2>&1 && bad "guest can query external DNS" || pass "no external DNS queries"

c=$(code http://169.254.169.254/latest/meta-data/); [[ $c != 200 ]] && pass "cloud metadata unreachable via proxy ($c)" || bad "metadata reachable"
curl -sS --noproxy '*' --max-time 5 -o /dev/null http://169.254.169.254/ 2>/dev/null && bad "metadata reachable directly" || pass "cloud metadata unreachable directly"
curl -sS --noproxy '*' --max-time 5 -o /dev/null http://host.containers.internal/ 2>/dev/null && bad "host reachable" || pass "host not reachable"
curl -sS --noproxy '*' --max-time 3 -o /dev/null "http://$proxy_ip:8080/" 2>/dev/null && bad "other proxy ports open" || pass "only the proxy port is reachable"

git ls-remote https://github.com/containers/podman HEAD >/dev/null 2>&1 && pass "git read from allowed org" || bad "git read from allowed org"
git ls-remote https://github.com/torvalds/linux HEAD >/dev/null 2>&1 && bad "git read outside allowed org" || pass "git read outside allowed org refused"
[[ $(code -X POST https://github.com/containers/podman.git/git-receive-pack) == 403 ]] && pass "git push endpoint refused" || bad "git push endpoint not refused"
[[ $(code -H 'Host: gist.github.com' https://github.com/containers/podman) == 421 ]] && pass "Host header fronting refused" || bad "Host header fronting"
[[ $(code --path-as-is 'https://github.com/containers/../torvalds/linux') == 403 ]] && pass "dot-segment path trick refused" || bad "dot-segment path not refused"

files=$(ls /etc/hobgoblin | sort | tr '\n' ' ')
[[ $files == "ca-bundle.pem ca.pem " ]] && pass "agent sees only CA certs in /etc/hobgoblin" || bad "/etc/hobgoblin has: $files"
grep -rqs "PRIVATE KEY" /etc/hobgoblin && bad "private key visible to agent" || pass "no private key visible"
openssl x509 -in /etc/hobgoblin/ca.pem -noout -text 2>/dev/null | grep -q "Name Constraints: critical" && pass "session CA is name-constrained" || bad "CA not name-constrained"
exit $fail
EOF

echo "== hobgoblin e2e (host kernel $(uname -r))"
hobgobs doctor || { echo "doctor reported problems"; exit 1; }
set +e
hobgobs run "${SELINUX_FLAG[@]}" --policy scripts/e2e-policy.toml --workspace "$ws" --no-state \
  -e "HOST_KERNEL=$(uname -r)" -- bash -c "$CHECKS"
rc=$?
set -e
if [[ $rc -eq 0 ]]; then echo "== e2e: all checks passed"; else echo "== e2e: FAILED (rc=$rc)"; fi
exit $rc
