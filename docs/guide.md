# Using hobgoblin

Run these examples on the host from the hobgoblin checkout, after the
[one-time setup](../README.md#run-opencode). For the shell demo, skip the
API secret.

## Try a policy without an API key

Give a shell permission to read the PyPI metadata for **one package**. Keep
the policy beside the workspace so the shell can edit the project but not
the copy of the policy you'll use next time.

```bash
demo=$(mktemp -d)
mkdir "$demo/project"
cat > "$demo/policy.toml" <<'TOML'
version = 1

[[rule]]
host = "pypi.org"
action = "inspect"

[[rule.allow]]
methods = ["GET"]
paths = ["/pypi/requests/json"]
TOML

hobgobs check-policy "$demo/policy.toml"
hobgobs run --policy "$demo/policy.toml" --workspace "$demo/project" --no-state -- bash
```

Inside the VM, send two requests to the same host:

```bash
curl -sS https://pypi.org/pypi/requests/json | jq -r .info.version
curl -i https://pypi.org/pypi/pip/json
exit
```

The first prints the version of `requests`. The second gets a `403` from
the proxy: `GET /pypi/pip/json` is outside the allow list. On exit the
launcher prints an audit summary, including the reason for the denial.

## Run Claude Code

The [agent image](../containers/agent/Containerfile) includes Claude Code.
With `ANTHROPIC_API_KEY` set on the host, create the credential once:

```bash
printf '%s' "$ANTHROPIC_API_KEY" | podman secret create anthropic_api_key -
```

Start Claude on another project, using the policy from the checkout:

```bash
hobgobs run --policy examples/claude.toml --workspace "$HOME/src/myproject" -- claude
```

For a one-shot task, append `-p 'Summarize this project in three sentences.'`
after `claude`. To run a tool installed in another image, pass `--image IMAGE`
before `--`.

## Resume an OpenCode session

Use the same workspace and append `--continue` to the guest command:

```bash
hobgobs run --policy examples/opencode.toml -- /root/.opencode/bin/opencode --standalone --continue
```

For a non-interactive prompt, select a model your key can use:

```bash
hobgobs run --policy examples/opencode.toml -- \
  opencode run --standalone --model openai/gpt-5.4 'Summarize this project.'
```

State lives under `${XDG_STATE_HOME:-$HOME/.local/state}/hobgoblin/state/`,
in a directory keyed by the workspace's full path. The launcher prints its
location at startup. The guest's XDG directories, `CLAUDE_CONFIG_DIR` and
shell history point into `/state`; settings and plugins written there carry
over along with conversations. `--no-state` skips that mount for one run.
To reset saved state, remove that workspace's state directory on the host.

## Write a rule

| Action | What the proxy checks | Example use |
| --- | --- | --- |
| `inspect` | Terminates TLS with a per-session CA and checks HTTP methods and paths. Can inject credential headers. | Allow Git fetches for one organization or a single model endpoint. |
| `tunnel` | Checks the host, port and TLS server name, then passes encrypted traffic through. | Allow every path on a trusted package registry. |
| `tcp` | Checks the host and an explicitly listed port. | Connect to a non-HTTP service. |

An exact host wins over a wildcard. `*.example.com` matches subdomains but
not `example.com`. In a path, `*` stays in one segment and `**` can span
several. An `inspect` rule with no `[[rule.allow]]` permits **all** methods
and paths on that host.

`[[rule.inject]]` names a Podman secret and the header to replace on allowed
HTTPS requests. Only the proxy receives the secret and the session CA's
private key. The guest gets the public CA certificate and proxy settings.
See the [example policies](../examples/) for complete rules and the
[policy parser](../src/hobgoblin/policy.py) for network exceptions.

## Investigate a denial

On the host, use the session ID printed at startup:

```bash
hobgobs audit SESSION_ID
```

The log survives cleanup at
`${XDG_STATE_HOME:-$HOME/.local/state}/hobgoblin/sessions/SESSION_ID/audit.jsonl`.
For the shell demo, the summary distinguishes “host not allowed” from
“path not in allow list”: the latter needs a path change, not a new host.

To discover which destinations a task needs, try `mode = "audit"` under
`[defaults]` in a trial policy. **Audit mode allows unlisted destinations**
and logs what enforcement would have denied; the private-address guard
still applies. After the run, `hobgobs audit SESSION_ID --suggest`
drafts tunnel rules. Review them, narrow any rules that need path or method
restrictions to `inspect`, and switch back to `enforce`.

## Development and verification

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and run
`make dev` to sync the locked development environment. For the proxy integration
tests, map the following names to loopback in `/etc/hosts`; those tests
skip unless all five names resolve:

```text
127.0.0.1 allowed.hobgoblin.test inspect.hobgoblin.test evil.hobgoblin.test plain.hobgoblin.test ws.hobgoblin.test
```

```bash
make test
uv run --locked hobgobs run --policy examples/policy.toml --dry-run -- bash
```

The [tests](../tests/) cover policy decisions, address checks, the session
CA and a proxy talking to local TLS servers. Launcher tests use a fake
Podman. A dry run prints the Podman commands without starting a VM.

**Real-host verification is pending.** To check a running microVM on a
KVM-capable Fedora/RHEL host, build the images and run `make e2e`. See
the [host check](../scripts/e2e-fedora.sh) for the assertions.

On an SELinux-enforcing host, Podman gives the proxy and agent separate
labels. To use the optional proxy domain, install the `udica` templates,
run `make selinux-install` and pass `--selinux hobgoblin` to the launcher.
Run `HOBGOBLIN_E2E_SELINUX=hobgoblin make e2e` to exercise that domain.
