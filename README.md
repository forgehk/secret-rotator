# secret-rotator

> Rotate API keys across providers (AWS, GitHub, Stripe, ...) with snapshot-and-rollback safety. Pluggable provider drivers, YAML config, append-only audit log.

[![CI](https://github.com/forgehk/secret-rotator/actions/workflows/ci.yml/badge.svg)](https://github.com/forgehk/secret-rotator/actions/workflows/ci.yml) [![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg)]() [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Why this exists

Key rotation is one of those DevSecOps tasks every team knows they *should* do quarterly and nobody actually does. The friction is real: each provider has a different API, you need to keep the old key alive for a hot window so live services don't drop, and if you mess up you can take down production.

`secret-rotator` standardises the workflow:

1. **Snapshot** the current key version (so rollback is one command)
2. **Provision** a new key via the provider API
3. **Update** the consumer secret store (Vault / SSM / Doppler / etc.)
4. **Verify** the new key works
5. **Revoke** the old key after a grace period
6. Every step appended to a tamper-evident JSON-lines audit log

If any step fails, the run aborts and rollback re-installs the previous key from the snapshot.

---

## Quick example

```bash
$ secret-rotator rotate --config rotations.yaml --key aws_prod_deploy

[1/6] snapshot       OK    backup written to ~/.secret-rotator/snapshots/aws_prod_deploy-2026-05-17T08:14Z.json
[2/6] provision      OK    new key id: AKIA********ABCD
[3/6] update store   OK    SSM /app/prod/aws_access_key_id rotated
[4/6] verify         OK    boto3 sts.get_caller_identity returned 200
[5/6] grace 5 min    OK    waited for downstream pickup
[6/6] revoke old     OK    old key deactivated

rotation complete - audit log: ~/.secret-rotator/audit.jsonl
```

If step 4 fails:

```
[4/6] verify         FAIL  permission denied — see logs
rollback engaged...
[r/3] restore key    OK    new key revoked
[r/3] restore store  OK    SSM /app/prod/aws_access_key_id reverted
[r/3] notify         OK    posted to #ops-alerts
```

---

## Config format

```yaml
# rotations.yaml
keys:
  - name: aws_prod_deploy
    provider: aws_iam
    user: deploy-bot
    store:
      kind: ssm
      path: /app/prod/aws_access_key_id
    verify:
      kind: aws_sts
      region: us-west-2
    grace_seconds: 300

  - name: github_actions_deploy_pat
    provider: github_pat
    scopes: ["repo", "workflow"]
    store:
      kind: github_secret
      repo: forgehk/example-app
      name: DEPLOY_TOKEN
    verify:
      kind: github_user
    grace_seconds: 0  # PATs don't need overlap

  - name: stripe_webhook_signing
    provider: stripe_webhook
    endpoint: https://api.example.com/stripe-webhook
    store:
      kind: doppler
      project: example
      config: prd
      name: STRIPE_WEBHOOK_SECRET
    grace_seconds: 600

notify:
  slack_webhook: ${SLACK_OPS_WEBHOOK}
  on_failure: ["#sec-ops", "@oncall"]
```

---

## Architecture

```
              ┌──────────────────────────────────────┐
              │           rotator engine             │
              │  snapshot → provision → store →      │
              │  verify → grace → revoke (or roll back)
              └──┬─────────┬────────────┬───────────┘
                 │         │            │
   ┌─────────────┴──┐   ┌──┴───────┐   ┌┴──────────────┐
   │  provider      │   │  store   │   │  verifier     │
   │  drivers       │   │  drivers │   │  drivers      │
   │  aws_iam       │   │  ssm     │   │  aws_sts      │
   │  github_pat    │   │  doppler │   │  github_user  │
   │  stripe_webhook│   │  vault   │   │  http_ping    │
   └────────────────┘   └──────────┘   └───────────────┘
```

Each provider/store/verifier is a small class implementing a 3-method protocol. Adding a new SaaS is one file.

---

## Install

```bash
pip install git+https://github.com/forgehk/secret-rotator.git
secret-rotator --help
```

The package is not published on PyPI; the `secret-rotator` name there belongs to an unrelated project.

---

## Roadmap

- [x] Pluggable provider/store/verifier protocol
- [x] Append-only JSON-lines audit log
- [x] Snapshot-and-restore rollback path
- [x] Dry-run mode
- [ ] AWS IAM, SSM driver implementations
- [ ] GitHub PAT, github-secret driver
- [ ] Stripe webhook signing driver
- [ ] Vault store driver
- [ ] Slack failure notifier
- [ ] CRON entrypoint (`secret-rotator daemon`)

---

## License

[MIT](LICENSE)

---

*Built by [@forgehk](https://github.com/forgehk) — [DarkForge AI](https://darkforgeai.com)*
