# CamControl

Local CLI tooling for camera discovery, control, and protocol experimentation.

## Secrets

Secrets are no longer meant to be stored in `config.yaml`.

Resolution order:

1. CLI argument where supported
2. Environment variable
3. OS keychain via `keyring`
4. Legacy value in `config.yaml` as a fallback
5. Interactive prompt

Environment variable names use this pattern:

- `CAMCONTROL_ARLO_AUTH_TOKEN`
- `CAMCONTROL_WYZE_PASSWORD`
- `CAMCONTROL_WYZE_KEY_ID`
- `CAMCONTROL_WYZE_API_KEY`

Non-secret settings should live in `config.yaml`. Use [config.example.yaml](/Users/anthonygrant/palmettodevs/cam-control/config.example.yaml) as the template.

## One-Time Cleanup

After rotating credentials:

- Keep `config.yaml` local and untracked
- Remove any generated token files
- Remove any generated MITM CA material

If `.ca/` was created by a privileged run, remove it with:

```bash
sudo rm -rf .ca
```
