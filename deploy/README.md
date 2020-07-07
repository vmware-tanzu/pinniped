# Deploying

This example deployment uses `ytt` and `kapp` from [https://k14s.io](https://k14s.io/).

1. Fill in the values in [values.yml](values.yaml)
2. In a terminal, cd to this `deploy` directory
3. Run: `ytt --file . | kapp deploy --yes --app placeholder-name --diff-changes --file -`
