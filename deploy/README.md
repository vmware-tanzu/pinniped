# Deploying

This example deployment uses `ytt` and `kapp` from [k14s.io](https://k14s.io/).

If you would rather not install these command-line tools directly on your machine,
you can use alternatively get the most recent version of this container image: 
https://hub.docker.com/r/k14s/image/tags

1. Fill in the values in [values.yml](values.yaml)
2. In a terminal, cd to this `deploy` directory
3. Run: `ytt --file . | kapp deploy --yes --app placeholder-name --diff-changes --file -`
