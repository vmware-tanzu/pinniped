# Deploying

## Tools

This example deployment uses `ytt` from [Carvel](https://carvel.dev/) to template the YAML files.
Either [install `ytt`](https://get-ytt.io/) or use the [container image from Dockerhub](https://hub.docker.com/r/k14s/image/tags).

## Procedure

1. The configuration options are in [values.yml](values.yaml). Fill in the values in that file, or override those values
   using `ytt` command-line options in the command below.
2. In a terminal, cd to this `deploy` directory
3. To generate the final YAML files, run: `ytt --file .`
4. Deploy the generated YAML using your preferred deployment tool, such as `kubectl` or [`kapp`](https://get-kapp.io/).
   For example: `ytt --file . | kapp deploy --yes --app pinniped --diff-changes --file -`
