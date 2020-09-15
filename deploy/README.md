# Deploying

## Connecting Pinniped to an Identity Provider

If you would like to try Pinniped, but you don't have a compatible identity provider,
you can use Pinniped's test identity provider.
See [deploy-local-user-authenticator/README.md](../deploy-local-user-authenticator/README.md)
for details.

## Tools

This example deployment uses `ytt` and `kapp` from [Carvel](https://carvel.dev/) to template the YAML files
and to deploy the app.
Either [install `ytt` and `kapp`](https://carvel.dev/) or use the [container image from Dockerhub](https://hub.docker.com/r/k14s/image/tags).

## Procedure

1. The configuration options are in [values.yml](values.yaml). Fill in the values in that file, or override those values
   using `ytt` command-line options in the command below.
2. In a terminal, cd to this `deploy` directory
3. To generate the final YAML files, run: `ytt --file .`
4. Deploy the generated YAML using your preferred deployment tool, such as `kubectl` or [`kapp`](https://get-kapp.io/).
   For example: `ytt --file . | kapp deploy --yes --app pinniped --diff-changes --file -`
