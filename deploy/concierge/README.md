# Deploying

## Connecting Pinniped to an Identity Provider

If you would like to try Pinniped, but you don't have a compatible identity provider,
you can use Pinniped's test identity provider.
See [deploy/local-user-authenticator/README.md](../../deploy/local-user-authenticator/README.md)
for details.

## Installing the Latest Version with Default Options

```bash
kubectl apply -f https://get.pinniped.dev/latest/install-pinniped-concierge.yaml
```

## Installing a Specific Version with Default Options

Choose your preferred [release](https://github.com/vmware-tanzu/pinniped/releases) version number
and use it to replace the version number in the URL below.

```bash
# Replace v0.4.1 with your preferred version in the URL below
kubectl apply -f https://get.pinniped.dev/v0.4.1/install-pinniped-concierge.yaml
```

## Installing with Custom Options

Creating your own deployment YAML file requires `ytt` from [Carvel](https://carvel.dev/) to template the YAML files
in the `deploy/concierge` directory.
Either [install `ytt`](https://get-ytt.io/) or use the [container image from Dockerhub](https://hub.docker.com/r/k14s/image/tags).

1. `git clone` this repo and `git checkout` the release version tag of the release that you would like to deploy.
1. The configuration options are in [deploy/concierge/values.yml](values.yaml).
   Fill in the values in that file, or override those values using additional `ytt` command-line options in
   the command below. Use the release version tag as the `image_tag` value.
2. In a terminal, cd to this `deploy/concierge` directory
3. To generate the final YAML files, run `ytt --file .`
4. Deploy the generated YAML using your preferred deployment tool, such as `kubectl` or [`kapp`](https://get-kapp.io/).
   For example: `ytt --file . | kapp deploy --yes --app pinniped --diff-changes --file -`
