# Deploying the Pinniped Supervisor

## What is the Pinniped Supervisor?

The Pinniped Supervisor app is a component of the Pinniped OIDC and Cluster Federation solutions.
It can be deployed when those features are needed.

## Installing the Latest Version with Default Options

```bash
kubectl apply -f https://github.com/vmware-tanzu/pinniped/releases/latest/download/install-supervisor.yaml
```

## Installing an Older Version with Default Options

Choose your preferred [release](https://github.com/vmware-tanzu/pinniped/releases) version number
and use it to replace the version number in the URL below.

```bash
# Replace v0.3.0 with your preferred version in the URL below
kubectl apply -f https://github.com/vmware-tanzu/pinniped/releases/download/v0.3.0/install-supervisor.yaml
```

## Installing with Custom Options

Creating your own deployment YAML file requires `ytt` from [Carvel](https://carvel.dev/) to template the YAML files
in the `deploy/supervisor` directory.
Either [install `ytt`](https://get-ytt.io/) or use the [container image from Dockerhub](https://hub.docker.com/r/k14s/image/tags).

1. `git clone` this repo and `git checkout` the release version tag of the release that you would like to deploy.
1. The configuration options are in [deploy/supervisor/values.yml](values.yaml).
   Fill in the values in that file, or override those values using additional `ytt` command-line options in
   the command below. Use the release version tag as the `image_tag` value.
2. In a terminal, cd to this `deploy/supervisor` directory
3. To generate the final YAML files, run `ytt --file .`
4. Deploy the generated YAML using your preferred deployment tool, such as `kubectl` or [`kapp`](https://get-kapp.io/).
   For example: `ytt --file . | kapp deploy --yes --app pinniped-supervisor --diff-changes --file -`

## Configuring After Installing

### Exposing the Supervisor App as a Service

Create a Service to make the app available outside of the cluster. If you installed using `ytt` then you can use
the related `service_*_port` options from [deploy/supervisor/values.yml](values.yaml) to create a Service, instead
of creating them manually as shown below.

#### Using a LoadBalancer Service

Using a LoadBalancer Service is probably the easiest way to expose the Supervisor app, if your cluster supports
LoadBalancer Services. For example:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: pinniped-supervisor-loadbalancer
  namespace: pinniped-supervisor
  labels:
    app: pinniped-supervisor
spec:
  type: LoadBalancer
  selector:
    app: pinniped-supervisor
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
```

#### Using a NodePort Service

A NodePort Service exposes the app as a port on the nodes of the cluster.
This is convenient for use with kind clusters, because kind can
[expose node ports as localhost ports on the host machine](https://kind.sigs.k8s.io/docs/user/configuration/#extra-port-mappings).

For example:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: pinniped-supervisor-nodeport
  namespace: pinniped-supervisor
  labels:
    app: pinniped-supervisor
spec:
  type: NodePort
  selector:
    app: pinniped-supervisor
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
    nodePort: 31234
```

### Configuring the Supervisor to Act as an OIDC Provider

The Supervisor can be configured as an OIDC provider by creating `OIDCProviderConfig` resources
in the same namespace where the Supervisor app was installed. For example:

```yaml
apiVersion: config.pinniped.dev/v1alpha1
kind: OIDCProviderConfig
metadata:
  name: my-provider
  namespace: pinniped-supervisor
spec:
  issuer: https://my-issuer.eaxmple.com
```
