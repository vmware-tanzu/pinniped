# Deploying `local-user-authenticator`

## What is `local-user-authenticator`?

The `local-user-authenticator` app is an identity provider used for integration testing and demos.
If you would like to demo Pinniped, but you don't have a compatible identity provider handy,
you can use Pinniped's `local-user-authenticator` identity provider. Note that this is not recommended for
production use.

The `local-user-authenticator` is a Kubernetes Deployment which runs a webhook server that implements the Kubernetes
[Webhook Token Authentication interface](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication).

User accounts can be created and edited dynamically using `kubectl` commands (see below).

## Tools

This example deployment uses `ytt` from [Carvel](https://carvel.dev/) to template the YAML files.
Either [install `ytt`](https://get-ytt.io/) or use the [container image from Dockerhub](https://hub.docker.com/r/k14s/image/tags).

As well, this demo requires a tool capable of generating a `bcrypt` hash in order to interact with
the webhook. The example below uses `htpasswd`, which is installed on most macOS systems, and can be
installed on some Linux systems via the `apache2-utils` package (e.g., `apt-get install
apache2-utils`).

## Procedure

1. The configuration options are in [values.yml](values.yaml). Fill in the values in that file, or override those values
   using `ytt` command-line options in the command below.
2. In a terminal, cd to this `deploy-local-user-authenticator` directory
3. To generate the final YAML files, run: `ytt --file .`
4. Deploy the generated YAML using your preferred deployment tool, such as `kubectl` or [`kapp`](https://get-kapp.io/).
   For example: `ytt --file . | kapp deploy --yes --app local-user-authenticator --diff-changes --file -`

## Configuring After Installing

### Create Users

Use `kubectl` to create, edit, and delete user accounts by creating a `Secret` for each user account in the same
namespace where `local-user-authenticator` is deployed.  The name of the `Secret` resource is the username.
Store the user's group membership and `bcrypt` encrypted password as the contents of the `Secret`.
For example, to create a user named `ryan` with the password `password123`
who belongs to the groups `group1` and `group2`, use:

```bash
kubectl create secret generic ryan \
  --namespace local-user-authenticator \
  --from-literal=groups=group1,group2 \
  --from-literal=passwordHash=$(htpasswd -nbBC 10 x password123 | sed -e "s/^x://")
```

### Get the `local-user-authenticator` App's Auto-Generated Certificate Authority Bundle

Fetch the auto-generated CA bundle for the `local-user-authenticator`'s HTTP TLS endpoint.

```bash
kubectl get secret api-serving-cert --namespace local-user-authenticator \
  -o jsonpath={.data.caCertificate} \
  | base64 -d \
  | tee /tmp/local-user-authenticator-ca
```

### Configuring Pinniped to Use `local-user-authenticator` as an Identity Provider

When installing Pinniped on the same cluster, configure `local-user-authenticator` as an Identity Provider for Pinniped
using the webhook URL `https://local-user-authenticator.local-user-authenticator.svc/authenticate`
along with the CA bundle fetched by the above command.

### Optional: Manually Test the Webhook Endpoint

  1. Start a pod from which you can curl the endpoint from inside the cluster.

      ```bash
      kubectl run curlpod --image=curlimages/curl --command -- /bin/sh -c "while true; do echo hi; sleep 120; done"
      ```

  1. Copy the CA bundle that was fetched above onto the new pod.

      ```bash
      kubectl cp /tmp/local-user-authenticator-ca curlpod:/tmp/local-user-authenticator-ca
      ```

  1. Run a `curl` command to try to authenticate as the user created above.

      ```bash
      kubectl -it exec curlpod -- curl https://local-user-authenticator.local-user-authenticator.svc/authenticate \
        --cacert /tmp/local-user-authenticator-ca \
        -H 'Content-Type: application/json' -H 'Accept: application/json' -d '
      {
        "apiVersion": "authentication.k8s.io/v1beta1",
        "kind": "TokenReview",
        "spec": {
          "token": "ryan:password123"
        }
      }'
      ```

      When authentication is successful the above command should return some JSON similar to the following.
      Note that the value of `authenticated` is `true` to indicate a successful authentication.

      ```json
      {"apiVersion":"authentication.k8s.io/v1beta1","kind":"TokenReview","status":{"authenticated":true,"user":{"username":"ryan","uid":"19c433ec-8f58-44ca-9ef0-2d1081ccb876","groups":["group1","group2"]}}}
      ```

      Trying the above `curl` command again with the wrong username or password in the body of the request
      should result in a JSON response which indicates that the authentication failed.

      ```json
      {"apiVersion":"authentication.k8s.io/v1beta1","kind":"TokenReview","status":{"authenticated":false}}
      ```

  1. Remove the curl pod.

      ```bash
      kubectl delete pod curlpod
      ```
