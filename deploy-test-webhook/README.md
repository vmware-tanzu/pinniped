# Deploying `test-webhook`

## What is `test-webhook`?

The `test-webhook` app is an identity provider used for integration testing and demos.
If you would like to demo Pinniped, but you don't have a compatible identity provider handy,
you can use Pinniped's `test-webhook` identity provider. Note that this is not recommended for
production use.

The `test-webhook` is a Kubernetes Deployment which runs a webhook server that implements the Kubernetes
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
2. In a terminal, cd to this `deploy-test-webhook` directory
3. To generate the final YAML files, run: `ytt --file .`
4. Deploy the generated YAML using your preferred deployment tool, such as `kubectl` or [`kapp`](https://get-kapp.io/).
   For example: `ytt --file . | kapp deploy --yes --app test-webhook --diff-changes --file -`

## Configuring After Installing

### Create Users

Use `kubectl` to create, edit, and delete user accounts by creating a `Secret` for each user account in the same
namespace where `test-webhook` is deployed.  The name of the `Secret` resource is the username.
Store the user's group membership and `bcrypt` encrypted password as the contents of the `Secret`.
For example, to create a user named `ryan` with the password `password123`
who belongs to the groups `group1` and `group2`, use:

```bash
kubectl create secret generic ryan \
  --namespace test-webhook \
  --from-literal=groups=group1,group2 \
  --from-literal=passwordHash=$(htpasswd -nbBC 10 x password123 | sed -e "s/^x://")
```

### Get the `test-webhook` App's Auto-Generated Certificate Authority Bundle

Fetch the auto-generated CA bundle for the `test-webhook`'s HTTP TLS endpoint.

```bash
kubectl get secret api-serving-cert --namespace test-webhook \
  -o jsonpath={.data.caCertificate} \
  | base64 -d \
  | tee /tmp/test-webhook-ca
```

### Configuring Pinniped to Use `test-webhook` as an Identity Provider

When installing Pinniped on the same cluster, configure `test-webhook` as an Identity Provider for Pinniped
using the webhook URL `https://test-webhook.test-webhook.svc/authenticate`
along with the CA bundle fetched by the above command.

### Optional: Manually Test the Webhook Endpoint

  1. Start a pod from which you can curl the endpoint from inside the cluster.

      ```bash
      kubectl run curlpod --image=curlimages/curl --command -- /bin/sh -c "while true; do echo hi; sleep 120; done"
      ```

  1. Copy the CA bundle that was fetched above onto the new pod.

      ```bash
      kubectl cp /tmp/test-webhook-ca curlpod:/tmp/test-webhook-ca
      ```

  1. Run a `curl` command to try to authenticate as the user created above.

      ```bash
      kubectl -it exec curlpod -- curl https://test-webhook.test-webhook.svc/authenticate \
        --cacert /tmp/test-webhook-ca \
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
