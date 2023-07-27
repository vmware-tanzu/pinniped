# ldapsearch.sh

Translate your `LDAPIdentityProvider` into `ldapsearch` queries for debugging purposes.

Usage

```shell
kubectl get ldapidentityprovider <name> \
  --namespace=<namespace> \
  --output=yaml | ./hack/ldapsearch/ldapsearch.sh
```

Add `--debug` for some additional output.

```shell
kubectl get ldapidentityprovider <name> \
  --namespace=<namespace> \
  --output=yaml | ./hack/ldapsearch/ldapsearch.sh --debug
```
