#!/bin/bash


APP="pinn-conci"

kapp deploy --app "${APP}" --diff-changes --file <(ytt \
  --file concierge/config/authentication.concierge.pinniped.dev_jwtauthenticators.yaml
  --file concierge/config/authentication.concierge.pinniped.dev_webhookauthenticcators.yaml
  --file concierge/config/config.concierge.pinniped.dev_credential_issuers.yaml
  --file concierge/config/deployment-HACKED.yaml \
  --file concierge/config/helpers.lib.yaml \
  --file concierge/config/rbac.yaml \
  --file concierge/config/z0_crd_overlay.yaml \
  --file concierge/config/values.yaml \
  --data-value app_name=pinn-conci \
  --data-value namespace=pinn-conci \
  --data-value-yaml 'custom_labels={"foo": bar}' \
  --data-value replicas=3)


## template the thing
#RENDER_OUTPUT_FILE=$(
#ytt \
#  --file concierge/config/helpers.lib.yaml \
#  --file concierge/config/deployment.yaml \
#  --file concierge/config/service.yaml \
#  --file concierge/config/values.yaml \
#  --data-value app_name=pinn-super \
#  --data-value namespace=pinn-super \
#  --data-value-yaml 'custom_labels={"foo": bar}' \
#  --data-value replicas=3
#)
#
## view it
#echo "$RENDER_OUTPUT_FILE"
#
## give it to kapp
#kapp deploy \
#  --app pinn-super \
#  --diff-changes \
#  --file <( "${RENDER_OUTPUT_FILE}" )
