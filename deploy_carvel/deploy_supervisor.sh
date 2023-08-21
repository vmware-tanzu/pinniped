#!/bin/bash

# need to maintain this if used.
# but there must be a way to get ytt to read a directory of files.
#RENDERED_OUTPUT_FILES=$(
#ytt \
#  --file supervisor/config/helpers.lib.yaml \
#  --file supervisor/config/config.supervisor.pinniped.dev_federationdomains.yaml \
#  --file supervisor/config/config.supervisor.pinniped.dev_oidcclients.yaml \
#  --file supervisor/config/idp.supervisor.pinniped.dev_activedirectoryidentityproviders.yaml \
#  --file supervisor/config/idp.supervisor.pinniped.dev_ldapidentityproviders.yaml \
#  --file supervisor/config/idp.supervisor.pinniped.dev_oidcidentityproviders.yaml \
#  --file supervisor/config/z0_crd_overlay.yaml \
#  --file supervisor/config/rbac.yaml \
#  --file supervisor/config/service.yaml \
#  --file supervisor/config/deployment.yaml \
#  --file supervisor/config/values.yaml \
#  --data-value app_name=pinn-super \
#  --data-value namespace=pinn-super \
#  --data-value-yaml 'custom_labels={"foo": bar}' \
#  --data-value replicas=3
#)
#
#echo "${RENDERED_OUTPUT_FILES}"

APP="pinn-super"

kapp deploy --app  "${APP}" --diff-changes --file <(ytt \
  --file supervisor/config/helpers.lib.yaml \
  --file supervisor/config/config.supervisor.pinniped.dev_federationdomains.yaml \
  --file supervisor/config/config.supervisor.pinniped.dev_oidcclients.yaml \
  --file supervisor/config/idp.supervisor.pinniped.dev_activedirectoryidentityproviders.yaml \
  --file supervisor/config/idp.supervisor.pinniped.dev_ldapidentityproviders.yaml \
  --file supervisor/config/idp.supervisor.pinniped.dev_oidcidentityproviders.yaml \
  --file supervisor/config/z0_crd_overlay.yaml \
  --file supervisor/config/rbac.yaml \
  --file supervisor/config/service.yaml \
  --file supervisor/config/deployment-HACKED.yaml \
  --file supervisor/config/values.yaml \
  --data-value app_name=pinn-super \
  --data-value namespace=pinn-super \
  --data-value-yaml 'custom_labels={"foo": bar}' \
  --data-value replicas=3)


## template the thing
#RENDER_OUTPUT_FILE=$(
#ytt \
#  --file supervisor/config/helpers.lib.yaml \
#  --file supervisor/config/deployment.yaml \
#  --file supervisor/config/service.yaml \
#  --file supervisor/config/values.yaml \
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
