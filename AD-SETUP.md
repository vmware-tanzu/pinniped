# Creating an Active Directory server on Google Cloud for Pinniped integration tests

This documents the steps that were taken to create our test AD server used by the integration tests.
The integration tests use LDAPS and StartTLS to connect to the AD server.

## Create a Windows Server VM and configure it as an AD Domain Controller

The steps in this section were mostly inspired by
https://cloud.google.com/architecture/deploy-an-active-directory-forest-on-compute-engine.

From your Mac, create a VPC, subnet, firewall rules, admin password, reserved static IP, and the VM itself.

On your Mac:

```shell
# Login as yourself.
gcloud auth login

# Set some variables.
project="REDACTED" # Change this to be the actual project name before running these commands.
region="us-west1"
zone="us-west1-c"
vpc_name="ad"

# Create VPC.
gcloud compute networks create ${vpc_name} \
  --project ${project} \
  --description "VPC network to deploy Active Directory" \
  --subnet-mode custom

# Create subnet.
# The google tutorial says to "enable Private Google Access so that Windows can activate without internet access."
gcloud compute networks subnets create domain-controllers \
  --project ${project} --region ${region} \
  --network ${vpc_name} \
  --range "10.0.0.0/28" \
  --enable-private-ip-google-access

# Create a firewall rule to allow RDP. Find out what your public IP address is by going to https://whatismyipaddress.com.
# Replace the X.X.X.X placeholder address shown here with your real IPv4 address.
my_ip=X.X.X.X
gcloud compute firewall-rules create allow-rdp-ingress-to-addc \
  --project ${project} \
  --direction INGRESS \
  --action allow \
  --rules tcp:3389 \
  --source-ranges "${my_ip}/32" \
  --target-tags ad-domaincontroller \
  --network ${vpc_name} \
  --priority 10000

# Allow LDAPS (port 636) from the whole internet.
gcloud compute firewall-rules create allow-ldaps-ingress-to-addc \
  --project ${project} \
  --direction INGRESS \
  --action allow \
  --rules tcp:636 \
  --source-ranges "0.0.0.0/0" \
  --target-tags ad-domaincontroller \
  --network ${vpc_name} \
  --priority 10000

# Allow LDAP (port 389) from the whole internet, to allow the integration tests to use StartTLS.
gcloud compute firewall-rules create allow-ldap-ingress-to-addc \
  --project ${project} \
  --direction INGRESS \
  --action allow \
  --rules tcp:389 \
  --source-ranges "0.0.0.0/0" \
  --target-tags ad-domaincontroller \
  --network ${vpc_name} \
  --priority 10000

# Reserve a static public IP address for the domain controller VM.
addressOfDc1=$(gcloud compute addresses create ad-domain-controller \
  --project ${project} --region ${region} \
  --format="value(address)")

# Create an admin password for the Administrator user on Windows, and save it to secrets manager.
password="$(openssl rand -hex 8)-$(openssl rand -hex 8)"
echo -n "$password" > password.tmp
gcloud secrets create active-directory-dc1-password \
  --project ${project} \
  --data-file password.tmp
rm password.tmp

# This creates a service account called ad-domaincontroller@PROJECT_NAME.iam.gserviceaccount.com
# (where PROJECT_NAME is the actual GCP project name) and sets the account name to the
# variable $dcServiceAccount.
dcServiceAccount=$(gcloud iam service-accounts create ad-domaincontroller \
  --project ${project} \
  --display-name "AD Domain Controller VM Service Account" \
  --format "value(email)")

# Allow the new service account to temporarily read the Windows admin password from secret manager.
# The following `date` command might only work on MacOS. It prints the time like this: 2024-10-23T19:20:36Z
one_hour_from_now=$(TZ=UTC date -v "+1H" +"%Y-%m-%dT%H:%M:%SZ")
gcloud secrets add-iam-policy-binding active-directory-dc1-password \
  --project ${project} \
  "--member=serviceAccount:$dcServiceAccount" \
  --role=roles/secretmanager.secretAccessor \
  --condition="title=Expires after 1h,expression=request.time < timestamp('$one_hour_from_now')"

# Optional: list all bindings to see the binding that you just created.
gcloud secrets get-iam-policy active-directory-dc1-password \
  --project ${project}

# Create a powershell startup script in a local file.
cat <<"EOF" > dc-startup.ps1
$ErrorActionPreference = "Stop"

#
# Only run the script if the VM is not a domain controller already.
#
if ((Get-CimInstance -ClassName Win32_OperatingSystem).ProductType -eq 2) {
    exit
}

#
# Read configuration from metadata.
#
Import-Module "${Env:ProgramFiles}\Google\Compute Engine\sysprep\gce_base.psm1"

Write-Host "Reading metadata..."
$ActiveDirectoryDnsDomain     = Get-MetaData -Property "attributes/ActiveDirectoryDnsDomain" -instance_only
$ActiveDirectoryNetbiosDomain = Get-MetaData -Property "attributes/ActiveDirectoryNetbiosDomain" -instance_only
$ProjectId                    = Get-MetaData -Property "project-id" -project_only
$AccessToken                  = (Get-MetaData -Property "service-accounts/default/token" | ConvertFrom-Json).access_token

#
# Read the DSRM password from secret manager.
#
Write-Host "Reading secret from secret manager..."
$Secret = (Invoke-RestMethod `
    -Headers @{
        "Metadata-Flavor" = "Google";
        "x-goog-user-project" = $ProjectId;
        "Authorization" = "Bearer $AccessToken"} `
    -Uri "https://secretmanager.googleapis.com/v1/projects/$ProjectId/secrets/active-directory-dc1-password/versions/latest:access")
$DsrmPassword = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Secret.payload.data))
$DsrmPassword = ConvertTo-SecureString -AsPlainText $DsrmPassword -force

#
# Promote.
#
Write-Host "Setting administrator password..."
Set-LocalUser -Name Administrator -Password $DsrmPassword

Write-Host "Creating a new forest $ActiveDirectoryDnsDomain ($ActiveDirectoryNetbiosDomain)..."
Install-ADDSForest `
    -DomainName $ActiveDirectoryDnsDomain `
    -DomainNetbiosName $ActiveDirectoryNetbiosDomain `
    -SafeModeAdministratorPassword $DsrmPassword `
    -DomainMode Win2008R2 `
    -ForestMode Win2008R2 `
    -InstallDns `
    -CreateDnsDelegation:$False `
    -NoRebootOnCompletion:$True `
    -Confirm:$false

#
# Configure DNS.
#
Write-Host "Configuring DNS settings..."
Get-Netadapter| Disable-NetAdapterBinding -ComponentID ms_tcpip6
Set-DnsClientServerAddress  `
    -InterfaceIndex (Get-NetAdapter -Name Ethernet).InterfaceIndex `
    -ServerAddresses 127.0.0.1

#
# Enable LSA protection.
#
New-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" `
    -Value 1 `
    -PropertyType DWord

Write-Host "Restarting to apply all settings..."
Restart-Computer
EOF

# Create a domain controller VM.
# E2 are the cheapest VMs. e2-medium has 2 vCPUs (shared with other customers) and 4 GB of memory.
# See https://cloud.google.com/compute/docs/general-purpose-machines#e2-shared-core.
# When we originally set up this VM, we actually started it as n2-standard-2 and after we
# finished setting up everything as shown in this guide, then we stopped the VM and changed its
# type to e2-medium and started the VM again. Maybe it would work fine to create it as
# e2-medium from the beginning, but note that we didn't actually test that.
gcloud compute instances create active-directory-dc1  \
  --project ${project} \
  --zone ${zone} \
  --image-family windows-2022 \
  --image-project windows-cloud \
  --machine-type e2-medium \
  --tags ad-domaincontroller \
  --metadata "ActiveDirectoryDnsDomain=activedirectory.test.pinniped.dev,ActiveDirectoryNetbiosDomain=pinniped-ad,sysprep-specialize-script-ps1=Install-WindowsFeature AD-Domain-Services -IncludeManagementTools; Install-WindowsFeature DNS,disable-account-manager=true" \
  --metadata-from-file windows-startup-script-ps1=dc-startup.ps1 \
  --address ${addressOfDc1} \
  --subnet=domain-controllers \
  --service-account "$dcServiceAccount" \
  --scopes cloud-platform \
  --shielded-integrity-monitoring \
  --shielded-secure-boot \
  --shielded-vtpm

# Monitor the initialization process of the first domain controller by viewing its serial port output.
# It should install the sysprep stuff, reboot, run our startup script, and then reboot again.
gcloud compute instances tail-serial-port-output active-directory-dc1 \
  --project ${project} \
  --zone ${zone}
# Use CTRL-C to cancel tailing the output.
```

## Update DNS

Update the Cloud DNS entry for `activedirectory.test.pinniped.dev.` to be an "A" record pointing to the
public static IP of the VM. This is easier to do in the Cloud DNS UI in your browser.
It would take many gcloud CLI commands to accomplish the same task.

## Configure test users and groups

Make sure you have an RDP client installed. On a Mac, you can install RDP from the App Store.
It was recently renamed "Windows App".

Note: To copy/paste in the RDP client, you may need to use CTRL-C/CTRL-V if CMD-C/CMD-V don't work.

RDP into the Windows VM. To connect, use `activedirectory.test.pinniped.dev` as the name of the server,
the username `Administrator`, and the password from the `active-directory-dc1-password` entry in Secrets Manager.
You can ignore the RDP certificate error.

In your RDP session, open Powershell. Then run the following commands to add some users and groups,
change the password policy, and grant some permissions.

Before running the commands, replace the redacted passwords as follows:
- The value for `REDACTED_BIND_USER_PASSWORD` can be found at `aws-ad-bind-account-password` in the `concourse-secrets` secret
- The value for `REDACTED_PINNY_USER_PASSWORD` can be found at `aws-ad-user-password` in the `concourse-secrets` secret
- The value for `REDACTED_DEACTIVATED_USER_PASSWORD` can be found at `aws-ad-deactivated-user-password` in the `concourse-secrets` secret

```shell
New-ADOrganizationalUnit -Name "pinniped-ad" `
  -ProtectedFromAccidentalDeletion $false

New-ADOrganizationalUnit -Name "Users" `
  -Path "OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev" `
  -ProtectedFromAccidentalDeletion $false

New-ADOrganizationalUnit -Name "test-users" `
  -Path "OU=Users,OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev" `
  -Description "integration tests will create and delete ephemeral users here" `
  -ProtectedFromAccidentalDeletion $false

# Print all OUs to validate that they were created.
Get-ADOrganizationalUnit -Filter *

New-ADUser -Name "Bind User" -SamAccountName "bind-user" -GivenName "Bind" -Surname "User" -DisplayName "Bind User" `
  -UserPrincipalName "bind-user@activedirectory.test.pinniped.dev" `
  -Path "OU=Users,OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev" `
  -AccountPassword (ConvertTo-SecureString "REDACTED_BIND_USER_PASSWORD" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

# Note that the value of EmailAddress is not a real email address, but that's okay.
New-ADUser -Name "Pinny Seal" -SamAccountName "pinny" -GivenName "Pinny" -Surname "Seal" -DisplayName "Pinny Seal" `
  -UserPrincipalName "pinny@activedirectory.test.pinniped.dev" `
  -Path "OU=Users,OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev" `
  -EmailAddress "tanzu-user-authentication@groups.vmware.com" `
  -AccountPassword (ConvertTo-SecureString "REDACTED_PINNY_USER_PASSWORD" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

New-ADUser -Name "Deactivated User" -SamAccountName "deactivated-user" -GivenName "Deactivated" -Surname "User" -DisplayName "Deactivated User" `
  -UserPrincipalName "deactivated-user@activedirectory.test.pinniped.dev" `
  -Path "OU=Users,OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev" `
  -AccountPassword (ConvertTo-SecureString "REDACTED_DEACTIVATED_USER_PASSWORD" -AsPlainText -Force) `
  -Enabled $false -PasswordNeverExpires $true

# Take note of the pinny account's ObjectGUID. You will need to edit the concourse-secrets secret later to update this GUID value.
# This value should look something like "288188dd-ab76-4f61-b6e4-c72e081502c5".
Get-ADUser pinny -Properties * | Select SamaccountName,ObjectGUID

# Print all users to validate that they were created.
Get-ADUser -Filter *

New-ADGroup -Name "Marine Mammals" -SamAccountName "Marine Mammals" -DisplayName "Marine Mammals" `
  -GroupCategory Security -GroupScope Global `
  -Path "OU=Users,OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev"

Add-ADGroupMember -Identity "Marine Mammals" -Members "pinny"

New-ADGroup -Name "Mammals" -SamAccountName "Mammals" -DisplayName "Mammals" `
  -GroupCategory Security -GroupScope Global `
  -Path "OU=Users,OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev"

Add-ADGroupMember -Identity "Mammals" -Members "Marine Mammals"

# Change the default password policy. There are some integration tests that rely on this.
# This is the equivalent of doing this in the Windows "Active Directory Administrative Center" UI:
# check "enforce account lockout policy", give it 20 failed attempts and a 15-minute reset, then
# uncheck "enforce minimum password age" so we can change the password immediately upon creating a user.
Set-ADDefaultDomainPasswordPolicy -Identity "activedirectory.test.pinniped.dev" `
  -LockoutThreshold 20 -LockoutDuration "00:15:00" -LockoutObservationWindow "00:15:00" `
  -MinPasswordAge 0

# Print the policy to validate that it was updated.
Get-ADDefaultDomainPasswordPolicy

# We need to allow the bind-user to create/delete/edit users and groups within the test-users OU, because several
# integration tests want to crate/delete/edit ephemeral test users and groups.
# These access control steps were inspired by https://the-itguy.de/delegate-access-in-active-directory-with-powershell/.
# This is intended to be the equivalent of using the UI to assign permissions like this: right click on "test-users",
# select Delegate Control, select "bind-user" as the user, select "create, delete and manage user accounts" and
# "reset user passwords" as the tasks to delegate.
function New-ADDGuidMap
{
    $rootdse = Get-ADRootDSE
    $guidmap = @{ }
    $GuidMapParams = @{
        SearchBase = ($rootdse.SchemaNamingContext)
        LDAPFilter = "(schemaidguid=*)"
        Properties = ("lDAPDisplayName", "schemaIDGUID")
    }
    Get-ADObject @GuidMapParams | ForEach-Object { $guidmap[$_.lDAPDisplayName] = [System.GUID]$_.schemaIDGUID }
    return $guidmap
}
$GuidMap = New-ADDGuidMap
$BindUserSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADUser "bind-user").SID
$acl = Get-Acl -Path "AD:OU=test-users,OU=Users,OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev"
$ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $BindUserSID, "GenericAll", "Allow", "Descendents", $GuidMap["user"]
$ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $BindUserSID, "CreateChild, DeleteChild", "Allow", $GuidMap["user"], "All"
$ace3 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $BindUserSID, "GenericAll", "Allow", "Descendents", $GuidMap["group"]
$ace4 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $BindUserSID, "CreateChild, DeleteChild", "Allow", $GuidMap["group"], "All"
$acl.AddAccessRule($ace1)
$acl.AddAccessRule($ace2)
$acl.AddAccessRule($ace3)
$acl.AddAccessRule($ace4)
Set-Acl -Path "AD:OU=test-users,OU=Users,OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev" -AclObject $acl

# Print the access control rules that were just applied.
$acl = Get-Acl -Path "AD:OU=test-users,OU=Users,OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev"
$acl.Access |  Where-Object { $_.IdentityReference -eq "pinniped-ad\bind-user" }
```

If you would like to see these OUs, users, and groups in the UI, you can open the "Active Directory Users and Computers"
app in your RDP session.

## Configure a CA and a serving certificate for LDAPS

Now we need to create and configure a TLS serving certificate for LDAPS.

The certificate needs to include two hostnames. One of the hostnames is the name that the AD server
thinks is its own hostname (`active-directory-dc1.activedirectory.test.pinniped.dev`).
This is how the AD server will decide to use this cert for the LDAPS port.
The other hostname is the one that clients will use when making connections from the outside
(`activedirectory.test.pinniped.dev`) so they can validate the server certificate.

The steps here were inspired by https://gist.github.com/magnetikonline/0ccdabfec58eb1929c997d22e7341e45.

On your mac:

```shell
# On your Mac: Create a self-signed CA public/private keypair.
openssl req -x509 -newkey rsa:4096 \
  -keyout ad-ca.key -out ad-ca.crt \
  -sha256 -days 36500 -nodes \
  -subj "/C=US/ST=California/L=San Francisco/O=Pinniped/OU=Pinniped CI/CN=Pinniped AD CA"

# Copy the public key to your clipboard.
cat ad-ca.crt| pbcopy
```

In Powershell terminal:

```shell
# In your Windows RDP session's Powershell terminal, put the content of the clipboard into a file.
# Note that if you copy/paste this command to your RDP session, then you need to pbcopy the public
# key again before you hit return for this command.
Get-Clipboard | Out-File -FilePath "C:\users\administrator\desktop\ca.crt"

# In Powershell terminal, check that the file exists and looks correct.
type "C:\users\administrator\desktop\ca.crt"

# Import root certificate into trusted store of domain controller in your Powershell terminal:
Import-Certificate -FilePath "C:\users\administrator\desktop\ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

If you want to validate that this was imported, open the UI tool called "Manage computer certificates"
and look in the folder called "Trusted Root Certification Authorities\Certificates".
If the UI was already open, click the refresh button.

Copy the following file contents to your clipboard:

```shell
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=activedirectory.test.pinniped.dev"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1 ; Server Authentication

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "DNS=activedirectory.test.pinniped.dev"
_continue_ = "DNS=active-directory-dc1.activedirectory.test.pinniped.dev"
```

In Powershell terminal:

```shell
# In your Windows RDP session's Powershell terminal, put the content of the clipboard into a file.
# Note that if you copy/paste this command to your RDP session, then you need to copy the file contents
# from above again before you hit return for this command.
Get-Clipboard | Out-File -FilePath "C:\users\administrator\desktop\request.inf"

# In Powershell terminal, check that the file exists and looks correct.
type "C:\users\administrator\desktop\request.inf"

# Create a CSR. This command will also generate a private key for the AD server and save it.
certreq -new "C:\users\administrator\desktop\request.inf" "C:\users\administrator\desktop\client.csr"

# Show the CSR.
type "C:\users\administrator\desktop\client.csr"

# Copy the content of this file to your clipboard.
Get-Content "C:\users\administrator\desktop\client.csr" | Set-Clipboard
```

On your mac:

```shell
# On your Mac, use the CA to issue a serving cert based on the CSR.
pbpaste > client.csr

cat <<EOF > v3ext.txt
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
subjectAltName = @alt_names
[alt_names]
  DNS.1 = activedirectory.test.pinniped.dev
  DNS.2 = active-directory-dc1.activedirectory.test.pinniped.dev
EOF

# Create a cert from the CSR signed by the CA.
openssl x509 \
   -req -days 36500 \
   -in client.csr -CA ad-ca.crt -CAkey ad-ca.key -extfile v3ext.txt \
   -set_serial 01 -out client.crt

# Inspect the generated certificate.
# Ensure the following X509v3 extensions are all present:
#   Key Usage: Digital Signature, Key Encipherment
#   Extended Key Usage: TLS Web Server Authentication
#   Subject Key Identifier
#   Subject Alternative Name with 2 DNS hostnames
#   Authority Key Identifier
openssl x509 -in client.crt -text

# Copy the generated cert.
cat client.crt | pbcopy
```

In Powershell terminal:

```shell
# In your Windows RDP session's Powershell terminal, put the content of the clipboard into a file.
# Note that if you copy/paste this command to your RDP session, then you need to pbcopy the file contents
# from above again before you hit return for this command.
Get-Clipboard | Out-File -FilePath "C:\users\administrator\desktop\client.crt"

# In Powershell terminal, check that the file exists and looks correct.
type "C:\users\administrator\desktop\client.crt"

# Add the serving certificate to Windows. This will also automatically associate it to the private key that you
# generated with the previous usage of certreq.
certreq -accept "C:\users\administrator\desktop\client.crt"

# If you want to validate that this was imported, open the UI tool called "Manage computer certificates"
# and look in the folder called "Personal\Certificates". If the UI was already open, click the refresh button.
# Double click on the cert. Ensure that it says, "you have a private key that corresponds to this certificate".
# Next, we need to reboot the VM for the cert to get picked up and used for serving incoming LDAPS connections.
# After showing you a warning dialog box, this should terminate your RDP session and stop the VM.
shutdown /s
```

Wait for the VM to stop, then start the VM again from your Mac:

```shell
gcloud compute instances start active-directory-dc1 --project ${project} --zone ${zone}
```

Wait for the VM to finish booting. Then we can confirm that LDAPS is working. On your Mac:

```shell
# Check that serving cert is being returned on the LDAPS port. This command should show the cert chain.
# It should also verify the server cert using our CA. The output should include "Verify return code: 0 (ok)".
openssl s_client -connect activedirectory.test.pinniped.dev:636 -showcerts -CAfile ad-ca.crt < /dev/null

# Unfortunately, the ldapsearch command that comes pre-installed on MacOS does not seem to respect
# the LDAPTLS_CACERT env variable. So it will not be able to validate the server certificates.
# As a workaround, we can use docker to run ldapsearch commands in a linux container.

# Test the regular LDAP port by issuing a query on your Mac. The -ZZ option asks it to use StartTLS.
# This should list all users. Replace REDACTED_BIND_USER_PASSWORD with the real password.
docker run -v "$(pwd):/certs" -e LDAPTLS_CACERT="/certs/ad-ca.crt" --rm -it bitnami/openldap \
  ldapsearch -d8 -v -x -ZZ -H 'ldap://activedirectory.test.pinniped.dev' \
  -D 'CN=Bind User,OU=Users,OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev' \
  -w 'REDACTED_BIND_USER_PASSWORD' \
  -b 'OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev' \
  -s sub \
  '(objectClass=user)' '*'

# Test the LDAPS port by issuing a query on your Mac. This should list all users.
# Replace REDACTED_BIND_USER_PASSWORD with the real password.
docker run -v "$(pwd):/certs" -e LDAPTLS_CACERT="/certs/ad-ca.crt" --rm -it bitnami/openldap \
  ldapsearch -d8 -v -x -H 'ldaps://activedirectory.test.pinniped.dev' \
  -D 'CN=Bind User,OU=Users,OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev' \
  -w 'REDACTED_BIND_USER_PASSWORD' \
  -b 'OU=pinniped-ad,DC=activedirectory,DC=test,DC=pinniped,DC=dev' \
  -s sub \
  '(objectClass=user)' '*'
```

## Update the `concourse-secrets` secret in GCP Secrets Manager

On your Mac:

```shell
# Copy the CA's public cert.
cat ad-ca.crt | base64 | pbcopy

# cd to your local clone of the `ci` branch of the pinniped repo
cd pinniped-ci-branch

# Edit the secret.
./hack/edit-gcloud-secret.sh concourse-secret
# This opens vim to edit the secret.
# Paste the cert as the value for `aws-ad-ca-data`.
# Also edit the the value of `aws-ad-user-unique-id-attribute-value`. The value should be the ObjectGUID of the pinny
# user that you created in the steps above.
# Save your changes, exit vim, and when prompted say that you want to save this as the new version of concourse-secrets.
```

## Confirm that Active Directory integration tests can pass

Use these commands run all the Active Directory integration tests on your Mac.
The `-run` filter is based on the tests as they existed at the time of writing this doc.
You can find AD tests by searching for `SkipTestWhenActiveDirectoryIsUnavailable`.

On your Mac:

```shell
# Login so we can read the secrets from GCP Secret Manager.
gcloud auth login

# cd to your local git clone
cd pinniped

# Compile and install onto a local kind cluster.
./hack/prepare-for-integration-tests.sh -c --get-active-directory-vars "../pinniped-ci-branch/hack/get-aws-ad-env-vars.sh"

# Run all the tests that depend on AD.
source /tmp/integration-test-env && go test -v -race -count 1 -timeout 0 ./test/integration \
  -run "/TestSupervisorLogin_Browser/active_directory|/TestE2EFullIntegration_Browser/with_Supervisor_ActiveDirectory|/TestActiveDirectoryIDPPhaseAndConditions_Parallel|/TestSupervisorWarnings_Browser/Active_Directory"
```

## Cleanup

On your Mac:

```shell
# Remove all bindings for the service account from the secret.
# The binding was only needed during the first boot of the VM.
gcloud secrets remove-iam-policy-binding active-directory-dc1-password \
  --project ${project} \
  --member "serviceAccount:${dcServiceAccount}" --role roles/secretmanager.secretAccessor \
  --all

# Remove the firewall rule which allows incoming RDP connections.
# If you need to RDP to this AD VM in the future, then you will need to create
# a new firewall rule to allow it.
gcloud compute firewall-rules delete allow-rdp-ingress-to-addc \
  --project ${project} \
  --quiet

# Remove all temp files. It's okay to remove the private key for our CA because we
# created certs that are good for 100 years, as long as you have already added the
# public cert to the concourse-secrets secret. If we need to create a new AD VM, we
# can also create a new CA.
rm ad-ca.crt ad-ca.key client.crt client.csr v3ext.txt
```
