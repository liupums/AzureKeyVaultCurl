# Azure DevOps, Build Agent VMSS
This template creates Linux VM as the build agent for Azure DevOps, see the [referenced tutorial](https://github.com/matt-FFFFFF/terraform-azuredevops-vmss-agent)
The Microsoft doc is available [here](https://docs.microsoft.com/en-us/azure/devops/pipelines/agents/scale-set-agents?view=azure-devops)

# How to build and deploy
- `az bicep build -f buildagent.main.bicep`
- `az deployment sub create --location westus3 --template-file buildagent.main.bicep --parameters @buildagent.parameters.json`

# Note
- The [cloud-init.txt](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/tutorial-automate-vm-deployment) is used to install required packages for building 
- A maunal step is needed to convet the cloud-init.txt to base64 string and then add to main.parameters.json  
`cat cloud-init.txt | base64` 

# Full transcript of testing
  ```
  root@linuxbuildagent:/var/lib/waagent/custom-script/download# dir
0  1  3  4  5
root@linuxbuildagent:/var/lib/waagent/custom-script/download# cd 5
root@linuxbuildagent:/var/lib/waagent/custom-script/download/5# dir
startbuild.sh  stderr  stdout
root@linuxbuildagent:/var/lib/waagent/custom-script/download/5# cat stdout
Reading package lists...
Building dependency tree...
Reading state information...
build-essential is already the newest version (12.4ubuntu1).
cmake is already the newest version (3.10.2-1ubuntu2.18.04.2).
libcurl4-openssl-dev is already the newest version (7.58.0-2ubuntu3.16).
libjson-c-dev is already the newest version (0.12.1-1.3ubuntu0.3).
libssl-dev is already the newest version (1.1.1-1ubuntu2.1~18.04.13).
nginx is already the newest version (1.14.0-0ubuntu1.9).
The following package was automatically installed and is no longer required:
  linux-headers-4.15.0-162
Use 'sudo apt autoremove' to remove it.
0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.
-- Configuring done
-- Generating done
-- Build files have been written to: /opt/AkvOpensslEngine/src/build
[ 90%] Built target eakv_obj
[100%] Built target eakv
ENGINESDIR: "/usr/lib/x86_64-linux-gnu/engines-1.1"
(e_akv) AKV/HSM engine
     [ available ]
     debug: debug (0=OFF, else=ON)
          (input flags): NUMERIC
Hit:1 http://azure.archive.ubuntu.com/ubuntu bionic InRelease
Hit:2 https://packages.microsoft.com/repos/azure-cli bionic InRelease
Hit:3 http://azure.archive.ubuntu.com/ubuntu bionic-updates InRelease
Hit:4 http://azure.archive.ubuntu.com/ubuntu bionic-backports InRelease
Hit:5 http://security.ubuntu.com/ubuntu bionic-security InRelease
Reading package lists...
Reading package lists...
Building dependency tree...
Reading state information...
lsb-release is already the newest version (9.20170808ubuntu1).
curl is already the newest version (7.58.0-2ubuntu3.16).
gnupg is already the newest version (2.2.4-1ubuntu1.4).
apt-transport-https is already the newest version (1.6.14).
The following package was automatically installed and is no longer required:
  linux-headers-4.15.0-162
Use 'apt autoremove' to remove it.
0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.
Hit:1 http://azure.archive.ubuntu.com/ubuntu bionic InRelease
Hit:2 http://azure.archive.ubuntu.com/ubuntu bionic-updates InRelease
Hit:3 http://azure.archive.ubuntu.com/ubuntu bionic-backports InRelease
Hit:4 https://packages.microsoft.com/repos/azure-cli bionic InRelease
Hit:5 http://security.ubuntu.com/ubuntu bionic-security InRelease
Reading package lists...
Reading package lists...
Building dependency tree...
Reading state information...
azure-cli is already the newest version (2.30.0-1~bionic).
The following package was automatically installed and is no longer required:
  linux-headers-4.15.0-162
Use 'apt autoremove' to remove it.
0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.
[
  {
    "environmentName": "AzureCloud",
    "homeTenantId": "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "id": "ce2c696e-9825-44f7-9a68-f34d153e64ba",
    "isDefault": true,
    "managedByTenants": [],
    "name": "uswestcsu_internal",
    "state": "Enabled",
    "tenantId": "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "user": {
      "assignedIdentityInfo": "MSI",
      "name": "systemAssignedIdentity",
      "type": "servicePrincipal"
    }
  }
]
{
  "attributes": {
    "created": "2021-11-14T07:32:39+00:00",
    "enabled": true,
    "expires": null,
    "exportable": null,
    "notBefore": null,
    "recoverableDays": 7,
    "recoveryLevel": "CustomizedRecoverable",
    "updated": "2021-11-14T07:32:39+00:00"
  },
  "key": {
    "crv": null,
    "d": null,
    "dp": null,
    "dq": null,
    "e": "AQAB",
    "k": null,
    "keyOps": [
      "encrypt",
      "decrypt",
      "sign",
      "verify",
      "wrapKey",
      "unwrapKey"
    ],
    "kid": "https://linuxbuildtestkeyvault.vault.azure.net/keys/testrsakey/9f3ca3e0300246669e344693c40bba81",
    "kty": "RSA",
    "n": "qkSnJvNzpHwEohZykFviCA2RMmKYXxt8GR7X6VnTcO2aJZOBkYwmm+DypwhA6Q6cwjET0XLwzibX5mABi+sAlGD+kmrME732QMPFZ79Xh1fhseC4L8jJacZXHU9uAvZkspNqUtFmib4LipEQDrN6to083v4f1xX5gPlPBeGMo58909rl0jPV0DMisjGZzRHVVop3lwy2zjCJFAROCgzNe7zedgyMnIFcs+pb8+ERxL19YM3UQLMfGD6Pxi1BhAfrOqkqPb7VIdTubaRJ3myB47MfWFUrH0mb2hU5IgrgDzO4GxeBn7jv8d7ZAkoq3XHzu+5wBUTTQkZOgf1QdQKCXQ==",
    "p": null,
    "q": null,
    "qi": null,
    "t": null,
    "x": null,
    "y": null
  },
  "managed": null,
  "releasePolicy": null,
  "tags": null
}
Restarting nginx (via systemctl): nginx.service.
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
  ```
