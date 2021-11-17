/*
 Summary: Provisions a Azure DevOps build agent using a Linux VM.
*/

// Subscription deployemnt of RG, then contained resources as modules
targetScope = 'subscription'


// ============================================================================
// Parameters


@description('VM Name')
param vmName string

@description('Admin username for VMs')
param adminUserName string = 'azureuser'

@description('Administrative SSH key for the VM')
param adminSshPubKey string

@description('Name of Key Vault')
param keyVaultName string = take('${vmName}KeyVault', 24)

@description('Location to deploy resources, defaults to deployment location')
param location string = deployment().location

@description('Resource group name')
param resourceGroupName string = '${vmName}Rg'

@description('VM SKU to use for VM')
param vmSku string = 'Standard_B2ms'

@description('Deploy KeyVault')
param deployKeyVault bool

param buildScriptPath string = deployment().properties.templateLink.id
var scriptPath = uri(buildScriptPath, 'startbuild.sh')

// ============================================================================
// Resources

resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: resourceGroupName
  location: location
}

var vNetBuildAgentDefinitions = {
  name: 'buildagentVnet'
  location: location
  addressSpacePrefix: '192.168.128.0/24' // 192.168.128.0 - 192.168.128.255
  subnets: [
    {
      name: 'worker'    
      subnetPrefix: '192.168.128.0/25' // // 192.168.128.0 - 192.168.128.127
    }
  ]
}

module vnet 'buildagent.vnet.bicep' = {
  name: 'vnetDeploy'
  scope: rg
  params: {
    vNetBuildAgentDefinitions: vNetBuildAgentDefinitions
  }
}

module vm './buildagent.vm.bicep' = {
  name: 'vmDeploy'
  scope: rg
  params: {
    adminSshPubKey: adminSshPubKey
    adminUserName: adminUserName
    vmSku: vmSku
    vmName : vmName
    subnetResourceId: vnet.outputs.subnetResourceId[0].id // subnet 'worker' with index 0 is for vm
  }
}


// Built-in roleDefinition GUID for kay vault admin
// https://docs.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli
var roleDefinition_keyVaultAdmin = '00482a5a-887f-4fb3-b363-3b7fe8e74483'

// Azure key valut depends on VM
module kv './buildagent.kv.bicep' = if (deployKeyVault) {
  name: 'kvDeploy'
  scope: rg
  params: {
    keyVaultName: keyVaultName
    subnetResourceId: vnet.outputs.subnetResourceId[0].id
    vmPrincipalId: vm.outputs.principalId
    vnetResourceId: vnet.outputs.vnetResourceId
    roleDef: roleDefinition_keyVaultAdmin
  }
}

// The VM script depends on Auzre Key Vault
module vmScript './buildagent.vmscript.bicep' = {
  name: 'vmScipt'
  scope: rg
  params: {
    vmName: vmName
    buildScriptPath: scriptPath
    akvName: kv.outputs.akvName
  }
}
