# How to build and deploy
- `az bicep build -f buildagent.main.bicep`
- `az deployment sub create --location westus3 --template-file buildagent.main.bicep --parameters @buildagent.parameters.json`

# Deploy to Azure
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fliupums%2FAzureKeyVaultCurl%2Fmain%2Flinuxvm-build-agent%2Fbuildagent.main.json)
