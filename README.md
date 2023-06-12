# csv_automation

This repository contains the scripts to collect data from Prisma and create CSVs in Azure/AWS/Docker.

## Requirements

* Python 3.10
* Docker
* Azure Subscription
* Azure Functions Core Tools
* Azurite V3 Extension

## Azure

### Deployment

* Click on the `Azure` tab in the Activity Bar of VS Code.
* Under the `Resources` tab, `Sign in to Azure...`
* After signing in, click the `+` symbol next to `Resources` tab.
* Create a function app with the following configurations,
  * Python v2 Programming Model
  * Python 3.10
  * Name of the Function
  * Cloud Region for the Function
* Under the `Workspace` tab, Deploy the `Local Project` to Azure pointing to the newly created function app.
* Add the following environment variable to the new function app in Azure under `Configuration`
  * `AzureWebJobsFeatureFlags` = `EnableWorkerIndexing` 
* You can configure the environment variables 1 of 2 ways,
  * Renaming `.env.template` to `.env`
  * Adding all the variables in `.env.template` to `Application Settings` in Azure.


### Testing Azure Function

* Add the following key value pair to `local.settings.json` in the `values` dict,
  * `"AzureWebJobsStorage": "UseDevelopmentStorage=true"`
* Make sure you have the `Azurite V3 extension` installed in VS Code.
* Hit `F1` key to open the `VS Code Command Palette`.
* Run the `Azurite: Start` command to begin the emulator for local Azure function testing.
* Hit `F5` with `azure-function/function_app.py` to run the function locally.
* Choose the `Azure Icon` in the VS Code Activity Bar.
* In the `Workspace` area, expand `Local Project > Functions`.
* Right click any of the functions and click `Execute Function Now...`
* Send the request and view the logs in terminal and response from VS Code.
  * The business logic is ran asynchronously, VS Code will return a response before the alert sync automation is done running be sure to check the logs for errors.


## Docker

* Within the `app/` directory, run the following commands...
  * `docker compose build`
  * `docker compose up`

* To debug and interact in the container,
  * `docker run -it csv_automation:latest /bin/bash`

## Testing

* Rename `.env.template` to `.env`
* Configure the environment variables to point to your tenant.
* Configure your access/secret key pair in `.env`, you can generate the key pair in PRISMA console.

To run the scripts in a venv run the following commands,

* `python -m venv .venv`
* `source .venv/bin/activate`
* `pip install -r app/requirements.txt`
* `python app/main.py`

You can exit the virtual env by running the following command,

* `deactivate`

### API Calls made by export_containers_csv.py

* [POST - Generate Prisma Token](https://pan.dev/prisma-cloud/api/cspm/app-login/)
* [GET - Container Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-containers/)

### API Calls made by export_host_applications_csv.py

* [POST - Generate Prisma Token](https://pan.dev/prisma-cloud/api/cspm/app-login/)
* [GET - Host Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-hosts/)

#### Available CSV Fields for export_host_applications_csv.py

["Incremental_ID", "repoTag", "firewallProtection", "history", "creationTime", "packageManager", "complianceIssuesCount", "collections", "pushTime", "scanBuildDate", "osDistro", "labels", "scanVersion", "hostDevices", "err", "packageCorrelationDone", "scanID", "firstScanTime", "complianceDistribution", "startupBinaries", "vulnerabilityRiskScore", "image", "agentless", "tags", "appEmbedded", "wildFireUsage", "trustStatus", "hosts", "Secrets", "vulnerabilitiesCount", "type", "riskFactors", "osDistroRelease", "applications", "isARM64", "distro", "vulnerabilityDistribution", "complianceRiskScore", "allCompliance", "binaries", "instances", "files", "installedProducts", "scanTime", "complianceIssues", "cloudMetadata", "hostname", "_id", "packages", "osDistroVersion", "repoDigests", "externalLabels", "rhelRepos", "clusters", "k8sClusterAddr", "stopped", "ecsClusterName", ]

### API Calls made by export_host_vulnerability_csv.py

* [POST - Generate Prisma Token](https://pan.dev/prisma-cloud/api/cspm/app-login/)
* [GET - Host Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-hosts/)

#### Available CSV Fields for export_host_vulnerability_csv.py

["Incremental_ID", "Resource_ID", "Package_Path", "severity", "published", "vecStr", "exploit", "cri", "text", "type", "fixDate", "discovered", "title", "functionLayer", "cve", "twistlock", "riskFactors", "layerTime", "description", "link", "cause", "status", "templates", "applicableRules", "cvss", "id", "packageName", "packageVersion", "binaryPkgs", "exploits", "fixLink", "vulnTagInfos"]

### API Calls made by export_openshift_applications_csv.py

* [POST - Generate Prisma Token](https://pan.dev/prisma-cloud/api/cspm/app-login/)
* [GET - Container Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-containers/)

### API Calls made by export_openshift_image_vulnerability_csv.py

* [POST - Generate Prisma Token](https://pan.dev/prisma-cloud/api/cspm/app-login/)
* [GET - Container Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-containers/)
* [GET - Image Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-images/)

#### Available CSV Fields for export_openshift_image_vulnerability_csv.py

["osDistroVersion", "complianceIssues", "exploit", "isARM64", "vulnerabilityDistribution", "cvss", "hostname", "severity", "type", "discovered", "cause", "riskFactors", "applicableRules", "vulnerabilitiesCount", "packages", "complianceRiskScore", "agentless", "packageName", "scanTime", "firewallProtection", "packageCorrelationDone", "complianceDistribution", "layers", "cri", "allCompliance", "twistlock", "binaryPkgs", "vulnerabilityRiskScore", "scanVersion", "hosts", "text", "id", "layerTime", "registryType", "packageManager", "templates", "collections", "trustStatus", "vecStr", "complianceIssuesCount", "status", "title", "cve", "scanBuildDate", "appEmbedded", "wildFireUsage", "osDistro", "cloudMetadata", "_id", "osDistroRelease", "startupBinaries", "installedProducts", "scanID", "published", "Secrets", "image", "applications", "link", "files", "repoTag", "creationTime", "distro", "description", "binaries", "fixDate", "firstScanTime", "packageVersion", "repoDigests", "pushTime", "err", "functionLayer", "history", "topLayer", "instances", "tags", "labels", "exploits", "vulnTagInfos"]

### API Calls made by export_registry_image_application_csv.py

* [POST - Generate Prisma Token](https://pan.dev/prisma-cloud/api/cspm/app-login/)
* [GET - Registry Image Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-registry/)

#### Available CSV Fields for export_registry_image_application_csv.py

["Incremental_ID", "pushTime", "startupBinaries", "history", "vulnerabilitiesCount", "wildFireUsage", "osDistroVersion", "isARM64", "repoDigests", "packageCorrelationDone", "osDistro", "repoTag", "vulnerabilityRiskScore", "installedProducts", "files", "hosts", "firstScanTime", "trustStatus", "complianceIssuesCount", "firewallProtection", "complianceRiskScore", "collections", "Secrets", "err", "image", "riskFactors", "complianceIssues", "cloudMetadata", "allCompliance", "scanTime", "appEmbedded", "creationTime", "agentless", "packages", "_id", "complianceDistribution", "binaries", "packageManager", "tags", "instances", "osDistroRelease", "vulnerabilityDistribution", "resourceID", "type", "hostname", "id", "scanID", "registryType", "distro", "topLayer", "scanVersion", "scanBuildDate", "layers", "applications"]


### API Calls made by export_registry_image_vulnerability_csv.py

* [POST - Generate Prisma Token](https://pan.dev/prisma-cloud/api/cspm/app-login/)
* [GET - Registry Image Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-registry/)

#### Available CSV Fields for export_registry_image_vulnerability_csv.py

["Incremental_ID", "Resource_ID", "riskFactors", "twistlock", "cri", "cve", "cvss", "fixDate", "published", "description", "resourceID", "packageVersion", "text", "status", "functionLayer", "vecStr", "layerTime", "exploit", "title", "link", "type", "packageName", "templates", "applicableRules", "discovered", "id", "binaryPkgs", "severity", "cause"] 

### API Calls made by export_tanzu_blobstore_application_csv.py

* [POST - Generate Prisma Token](https://pan.dev/prisma-cloud/api/cspm/app-login/)
* [GET - Tanzu Blobstore Scan Results]()
  * Not available in documentation.

#### Available CSV Fields for export_tanzu_blobstore_application_csv.py

["Incremental_ID", "packages", "creationTime", "name", "osDistro", "accountID", "repoTag", "complianceRiskScore", "repoDigests", "osDistroVersion", "applications", "cloudMetadata", "timeout", "version", "defenderLayerARN", "vulnerabilitiesCount", "image", "packageManager", "collections", "provider", "region", "lastModified", "tags", "riskFactors", "id", "pushTime", "vulnerabilityDistribution", "installedProducts", "history", "labels", "complianceIssues", "scanTime", "binaries", "allCompliance", "complianceDistribution", "defended", "hash", "complianceIssuesCount", "files", "scannerVersion", "vulnerabilityRiskScore", "firstScanTime", "type", "isARM64", "runtime", "hostname", "distro", "Secrets", "_id", "architecture", "osDistroRelease", "memory", "description", "handler", "resourceGroupName", "cloudControllerAddress", "applicationName", "startupBinaries", "packageCorrelationDone"]

### API Calls made by export_tanzu_blobstore_vulnerability_csv.py

* [POST - Generate Prisma Token](https://pan.dev/prisma-cloud/api/cspm/app-login/)
* [GET - Tanzu Blobstore Scan Results]()
  * Not available in documentation.

#### Available CSV Fields for export_tanzu_blobstore_vulnerability_csv.py

["Incremental_ID", "Resource_ID", "link", "description", "cri", "cvss", "templates", "vecStr", "applicableRules", "fixDate", "packageVersion", "status", "twistlock", "text", "packageName", "exploit", "layerTime", "title", "functionLayer", "severity", "discovered", "cve", "type", "id", "cause", "published", "riskFactors", "exploits"]

### API Calls made by export_tas_application_csv.py

* [POST - Generate Prisma Token](https://pan.dev/prisma-cloud/api/cspm/app-login/)
* [GET - Image Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-images/)

#### Available CSV Fields for export_tas_application_csv

["Incremental_ID", "osDistroVersion", "packageCorrelationDone", "complianceIssues", "pushTime", "applications", "isARM64", "hosts", "_id", "id", "startupBinaries", "repoTag", "appEmbedded", "vulnerabilitiesCount", "installedProducts", "osDistro", "scanID", "err", "scanVersion", "collections", "allCompliance", "firstScanTime", "vulnerabilityDistribution", "firewallProtection", "wildFireUsage", "scanTime", "tags", "complianceDistribution", "instances", "osDistroRelease", "packageManager", "complianceIssuesCount", "hostname", "agentless", "vulnerabilityRiskScore", "type", "complianceRiskScore", "clusters", "Secrets", "image", "cloudMetadata", "trustStatus", "distro", "creationTime", "repoDigests", "binaries", "packages", "files", "riskFactors", "history"]


### API Calls made by export_tas_vulnerability_csv.py

* [POST - Generate Prisma Token](https://pan.dev/prisma-cloud/api/cspm/app-login/)
* [GET - Image Scan Results](https://pan.dev/prisma-cloud/api/cwpp/get-images/)

#### Available CSV Fields for export_tas_vulnerability_csv

["Incremental_ID", "Resource_ID", "labels", "type", "appEmbedded", "description", "firewallProtection", "clusters", "hostname", "scanVersion", "tags", "scanBuildDate", "Secrets", "binaries", "packageCorrelationDone", "layerTime", "scanTime", "wildFireUsage", "twistlock", "packages", "published", "_id", "complianceIssues", "distro", "text", "repoDigests", "hosts", "scanID", "vulnerabilitiesCount", "packageName", "isARM64", "id", "allCompliance", "status", "err", "severity", "cri", "functionLayer", "osDistro", "osDistroRelease", "creationTime", "cloudMetadata", "layers", "collections", "cause", "topLayer", "packageVersion", "exploit", "applicableRules", "trustStatus", "vulnerabilityRiskScore", "repoTag", "vulnerabilityDistribution", "vecStr", "instances", "title", "complianceDistribution", "firstScanTime", "cvss", "startupBinaries", "image", "link", "riskFactors", "pushTime", "complianceRiskScore", "files", "history", "agentless", "installedProducts", "complianceIssuesCount", "cve", "templates", "fixDate", "discovered", "osDistroVersion", "packageManager", "binaryPkgs", "exploits", "applications", "vulnTagInfos", "missingDistroVulnCoverage", "namespaces", "externalLabels", "rhelRepos", "gracePeriodDays", "block", "twistlockImage", "Package_Path"]