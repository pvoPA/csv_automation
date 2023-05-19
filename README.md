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

### API Calls made by export_applications_csv.py
### API Calls made by export_containers_csv.py
### API Calls made by export_host_vulnerability_csv.py
### API Calls made by export_image_vulnerability_csv.py
### API Calls made by export_registry_image_vulnerability_csv.py
### API Calls made by export_tanzu_blobstore_vulnerability_csv.py
### API Calls made by export_tas_vulnerability_csv.py
