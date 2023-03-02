# csv_automation

This repository contains the scripts and dockerfiles to collect data from Prisma and create CSVs.

## Requirements

* Python 3.10

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

### API Calls made by main.py

1. [POST - Token](https://pan.dev/prisma-cloud/api/cspm/app-login/)
2. [GET - Containers](https://pan.dev/prisma-cloud/api/cwpp/get-containers/)
3. [GET - Images](https://pan.dev/prisma-cloud/api/cwpp/get-images/)
