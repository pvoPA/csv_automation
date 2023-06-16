"""
Exports application data to CSV on tanzu blob store resources
    in Prisma Cloud.

This script is used to retrieve application data for
    tanzu blob store resources and exports it to
    a CSV file with the following actions,
        - Generate Prisma Token
        - Delete the CSV file if it exists from a previous run
        - Grab tanzu blob store scan results
        - For each API call,
            - Flatten application list for each blob
            - Write to CSV (Create a CSV directory and file.)

Usage:
    python export_tanzu_blobstore_application_csv.py

Options:

Requirements:
    - Python 3.10 or higher
    - .env configured with the following variables,
        - PRISMA_ACCESS_KEY
        - PRISMA_SECRET_KEY

Example:
    python export_tanzu_blobstore_application_csv.py

Note:
    This script is meant to be deployed in the following platforms,
        - docker container
            - the app directory
        - azure function
            - the azure-function directory
        - aws lambda function
            - the aws-lambda directory
"""
import os
import json
import datetime as dt
from azure.core import exceptions
from azure.storage.blob import BlobServiceClient
from helpers import logger
from helpers import prisma_get_images_scan_results
from helpers import prisma_get_containers_scan_results
from helpers import generate_prisma_token
from helpers import write_data_to_csv
from helpers import write_csv_to_blob


def etl_tanzu_blobstore_applications_csv():
    """
    Gets tanzu application service data from Prisma and export to CSV.

    Parameters:
        None

    Returns:
        None

    """
    todays_date = str(dt.datetime.today()).split()[0]
    COLLECTIONS_FILTER = ", ".join(json.loads(os.getenv("TAS_COLLECTIONS_FILTER")))
    tas_blobstore_application_csv_name = os.getenv("TAS_APPLICATION_CSV_NAME")
    tas_blobstore_application_fields_of_interest = json.loads(
        os.getenv("TAS_APPLICATION_FIELDS_OF_INTEREST")
    )

    blob_name = f"CSVs/{tas_blobstore_application_csv_name}_{todays_date}.csv"
    blob_store_connection_string = os.getenv("AzureWebJobsStorage")
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")
    external_labels_to_include = json.loads(os.getenv("TAS_EXTERNAL_LABELS_TO_INCLUDE"))

    tas_csv_fields = json.loads(os.getenv("TAS_APPLICATION_CSV_COLUMNS"))

    for external_label in external_labels_to_include:
        tas_csv_fields.append(external_label)

    ###########################################################################
    # Initialize blob store client

    blob_service_client = BlobServiceClient.from_connection_string(
        blob_store_connection_string
    )

    container_name = os.getenv("STORAGE_ACCOUNT_CONTAINER_NAME")
    try:
        container_client = blob_service_client.get_container_client(container_name)
    except exceptions.ResourceNotFoundError:
        container_client = blob_service_client.create_container(container_name)
    blob_client = container_client.get_blob_client(blob_name)

    ###########################################################################
    # Delete the CSV file if it exists from a previous run
    try:
        container_client.delete_blob(blob_name)
    except exceptions.ResourceNotFoundError:
        pass

    ###########################################################################
    # Generate Prisma Token

    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    ###########################################################################
    # Get images from Prisma and write to CSV

    end_of_page = False
    offset = 0
    page_limit = 50
    tas_application_dict = dict()

    while not end_of_page:
        (
            tas_response,
            status_code,
        ) = prisma_get_images_scan_results(
            prisma_token, offset=offset, limit=page_limit, collection=COLLECTIONS_FILTER
        )

        if status_code == 200:
            if tas_response:
                ###############################################################
                # Flatten application list for each blob
                for tas in tas_response:
                    external_labels = dict()
                    if "externalLabels" in tas:
                        for external_label in tas["externalLabels"]:
                            if external_label["key"] in external_labels_to_include:
                                external_labels.update(
                                    {external_label["key"]: external_label["value"]}
                                )
                    # Grab base host information
                    vulnerability_dict = {
                        key: value
                        for key, value in tas.items()
                        if (key in tas_blobstore_application_fields_of_interest)
                    }

                    if tas["_id"] in tas_application_dict:
                        tas_application_dict[tas["_id"]].append(vulnerability_dict)
                    else:
                        tas_application_dict.update({tas["_id"]: [vulnerability_dict]})

                offset += page_limit
            else:
                end_of_page = True
                break
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
        else:
            logger.error("API returned %s.", status_code)

    ###########################################################################
    # Get collection IDs for TAS vulnerability correlation and write to CSV

    end_of_page = False
    offset = 0
    LIMIT = 50
    incremental_id = 0
    csv_rows = list()

    while not end_of_page:
        containers_response, status_code = prisma_get_containers_scan_results(
            prisma_token, offset=offset, limit=LIMIT, collection=COLLECTIONS_FILTER
        )
        if status_code == 200:
            if containers_response:
                for container in containers_response:
                    IMAGE_ID = container["info"]["imageID"]
                    if IMAGE_ID in tas_application_dict:
                        for vuln in tas_application_dict[IMAGE_ID]:
                            vuln.update({"Incremental_ID": incremental_id})

                            csv_rows.append(vuln)

                            incremental_id += 1

                        # remove the image ID as it's already been added to the CSV
                        tas_application_dict.pop(IMAGE_ID)

            else:
                end_of_page = True

            offset += LIMIT
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
        else:
            logger.error("API returned %s.", status_code)

    if csv_rows:
        write_csv_to_blob(
            blob_name, csv_rows, tas_csv_fields, blob_client, new_file=True
        )
    else:
        logger.info("No data to write to CSV, it will not be created.")


if __name__ == "__main__":
    logger.info("Creating tanzu blobstore applications CSV...")

    etl_tanzu_blobstore_applications_csv()
