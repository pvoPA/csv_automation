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
from helpers import prisma_get_tanzu_blob_store_scan_results
from helpers import generate_prisma_token
from helpers import write_data_to_csv
from helpers import write_csv_to_blob


def etl_tanzu_blobstore_applications_csv():
    """
    Gets tanzu blobstore data from Prisma and cleans up for exporting to CSV.

    Parameters:
        None

    Returns:
        None

    """
    todays_date = str(dt.datetime.today()).split()[0]

    tanzu_blobstore_application_csv_name = os.getenv(
        "TANZU_BLOBSTORE_APPLICATION_CSV_NAME"
    )
    tanzu_blobstore_application_fields_of_interest = json.loads(
        os.getenv("TANZU_BLOBSTORE_APPLICATION_FIELDS_OF_INTEREST")
    )
    blob_name = f"CSVs/{tanzu_blobstore_application_csv_name}_{todays_date}.csv"
    blob_store_connection_string = os.getenv("AzureWebJobsStorage")
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    tanzu_csv_fields = json.loads(os.getenv("TANZU_APPLICATION_CSV_COLUMNS"))

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
        for blob in container_client.list_blob_names():
            if todays_date not in blob:
                container_client.delete_blob(blob)
    except exceptions.ResourceNotFoundError:
        pass

    ###########################################################################
    # Generate Prisma Token

    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    ###########################################################################
    # Get blobstore data from Prisma and write to CSV

    end_of_page = False
    offset = 0
    incremental_id = 0
    page_limit = 50
    application_list = list()

    while not end_of_page:
        (
            tanzu_blobstore_response,
            status_code,
        ) = prisma_get_tanzu_blob_store_scan_results(
            prisma_token, offset=offset, limit=page_limit
        )

        if status_code == 200:
            if tanzu_blobstore_response:
                ###############################################################
                # Flatten application list for each blob

                for blob in tanzu_blobstore_response:
                    application_dict = {"Incremental_ID": incremental_id}
                    # Grab base host information
                    application_dict.update(
                        {
                            key: value
                            for key, value in blob.items()
                            if (key in tanzu_blobstore_application_fields_of_interest)
                        }
                    )

                    application_list.append(application_dict)
                    incremental_id += 1

                offset += page_limit
            else:
                end_of_page = True
                break
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
        else:
            logger.error("API returned %s.", status_code)

    ###############################################################
    # Write to CSV
    if application_list:
        write_csv_to_blob(
            blob_name,
            application_list,
            tanzu_csv_fields,
            blob_client,
            new_file=True,
        )
    else:
        logger.info("No data to write to CSV, it will not be created.")


if __name__ == "__main__":
    logger.info("Creating tanzu blobstore applications CSV...")

    etl_tanzu_blobstore_applications_csv()
