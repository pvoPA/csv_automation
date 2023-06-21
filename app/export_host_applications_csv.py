"""
Exports application data to CSV on host resources in Prisma Cloud.

This script is used to retrieve application data for host resources
and exports it to a CSV file with the following actions,
    - Generate Prisma Token
    - Delete the CSV file if it exists from a previous run
    - Grab host scan results
    - For each API call,
        - Flatten application list for each host
        - Write to CSV (Create a CSV directory and file.)

Usage:
    python export_host_application_csv.py

Options:

Requirements:
    - Python 3.10 or higher
    - .env configured with the following variables,
        - PRISMA_ACCESS_KEY
        - PRISMA_SECRET_KEY

Example:
    python export_host_application_csv.py

Note:
    This script is meant to be deployed in a docker container or azure function.
"""
import os
import json
import datetime as dt
from azure.core import exceptions
from azure.storage.blob import BlobServiceClient
from helpers import logger
from helpers import generate_prisma_token
from helpers import write_csv_to_blob
from helpers import prisma_get_host_scan_results


def etl_host_applications_csv():
    """
    Gets host data from Prisma and clean up for exporting to applications CSV.

    Parameters:
        None

    Returns:
        None

    """
    todays_date = str(dt.datetime.today()).split()[0]
    host_application_csv_name = os.getenv("HOST_APPLICATION_CSV_NAME")
    host_application_fields_of_interest = json.loads(
        os.getenv("HOST_APPLICATION_FIELDS_OF_INTEREST")
    )
    blob_name = f"CSVs/{host_application_csv_name}_{todays_date}.csv"
    blob_store_connection_string = os.getenv("AzureWebJobsStorage")
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")
    external_labels_to_include = json.loads(
        os.getenv("HOST_EXTERNAL_LABELS_TO_INCLUDE")
    )
    host_application_fields = json.loads(os.getenv("HOST_APPLICATION_CSV_COLUMNS"))

    for external_label in external_labels_to_include:
        host_application_fields.append(external_label)

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
    # Get hosts from Prisma

    end_of_page = False
    offset = 0
    incremental_id = 0
    page_limit = 50
    host_list = list()

    while not end_of_page:
        host_response, status_code = prisma_get_host_scan_results(
            prisma_token, offset=offset, limit=page_limit
        )

        if status_code == 200:
            if host_response:
                ###############################################################
                # Flatten application list for each host
                for host in host_response:
                    external_labels = dict()
                    if "externalLabels" in host:
                        for external_label in host["externalLabels"]:
                            if external_label["key"] in external_labels_to_include:
                                external_labels.update(
                                    {external_label["key"]: external_label["value"]}
                                )
                    host_dict = external_labels

                    host_dict.update({"Incremental_ID": incremental_id})

                    # Grab base host information
                    host_dict.update(
                        {
                            key: value
                            for key, value in host.items()
                            if (key in host_application_fields_of_interest)
                        }
                    )

                    host_list.append(host_dict)

                    incremental_id += 1

                ##############################################################
                # Write to CSV

                offset += page_limit
            else:
                end_of_page = True
                break
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
        else:
            logger.error("API returned %s.", status_code)

    if host_list:
        write_csv_to_blob(
            blob_name, host_list, host_application_fields, blob_client, new_file=True
        )
    else:
        logger.info("No data to write to CSV, it will not be created.")


if __name__ == "__main__":
    logger.info("Creating host applications CSV...")

    etl_host_applications_csv()
