import os
import json
import datetime as dt
from azure.core import exceptions
from azure.storage.blob import BlobServiceClient
from helpers import logger
from helpers import generate_prisma_token
from helpers import prisma_get_containers_scan_results
from helpers import write_data_to_csv
from helpers import write_csv_to_blob


def etl_containers_csv(collections_filter, containers_csv_name):
    """
    Gets container data from Prisma and transforms for CSV friendly data.

    Parameters:
        None

    Returns:
        None

    """
    csv_fields = [
        "Incremental_ID",
        "Namespace",
        "Container_Name",
        "Host_Name",
        "Collection",
        "Container_ID",
        "Account_ID",
        "Cluster",
        "Image_ID",
    ]
    todays_date = str(dt.datetime.today()).split()[0]
    blob_store_connection_string = os.getenv("AzureWebJobsStorage")
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    blob_name = f"CSVs/{containers_csv_name}_{todays_date}.csv"
    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

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

    ##########################################################################
    # Grab containers data from Prisma

    end_of_page = False
    offset = 0
    LIMIT = 50

    containers_data = list()

    while not end_of_page:
        containers_response, status_code = prisma_get_containers_scan_results(
            prisma_token, offset=offset, limit=LIMIT, collection=collections_filter
        )

        if status_code == 200:
            if containers_response:
                containers_data += [container for container in containers_response]
            else:
                end_of_page = True

            offset += LIMIT
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
        else:
            logger.error("API returned %s.", status_code)

    csv_rows = list()
    incremental_id = 0

    ###########################################################################
    # Transform and grab fields of interest

    if containers_data:
        for container in containers_data:
            # Constant fields
            # Key = CSV Column Name, Value = JSON field
            for collection in container["collections"]:
                row_dict = {
                    "Container_ID": container["info"]["id"],
                    "Container_Name": container["info"]["name"],
                    "Image_ID": container["info"]["imageID"],
                    "Host_Name": container["hostname"],
                    "Account_ID": container["info"]["cloudMetadata"]["accountID"],
                    "Collection": collection,
                }

                row_dict.update({"Incremental_ID": incremental_id})

                # Variable fields
                if "namespace" in container["info"]:
                    row_dict.update({"Namespace": container["info"]["namespace"]})
                else:
                    row_dict.update({"Namespace": ""})

                if "cluster" in container["info"]:
                    row_dict.update({"Cluster": container["info"]["cluster"]})
                else:
                    row_dict.update({"Cluster": ""})

                csv_rows.append(row_dict)

                incremental_id += 1

    ###########################################################################
    # Delete the CSV file if it exists from a previous run
    try:
        for blob in container_client.list_blob_names():
            if todays_date not in blob:
                container_client.delete_blob(blob)
    except exceptions.ResourceNotFoundError:
        pass

    if csv_rows:
        write_csv_to_blob(blob_name, csv_rows, csv_fields, blob_client, new_file=True)
    else:
        logger.info("No data to write to CSV, it will not be created.")


if __name__ == "__main__":
    logger.info("Creating containers CSV...")
    OPENSHIFT_COLLECTIONS_FILTER = ", ".join(
        json.loads(os.getenv("OPENSHIFT_COLLECTIONS_FILTER"))
    )
    OPENSHIFT_CONTAINERS_CSV_NAME = os.getenv("OPENSHIFT_CONTAINERS_CSV_NAME")
    # HOST_COLLECTIONS_FILTER = ", ".join(
    #     json.loads(os.getenv("HOST_COLLECTIONS_FILTER"))
    # )
    # HOST_CONTAINERS_CSV_NAME = os.getenv("HOST_CONTAINERS_CSV_NAME")
    TAS_COLLECTIONS_FILTER = ", ".join(json.loads(os.getenv("TAS_COLLECTIONS_FILTER")))
    TAS_CONTAINERS_CSV_NAME = os.getenv("TAS_CONTAINERS_CSV_NAME")

    etl_containers_csv(OPENSHIFT_COLLECTIONS_FILTER, OPENSHIFT_CONTAINERS_CSV_NAME)
    # etl_containers_csv(HOST_COLLECTIONS_FILTER, HOST_CONTAINERS_CSV_NAME)
    etl_containers_csv(TAS_COLLECTIONS_FILTER, TAS_CONTAINERS_CSV_NAME)
