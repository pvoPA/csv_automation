import os
import json
import datetime as dt
from helpers import logger
from helpers import generate_prisma_token
from helpers import prisma_get_containers_scan_results
from helpers import write_data_to_csv


def etl_containers_csv(collections_filter, containers_csv_name):
    """
    Gets container data from Prisma and transforms for CSV friendly data.

    Parameters:
        None

    Returns:
        None

    """
    csv_fields = [
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
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    file_path = f"CSVs/{containers_csv_name}_{todays_date}.csv"
    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

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
            logger.error(
                "Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(
                prisma_access_key, prisma_secret_key)
        else:
            logger.error("API returned %s.", status_code)

    csv_rows = list()

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

                # Variable fields
                if "namespace" in container["info"]:
                    row_dict.update(
                        {"Namespace": container["info"]["namespace"]})
                else:
                    row_dict.update({"Namespace": ""})

                if "cluster" in container["info"]:
                    row_dict.update({"Cluster": container["info"]["cluster"]})
                else:
                    row_dict.update({"Cluster": ""})

                csv_rows.append(row_dict)

    write_data_to_csv(file_path, csv_rows, csv_fields, new_file=True)


if __name__ == "__main__":
    logger.info("Creating containers CSV...")
    OPENSHIFT_COLLECTIONS_FILTER = ", ".join(
        json.loads(os.getenv("OPENSHIFT_COLLECTIONS_FILTER"))
    )
    OPENSHIFT_CONTAINERS_CSV_NAME = os.getenv("OPENSHIFT_CONTAINERS_CSV_NAME")
    HOST_COLLECTIONS_FILTER = ", ".join(
        json.loads(os.getenv("HOST_COLLECTIONS_FILTER"))
    )
    HOST_CONTAINERS_CSV_NAME = os.getenv("HOST_CONTAINERS_CSV_NAME")
    TAS_COLLECTIONS_FILTER = ", ".join(
        json.loads(os.getenv("TAS_COLLECTIONS_FILTER")))
    TAS_CONTAINERS_CSV_NAME = os.getenv("TAS_CONTAINERS_CSV_NAME")

    etl_containers_csv(OPENSHIFT_COLLECTIONS_FILTER,
                       OPENSHIFT_CONTAINERS_CSV_NAME)
    etl_containers_csv(HOST_COLLECTIONS_FILTER, HOST_CONTAINERS_CSV_NAME)
    etl_containers_csv(TAS_COLLECTIONS_FILTER, TAS_CONTAINERS_CSV_NAME)
