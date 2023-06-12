import os
import json
import datetime as dt
from helpers import logger
from helpers import generate_prisma_token
from helpers import prisma_get_containers_scan_results
from helpers import write_data_to_csv


def etl_applications_csv() -> None:
    """
    Gets container data from Prisma and transforms to create application relevant data.

    Parameters:
        None

    Returns:
        None

    """
    todays_date = str(dt.datetime.today()).split()[0]
    applications_csv_name = os.getenv("APPLICATIONS_CSV_NAME")
    COLLECTIONS_FILTER = ", ".join(
        json.loads(os.getenv("OPENSHIFT_COLLECTIONS_FILTER"))
    )
    APPLICATION_ID_KEY = os.getenv("APP_ID_KEY")
    OWNER_ID_KEY = os.getenv("OWNER_ID_KEY")
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    file_path = f"CSVs/{applications_csv_name}_{todays_date}.csv"
    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    csv_fields = ["Incremental_ID", "Container_ID", "App_ID", "Owner"]

    ###########################################################################
    # Get containers from Prisma

    end_of_page = False
    offset = 0
    LIMIT = 50

    containers_data = list()

    while not end_of_page:
        containers_response, status_code = prisma_get_containers_scan_results(
            prisma_token, offset=offset, limit=LIMIT, collection=COLLECTIONS_FILTER
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

    ###########################################################################
    # Transform and grab fields of interest

    csv_rows = list()
    incremental_id = 0

    if containers_data:
        for container in containers_data:
            # Constant fields
            CONTAINER_ID = container["info"]["id"]
            # Key = CSV Column Name, Value = JSON field
            # App id(cluster + namespace + app_id (external label added to the resource,
            #   if this app_id does not exist then the default is APP00046878),
            #   associated container ids, owner(external label ays_support_group)

            # Build out the App ID
            if "cluster" in container["info"]:
                CLUSTER = container["info"]["cluster"]
            else:
                CLUSTER = ""
            if "namespace" in container["info"]:
                NAMESPACE = container["info"]["namespace"]
            else:
                NAMESPACE = ""

            app_id_exists = False

            owner_exists = False

            if "externalLabels" in container["info"]:
                for label in container["info"]["externalLabels"]:
                    if label["key"] == APPLICATION_ID_KEY:
                        APP_ID_EXTERNAL_LABEL = label["value"]
                        app_id_exists = True

                    # Get the Owner while parsing external labels
                    if label["key"] == OWNER_ID_KEY:
                        OWNER = label["value"]
                        owner_exists = True

                    if app_id_exists and owner_exists:
                        break

            if not app_id_exists:
                APP_ID_EXTERNAL_LABEL = os.getenv("DEFAULT_APP")

            if not owner_exists:
                OWNER = ""

            APP_ID = f"{CLUSTER}_{NAMESPACE}_{APP_ID_EXTERNAL_LABEL}"

            ###################################################################
            # Create rows for CSV

            row_dict = {
                "Incremental_ID": incremental_id,
                "Container_ID": CONTAINER_ID,
                "App_ID": APP_ID,
                "Owner": OWNER,
            }

            csv_rows.append(row_dict)

            incremental_id += 1

    write_data_to_csv(file_path, csv_rows, csv_fields, new_file=True)


if __name__ == "__main__":
    logger.info("Creating applications CSV...")

    etl_applications_csv()
