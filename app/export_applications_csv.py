from helpers import *


def ETL_applications_csv(PRISMA_TOKEN: str) -> list[dict]:
    """
    Gets container data from Prisma and transforms to create application relevant data.

    Parameters:
    PRISMA_TOKEN (str): PRISMA token for API access.

    Returns:
    list[dict]: list of dictionaries containing application data

    """
    APPLICATION_ID_KEY = os.getenv("APP_ID_KEY")
    OWNER_ID_KEY = os.getenv("OWNER_ID_KEY")
    COLLECTIONS_FILTER = os.getenv("COLLECTIONS_FILTER")
    ############################################################################################################################################
    # Get containers from Prisma

    end_of_page = False
    offset = 0
    LIMIT = 50

    containers_data = list()

    while not end_of_page:
        containers_response = get_containers(
            PRISMA_TOKEN, offset=offset, limit=LIMIT, collections=COLLECTIONS_FILTER
        )

        if containers_response:
            containers_data += [container for container in containers_response]
        else:
            end_of_page = True

        offset += LIMIT

    ############################################################################################################################################
    # Transform and grab fields of interest

    csv_rows = list()

    if containers_data:
        # Build associated containers
        associated_container_names_by_app = dict()

        for container in containers_data:
            CONTAINER_NAME = container["info"]["name"]
            CONTAINER_ID = container["info"]["id"]

            app_id_exists = False

            if "externalLabels" in container["info"]:
                for label in container["info"]["externalLabels"]:
                    if label["key"] == APPLICATION_ID_KEY:
                        APP_ID_EXTERNAL_LABEL = label["value"]
                        app_id_exists = True
                        break

            if not app_id_exists:
                APP_ID_EXTERNAL_LABEL = os.getenv("DEFAULT_APP")

            if APP_ID_EXTERNAL_LABEL in associated_container_names_by_app:
                associated_container_names_by_app[APP_ID_EXTERNAL_LABEL].append(
                    {
                        "associated_container_name": CONTAINER_NAME,
                        "associated_container_ID": CONTAINER_ID,
                    }
                )
            else:
                associated_container_names_by_app.update(
                    {
                        APP_ID_EXTERNAL_LABEL: [
                            {
                                "associated_container_name": CONTAINER_NAME,
                                "associated_container_ID": CONTAINER_ID,
                            }
                        ]
                    }
                )

        for container in containers_data:
            # Constant fields
            CONTAINER_ID = container["info"]["id"]
            # Key = CSV Column Name, Value = JSON field
            # App id(cluster + namespace + app_id (external label added to the resource, if this app_id does not exist then the default is APP00046878), associated container ids, owner(external label ays_support_group)

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

            ############################################################################################################################################
            # Create rows for CSV

            for associated_container in associated_container_names_by_app[
                APP_ID_EXTERNAL_LABEL
            ]:
                row_dict = {
                    "Container_ID": CONTAINER_ID,
                    "App_ID": APP_ID,
                    "Associated_Container_Name": associated_container[
                        "associated_container_name"
                    ],
                    "Associated_Container_ID": associated_container[
                        "associated_container_ID"
                    ],
                    "Owner": OWNER,
                }

                csv_rows.append(row_dict)

    return csv_rows


PRISMA_TOKEN = generate_prisma_token(prisma_access_key, prisma_secret_key)

logger.info(f" Creating applications CSV...")
application_rows = ETL_applications_csv(PRISMA_TOKEN)
write_data_to_csv("prisma_applications.csv", application_rows)
