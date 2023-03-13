from helpers import *


def ETL_containers_csv(PRISMA_TOKEN: str):
    """
    Gets container data from Prisma and transforms for CSV friendly data.

    Parameters:
    PRISMA_TOKEN (str): PRISMA token for API access.

    Returns:
    list[dict]: list of dictionaries containing container data

    """
    COLLECTIONS_FILTER = os.getenv("COLLECTIONS_FILTER")
    ############################################################################################################################################
    # Grab containers data from Prisma
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

    csv_rows = list()

    ############################################################################################################################################
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
                    "Account_ID": container["info"]["cloudMetadata"]["accountID"],
                    "Collection": collection,
                }

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

    return csv_rows


PRISMA_TOKEN = generate_prisma_token(prisma_access_key, prisma_secret_key)

logger.info(f" Creating containers CSV...")
container_rows = ETL_containers_csv(PRISMA_TOKEN)
write_data_to_csv("prisma_containers.csv", container_rows)
