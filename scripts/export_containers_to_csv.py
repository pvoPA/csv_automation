from helpers import *


def main(data="", context=""):
    token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    end_of_page = False
    offset = 0
    LIMIT = 50

    containers_data = list()

    while not end_of_page:
        containers_response = get_containers(token, offset=offset, limit=LIMIT)

        if containers_response:
            containers_data += [container for container in containers_response]
        else:
            end_of_page = True

        offset += LIMIT

    csv_rows = list()

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

    if csv_rows:
        write_data_to_csv("prisma_containers.csv", csv_rows)


if __name__ == "__main__":
    main()
