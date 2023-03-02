from helpers import *


def ETL_applications_csv(PRISMA_TOKEN: str) -> list[dict]:
    """
    Gets container data from Prisma and transforms to create application relevant data.

    Parameters:
    PRISMA_TOKEN (str): PRISMA token for API access.

    Returns:
    list[dict]: list of dictionaries containing application data

    """

    ############################################################################################################################################
    # Get containers from Prisma

    end_of_page = False
    offset = 0
    LIMIT = 50

    containers_data = list()

    while not end_of_page:
        containers_response = get_containers(PRISMA_TOKEN, offset=offset, limit=LIMIT)

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
                    if label["key"] == "app_id":
                        APP_ID_EXTERNAL_LABEL = label["value"]
                        app_id_exists = True
                        break

            if not app_id_exists:
                APP_ID_EXTERNAL_LABEL = os.getenv("DEFAULT_APP_ID")

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
            if "namespace" in container["info"]:
                NAMESPACE = container["info"]["namespace"]

            app_id_exists = False

            owner_exists = False

            if "externalLabels" in container["info"]:
                for label in container["info"]["externalLabels"]:
                    if label["key"] == "app_id":
                        APP_ID_EXTERNAL_LABEL = label["value"]
                        app_id_exists = True

                    # Get the Owner while parsing external labels
                    if label["key"] == "ays_support_group":
                        OWNER = label["value"]
                        owner_exists = True

                    if app_id_exists and owner_exists:
                        break

            if not app_id_exists:
                APP_ID_EXTERNAL_LABEL = os.getenv("DEFAULT_APP_ID")

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


def ETL_containers_csv(PRISMA_TOKEN: str):
    """
    Gets container data from Prisma and transforms for CSV friendly data.

    Parameters:
    PRISMA_TOKEN (str): PRISMA token for API access.

    Returns:
    list[dict]: list of dictionaries containing container data

    """
    ############################################################################################################################################
    # Grab containers data from Prisma
    end_of_page = False
    offset = 0
    LIMIT = 50

    containers_data = list()

    while not end_of_page:
        containers_response = get_containers(PRISMA_TOKEN, offset=offset, limit=LIMIT)

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


def ETL_vulnerabilities_csv(PRISMA_TOKEN: str):
    """
    Gets container and image data from Prisma and transforms to create image vulnerability relevant data.

    Parameters:
    PRISMA_TOKEN (str): PRISMA token for API access.

    Returns:
    list[dict]: list of dictionaries containing image vulnerability data

    """
    ############################################################################################################################################
    # Get collection IDs for image vulnerability correlation

    end_of_page = False
    offset = 0
    LIMIT = 50

    containers_data = list()

    while not end_of_page:
        containers_response = get_containers(PRISMA_TOKEN, offset=offset, limit=LIMIT)

        if containers_response:
            containers_data += [container for container in containers_response]
        else:
            end_of_page = True

        offset += LIMIT

    ############################################################################################################################################
    # Get images from Prisma to extract vulnerabilities

    end_of_page = False
    offset = 0
    LIMIT = 50

    images_data = list()

    while not end_of_page:
        images_response = get_images(PRISMA_TOKEN, offset=offset, limit=LIMIT)

        if images_response:
            images_data += [image for image in images_response]
        else:
            end_of_page = True

        offset += LIMIT

    ############################################################################################################################################
    # Transform and grab fields of interest

    csv_rows = list()

    # Attach vulnerability data to the image ID
    image_vuln_dict = dict()

    if images_data:
        for image in images_data:
            IMAGE_ID = image["_id"]

            if "vulnerabilities" in image.keys():
                if image["vulnerabilities"]:
                    for vuln in image["vulnerabilities"]:
                        vuln_dict = {
                            "Image_ID": IMAGE_ID,
                            "CVE": f"{vuln['cve']}",
                            "CVSS_Score": f"{vuln['cvss']}",
                            "Severity": f"{vuln['severity']}",
                            "Fix_Status": f"{vuln['status']}",
                            "Package_Name": f"{vuln['packageName']}",
                            "Package_Path": "NOT_AVAILABLE",
                            "Time_Discovered": f"{vuln['discovered']}",
                        }

                        # Get the package info and install path
                        PACKAGE_NAME = vuln["packageName"]
                        PACKAGE_VERSION = vuln["packageVersion"]
                        PACKAGE_PATH = "NOT_AVAILABLE"

                        package_found = False

                        if PACKAGE_NAME:
                            for package_type in image["packages"]:
                                for package in package_type["pkgs"]:
                                    if (
                                        package["name"] == PACKAGE_NAME
                                        and package["version"] == PACKAGE_VERSION
                                    ):
                                        if "path" in package:
                                            PACKAGE_PATH = package["path"]
                                        package_found = True
                                        break

                            # Check "applications" field for package path
                            if not package_found:
                                if "applications" in image:
                                    for app in image["applications"]:
                                        if (
                                            app["name"] == PACKAGE_NAME
                                            and app["version"] == PACKAGE_VERSION
                                        ):
                                            PACKAGE_PATH = app["path"]
                                            package_found = True
                                            break

                            # Check "binaries" field for package path
                            if not package_found:
                                if "binaries" in image:
                                    for binary in image["binaries"]:
                                        if binary["name"] == PACKAGE_NAME:
                                            PACKAGE_PATH = binary["path"]
                                            package_found = True
                                            break

                            # Check "startupBinaries" field for package path
                            if not package_found:
                                if "binaries" in image:
                                    for binary in image["binaries"]:
                                        if binary["name"] == PACKAGE_NAME:
                                            PACKAGE_PATH = binary["path"]
                                            package_found = True
                                            break

                        if package_found:
                            vuln_dict["Package_Path"] = PACKAGE_PATH

                        if IMAGE_ID in image_vuln_dict:
                            image_vuln_dict[IMAGE_ID].append(vuln_dict)
                        else:
                            image_vuln_dict.update({IMAGE_ID: [vuln_dict]})

    incremental_id = 0

    ############################################################################################################################################
    # Create the rows for CSV creation

    if containers_data:
        for container in containers_data:
            # Constant fields
            # Key = CSV Column Name, Value = JSON field
            # Incrementing id, Container id, CVE, CVSS score, fix status, package name, install path of package, time discovered
            IMAGE_ID = container["info"]["imageID"]
            if IMAGE_ID in image_vuln_dict:
                for vuln in image_vuln_dict[IMAGE_ID]:
                    row_dict = {
                        "Incremental_ID": incremental_id,
                        "Container_ID": container["info"]["id"],
                        "Image_ID": vuln["Image_ID"],
                        "CVE": vuln["CVE"],
                        "CVSS_Score": vuln["CVSS_Score"],
                        "Severity": vuln["Severity"],
                        "Fix_Status": vuln["Fix_Status"],
                        "Package_Name": vuln["Package_Name"],
                        "Package_Path": vuln["Package_Path"],
                        "Time_Discovered": vuln["Time_Discovered"],
                    }

                    csv_rows.append(row_dict)

                    incremental_id += 1

    return csv_rows


def main(data="", context=""):
    PRISMA_TOKEN = generate_prisma_token(prisma_access_key, prisma_secret_key)

    logger.info(f" Creating applications CSV...")
    application_rows = ETL_applications_csv(PRISMA_TOKEN)
    write_data_to_csv("prisma_applications.csv", application_rows)

    logger.info(f" Creating containers CSV...")
    container_rows = ETL_containers_csv(PRISMA_TOKEN)
    write_data_to_csv("prisma_containers.csv", container_rows)

    logger.info(f" Creating vulnerabilities CSV...")
    vulnerability_rows = ETL_vulnerabilities_csv(PRISMA_TOKEN)
    write_data_to_csv("prisma_vulnerabilities.csv", vulnerability_rows)


if __name__ == "__main__":
    main()
