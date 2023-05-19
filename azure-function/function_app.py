"""
Azure Function that exports data from Prisma Cloud to CSV.

This function uses the Prisma Cloud API to retrieve data
    and exports it to a CSV file.
    The exported data includes information about
    compliance policies, risks, vulnerabilities,
    and other security-related issues in your cloud environment.

The function requires the following environment variables:
    - api_endpoint: The endpoint for the Prisma Cloud API.
    - access_key: The access key for the Prisma Cloud API.
    - secret_key: The secret key for the Prisma Cloud API.
    - csv_file_path: The path where the CSV file will be saved.

Usage:
    Please refer to the README.md for instructions on
        local testing and deployment

Returns:
   Creates CSV files locally
"""
import os
import json
import logging as logger
import azure.functions as func
from helpers import generate_prisma_token
from helpers import write_data_to_csv
from helpers import prisma_get_containers_scan_results
from helpers import prisma_get_host_scan_results
from helpers import prisma_get_images_scan_results
from helpers import prisma_get_registry_image_scan_results
from helpers import prisma_get_tanzu_blob_store_scan_results

function_app = func.FunctionApp()

applications_csv_cron_schedule = os.getenv("APPLICATIONS_CSV_CRON_SCHEDULE")
containers_csv_cron_schedule = os.getenv("CONTAINERS_CSV_CRON_SCHEDULE")
host_vulnerability_csv_cron_schedule = os.getenv("HOST_VULNERABILITY_CSV_CRON_SCHEDULE")
tas_vulnerability_csv_cron_schedule = os.getenv("TAS_VULNERABILITY_CSV_CRON_SCHEDULE")
image_vulnerability_csv_cron_schedule = os.getenv(
    "IMAGE_VULNERABILITY_CSV_CRON_SCHEDULE"
)
registry_image_vulnerability_csv_cron_schedule = os.getenv(
    "REGISTRY_IMAGE_VULNERABILITY_CSV_CRON_SCHEDULE"
)
tanzu_blobstore_vulnerability_csv_cron_schedule = os.getenv(
    "TANZU_BLOBSTORE_VULNERABILITY_CSV_CRON_SCHEDULE"
)


@function_app.function_name(name="export_applications_csv")
@function_app.schedule(
    schedule=applications_csv_cron_schedule, run_on_startup=False, use_monitor=True
)
def export_applications_csv():
    """
    Gets container data from Prisma and transforms to create application relevant data.

    Parameters:
        None

    Returns:
        None

    """
    applications_csv_name = os.getenv("APPLICATIONS_CSV_NAME")
    COLLECTIONS_FILTER = ", ".join(json.loads(os.getenv("COLLECTIONS_FILTER")))
    APPLICATION_ID_KEY = os.getenv("APP_ID_KEY")
    OWNER_ID_KEY = os.getenv("OWNER_ID_KEY")
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    file_path = f"CSVs/{applications_csv_name}"
    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

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

    field_names = [key for key in csv_rows[0].keys()]

    write_data_to_csv(file_path, csv_rows, field_names, new_file=True)


@function_app.function_name(name="export_containers_csv")
@function_app.schedule(
    schedule=applications_csv_cron_schedule, run_on_startup=False, use_monitor=True
)
def export_containers_csv():
    """
    Gets container data from Prisma and transforms for CSV friendly data.

    Parameters:
        None

    Returns:
        None

    """
    containers_csv_name = os.getenv("CONTAINERS_CSV_NAME")
    COLLECTIONS_FILTER = ", ".join(json.loads(os.getenv("COLLECTIONS_FILTER")))
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    file_path = f"CSVs/{containers_csv_name}"
    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    ##########################################################################
    # Grab containers data from Prisma

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

    field_names = [key for key in csv_rows[0].keys()]

    write_data_to_csv(file_path, csv_rows, field_names, new_file=True)


@function_app.function_name(name="export_host_vulnerability_csv")
@function_app.schedule(
    schedule=host_vulnerability_csv_cron_schedule,
    run_on_startup=False,
    use_monitor=True,
)
def export_host_vulnerability_csv():
    """
    Gets host vulnerability data from Prisma and cleans up for exporting to CSV.

    Parameters:
        None

    Returns:
        None

    """
    host_vulnerability_csv_name = os.getenv("HOST_VULNERABILITY_CSV_NAME")
    host_vulnerability_fields_of_interest = json.loads(
        os.getenv("HOST_VULNERABILITY_FIELDS_OF_INTEREST")
    )
    file_path = f"CSVs/{host_vulnerability_csv_name}"
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    host_vulnerability_fields = [
        "_id",
        "type",
        "hostname",
        "scanTime",
        "binaries",
        "Secrets",
        "startupBinaries",
        "osDistro",
        "osDistroVersion",
        "osDistroRelease",
        "distro",
        "packages",
        "files",
        "packageManager",
        "applications",
        "isARM64",
        "packageCorrelationDone",
        "image",
        "history",
        "complianceIssues",
        "allCompliance",
        "repoTag",
        "tags",
        "repoDigests",
        "creationTime",
        "pushTime",
        "vulnerabilitiesCount",
        "complianceIssuesCount",
        "vulnerabilityDistribution",
        "complianceDistribution",
        "vulnerabilityRiskScore",
        "complianceRiskScore",
        "k8sClusterAddr",
        "riskFactors",
        "labels",
        "installedProducts",
        "scanVersion",
        "scanBuildDate",
        "hostDevices",
        "firstScanTime",
        "cloudMetadata",
        "clusters",
        "instances",
        "hosts",
        "err",
        "collections",
        "scanID",
        "trustStatus",
        "firewallProtection",
        "appEmbedded",
        "wildFireUsage",
        "agentless",
        "text",
        "id",
        "severity",
        "cvss",
        "status",
        "cve",
        "cause",
        "description",
        "title",
        "vecStr",
        "exploit",
        "link",
        "packageName",
        "packageVersion",
        "layerTime",
        "templates",
        "twistlock",
        "cri",
        "published",
        "fixDate",
        "applicableRules",
        "discovered",
        "binaryPkgs",
        "vulnTagInfos",
        "functionLayer",
    ]

    ###########################################################################
    # Generate Prisma Token

    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    ###########################################################################
    # Delete the CSV file if it exists from a previous run

    try:
        os.remove(file_path)
    except FileNotFoundError:
        pass

    ###########################################################################
    # Get hosts from Prisma and write to CSV

    end_of_page = False
    new_file = True
    offset = 0
    page_limit = 50

    while not end_of_page:
        host_response, status_code = prisma_get_host_scan_results(
            prisma_token, offset=offset, limit=page_limit
        )

        if status_code == 200:
            if host_response:
                ###############################################################
                # Flatten vulnerability list for each host
                vulnerability_list = list()

                for host in host_response:
                    if "vulnerabilities" in host:
                        if host["vulnerabilities"]:
                            for vuln in host["vulnerabilities"]:
                                # Grab base host information
                                vulnerability_dict = {
                                    key: value
                                    for key, value in host.items()
                                    if (key in host_vulnerability_fields_of_interest)
                                }

                                # Add the individual vulnerability information
                                vulnerability_dict.update(
                                    {
                                        key: value
                                        for key, value in vuln.items()
                                        if (
                                            key in host_vulnerability_fields_of_interest
                                        )
                                    }
                                )

                                vulnerability_list.append(vulnerability_dict)

                ###############################################################
                # Write to CSV
                write_data_to_csv(
                    file_path, vulnerability_list, host_vulnerability_fields, new_file
                )
                new_file = False

                offset += page_limit
            else:
                end_of_page = True
                break
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
        else:
            logger.error("API returned %s.", status_code)


@function_app.function_name(name="export_image_vulnerability_csv")
@function_app.schedule(
    schedule=image_vulnerability_csv_cron_schedule,
    run_on_startup=False,
    use_monitor=True,
)
def export_image_vulnerability_csv():
    """
    Gets container and image data from Prisma and transforms to
        create image vulnerability relevant data.

    Parameters:
        None

    Returns:
        None

    """
    IMAGE_VULNERABILITY_CSV_NAME = os.getenv("IMAGE_VULNERABILITY_CSV_NAME")
    COLLECTIONS_FILTER = ", ".join(json.loads(os.getenv("COLLECTIONS_FILTER")))
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    file_path = f"CSVs/{IMAGE_VULNERABILITY_CSV_NAME}"
    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    ###########################################################################
    # Get collection IDs for image vulnerability correlation

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
    # Get images from Prisma to extract vulnerabilities

    end_of_page = False
    offset = 0
    LIMIT = 50

    images_data = list()

    while not end_of_page:
        images_response, status_code = prisma_get_images_scan_results(
            prisma_token, offset=offset, limit=LIMIT
        )

        if status_code == 200:
            if images_response:
                images_data += [image for image in images_response]
            else:
                end_of_page = True

            offset += LIMIT
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
        else:
            logger.error("API returned %s.", status_code)

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

    field_names = [key for key in csv_rows[0].keys()]

    write_data_to_csv(file_path, csv_rows, field_names, new_file=True)


@function_app.function_name(name="export_registry_image_vulnerability_csv")
@function_app.schedule(
    schedule=registry_image_vulnerability_csv_cron_schedule,
    run_on_startup=False,
    use_monitor=True,
)
def export_registry_image_vulnerability_csv():
    """
    Gets registry image data from Prisma and export to CSV.

    Parameters:
        None

    Returns:
        None

    """
    registry_image_blobstore_vulnerability_csv_name = os.getenv(
        "REGISTRY_IMAGE_VULNERABILITY_CSV_NAME"
    )
    registry_image_blobstore_vulnerability_fields_of_interest = json.loads(
        os.getenv("REGISTRY_IMAGE_VULNERABILITY_FIELDS_OF_INTEREST")
    )
    file_path = f"CSVs/{registry_image_blobstore_vulnerability_csv_name}"
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    registry_image_csv_fields = [
        "osDistroVersion",
        "complianceIssues",
        "exploit",
        "isARM64",
        "vulnerabilityDistribution",
        "cvss",
        "hostname",
        "severity",
        "type",
        "discovered",
        "cause",
        "riskFactors",
        "applicableRules",
        "vulnerabilitiesCount",
        "packages",
        "complianceRiskScore",
        "agentless",
        "packageName",
        "scanTime",
        "firewallProtection",
        "packageCorrelationDone",
        "complianceDistribution",
        "layers",
        "cri",
        "allCompliance",
        "twistlock",
        "binaryPkgs",
        "vulnerabilityRiskScore",
        "scanVersion",
        "hosts",
        "text",
        "id",
        "layerTime",
        "registryType",
        "packageManager",
        "templates",
        "collections",
        "trustStatus",
        "vecStr",
        "complianceIssuesCount",
        "status",
        "title",
        "cve",
        "scanBuildDate",
        "appEmbedded",
        "wildFireUsage",
        "osDistro",
        "cloudMetadata",
        "_id",
        "osDistroRelease",
        "startupBinaries",
        "installedProducts",
        "scanID",
        "published",
        "Secrets",
        "image",
        "applications",
        "link",
        "files",
        "repoTag",
        "creationTime",
        "distro",
        "description",
        "binaries",
        "fixDate",
        "firstScanTime",
        "packageVersion",
        "repoDigests",
        "pushTime",
        "err",
        "functionLayer",
        "history",
        "topLayer",
        "instances",
        "tags",
        "labels",
        "exploits",
        "vulnTagInfos",
    ]

    ###########################################################################
    # Generate Prisma Token

    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    ###########################################################################
    # Delete the CSV file if it exists from a previous run

    try:
        os.remove(file_path)
    except FileNotFoundError:
        pass

    ###########################################################################
    # Get hosts from Prisma and write to CSV

    end_of_page = False
    new_file = True
    offset = 0
    page_limit = 50

    while not end_of_page:
        (
            registry_image_response,
            status_code,
        ) = prisma_get_registry_image_scan_results(
            prisma_token, offset=offset, limit=page_limit
        )

        if status_code == 200:
            if registry_image_response:
                ###############################################################
                # Flatten vulnerability list for each blob
                vulnerability_list = list()

                for registry_image in registry_image_response:
                    if "vulnerabilities" in registry_image:
                        if registry_image["vulnerabilities"]:
                            for vuln in registry_image["vulnerabilities"]:
                                # Grab base host information
                                vulnerability_dict = {
                                    key: value
                                    for key, value in registry_image.items()
                                    if (
                                        key
                                        in registry_image_blobstore_vulnerability_fields_of_interest
                                    )
                                }

                                # Add the individual vulnerability information
                                vulnerability_dict.update(
                                    {
                                        key: value
                                        for key, value in vuln.items()
                                        if (
                                            key
                                            in registry_image_blobstore_vulnerability_fields_of_interest
                                        )
                                    }
                                )

                                vulnerability_list.append(vulnerability_dict)

                ###############################################################
                # Write to CSV
                write_data_to_csv(
                    file_path, vulnerability_list, registry_image_csv_fields, new_file
                )
                new_file = False

                offset += page_limit
            else:
                end_of_page = True
                break
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)


@function_app.function_name(name="export_tanzu_blobstore_vulnerability_csv")
@function_app.schedule(
    schedule=tanzu_blobstore_vulnerability_csv_cron_schedule,
    run_on_startup=False,
    use_monitor=True,
)
def export_tanzu_blobstore_vulnerability_csv():
    """
    Gets tanzu blobstore data from Prisma and cleans up for exporting to CSV.

    Parameters:
        None

    Returns:
        None

    """
    tanzu_blobstore_vulnerability_csv_name = os.getenv(
        "TANZU_BLOBSTORE_VULNERABILITY_CSV_NAME"
    )
    tanzu_blobstore_vulnerability_fields_of_interest = json.loads(
        os.getenv("TANZU_BLOBSTORE_VULNERABILITY_FIELDS_OF_INTEREST")
    )
    file_path = f"CSVs/{tanzu_blobstore_vulnerability_csv_name}"
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    tanzu_csv_fields = [
        "packageCorrelationDone",
        "firstScanTime",
        "riskFactors",
        "packageName",
        "status",
        "cvss",
        "startupBinaries",
        "_id",
        "collections",
        "packageVersion",
        "packageManager",
        "scanTime",
        "link",
        "history",
        "osDistro",
        "distro",
        "pushTime",
        "binaries",
        "cause",
        "twistlock",
        "applications",
        "image",
        "isARM64",
        "repoDigests",
        "title",
        "discovered",
        "functionLayer",
        "labels",
        "cri",
        "creationTime",
        "Secrets",
        "complianceRiskScore",
        "tags",
        "files",
        "layerTime",
        "repoTag",
        "exploit",
        "complianceIssuesCount",
        "installedProducts",
        "type",
        "fixDate",
        "osDistroVersion",
        "id",
        "complianceIssues",
        "vecStr",
        "cve",
        "cloudMetadata",
        "applicableRules",
        "text",
        "osDistroRelease",
        "complianceDistribution",
        "description",
        "hostname",
        "templates",
        "packages",
        "allCompliance",
        "vulnerabilitiesCount",
        "vulnerabilityRiskScore",
        "published",
        "vulnerabilityDistribution",
        "severity",
        "resourceGroupName",
        "version",
        "runtime",
        "cloudControllerAddress",
        "applicationName",
        "handler",
        "provider",
        "lastModified",
        "memory",
        "architecture",
        "name",
        "timeout",
        "defended",
        "scannerVersion",
        "defenderLayerARN",
        "hash",
        "accountID",
        "region",
        "exploits",
    ]

    ###########################################################################
    # Generate Prisma Token

    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    ###########################################################################
    # Delete the CSV file if it exists from a previous run

    try:
        os.remove(file_path)
    except FileNotFoundError:
        pass

    ###########################################################################
    # Get hosts from Prisma and write to CSV

    end_of_page = False
    new_file = True
    offset = 0
    page_limit = 50

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
                # Flatten vulnerability list for each blob
                vulnerability_list = list()

                for blob in tanzu_blobstore_response:
                    if "vulnerabilities" in blob:
                        if blob["vulnerabilities"]:
                            for vuln in blob["vulnerabilities"]:
                                # Grab base host information
                                vulnerability_dict = {
                                    key: value
                                    for key, value in blob.items()
                                    if (
                                        key
                                        in tanzu_blobstore_vulnerability_fields_of_interest
                                    )
                                }

                                # Add the individual vulnerability information
                                vulnerability_dict.update(
                                    {
                                        key: value
                                        for key, value in vuln.items()
                                        if (
                                            key
                                            in tanzu_blobstore_vulnerability_fields_of_interest
                                        )
                                    }
                                )

                                vulnerability_list.append(vulnerability_dict)

                ###############################################################
                # Write to CSV
                write_data_to_csv(
                    file_path, vulnerability_list, tanzu_csv_fields, new_file
                )
                new_file = False

                offset += page_limit
            else:
                end_of_page = True
                break
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)


@function_app.function_name(name="export_tas_vulnerability_csv")
@function_app.schedule(
    schedule=tas_vulnerability_csv_cron_schedule,
    run_on_startup=False,
    use_monitor=True,
)
def export_tas_vulnerability_csv():
    """
    Gets tanzu application service data from Prisma and export to CSV.

    Parameters:
        None

    Returns:
        None

    """
    tas_collections = ", ".join(json.loads(os.getenv("TAS_COLLECTIONS")))
    tas_blobstore_vulnerability_csv_name = os.getenv("TAS_VULNERABILITY_CSV_NAME")
    tas_blobstore_vulnerability_fields_of_interest = json.loads(
        os.getenv("TAS_VULNERABILITY_FIELDS_OF_INTEREST")
    )
    file_path = f"CSVs/{tas_blobstore_vulnerability_csv_name}"
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    tas_csv_fields = [
        "labels",
        "type",
        "appEmbedded",
        "description",
        "firewallProtection",
        "clusters",
        "hostname",
        "scanVersion",
        "tags",
        "scanBuildDate",
        "Secrets",
        "binaries",
        "packageCorrelationDone",
        "layerTime",
        "scanTime",
        "wildFireUsage",
        "twistlock",
        "packages",
        "published",
        "_id",
        "complianceIssues",
        "distro",
        "text",
        "repoDigests",
        "hosts",
        "scanID",
        "vulnerabilitiesCount",
        "packageName",
        "isARM64",
        "id",
        "allCompliance",
        "status",
        "err",
        "severity",
        "cri",
        "functionLayer",
        "osDistro",
        "osDistroRelease",
        "creationTime",
        "cloudMetadata",
        "layers",
        "collections",
        "cause",
        "topLayer",
        "packageVersion",
        "exploit",
        "applicableRules",
        "trustStatus",
        "vulnerabilityRiskScore",
        "repoTag",
        "vulnerabilityDistribution",
        "vecStr",
        "instances",
        "title",
        "complianceDistribution",
        "firstScanTime",
        "cvss",
        "startupBinaries",
        "image",
        "link",
        "riskFactors",
        "pushTime",
        "complianceRiskScore",
        "files",
        "history",
        "agentless",
        "installedProducts",
        "complianceIssuesCount",
        "cve",
        "templates",
        "fixDate",
        "discovered",
        "osDistroVersion",
        "packageManager",
        "binaryPkgs",
        "exploits",
        "applications",
        "vulnTagInfos",
        "missingDistroVulnCoverage",
        "namespaces",
        "externalLabels",
        "rhelRepos",
        "gracePeriodDays",
        "block",
        "twistlockImage",
    ]

    ###########################################################################
    # Generate Prisma Token

    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    ###########################################################################
    # Delete the CSV file if it exists from a previous run

    try:
        os.remove(file_path)
    except FileNotFoundError:
        pass

    ###########################################################################
    # Get hosts from Prisma and write to CSV

    end_of_page = False
    new_file = True
    offset = 0
    page_limit = 50

    while not end_of_page:
        (
            tas_response,
            status_code,
        ) = prisma_get_images_scan_results(
            prisma_token, offset=offset, limit=page_limit, collection=tas_collections
        )

        if status_code == 200:
            if tas_response:
                ###############################################################
                # Flatten vulnerability list for each blob
                vulnerability_list = list()

                for tas in tas_response:
                    if "vulnerabilities" in tas:
                        if tas["vulnerabilities"]:
                            for vuln in tas["vulnerabilities"]:
                                # Grab base host information
                                vulnerability_dict = {
                                    key: value
                                    for key, value in tas.items()
                                    if (
                                        key
                                        in tas_blobstore_vulnerability_fields_of_interest
                                    )
                                }

                                # Add the individual vulnerability information
                                vulnerability_dict.update(
                                    {
                                        key: value
                                        for key, value in vuln.items()
                                        if (
                                            key
                                            in tas_blobstore_vulnerability_fields_of_interest
                                        )
                                    }
                                )

                                vulnerability_list.append(vulnerability_dict)

                ###############################################################
                # Write to CSV
                write_data_to_csv(
                    file_path, vulnerability_list, tas_csv_fields, new_file
                )
                new_file = False

                offset += page_limit
            else:
                end_of_page = True
                break
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
