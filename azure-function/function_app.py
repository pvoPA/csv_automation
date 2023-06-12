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
import datetime as dt
import azure.functions as func
from helpers import generate_prisma_token
from helpers import write_data_to_csv
from helpers import prisma_get_containers_scan_results
from helpers import prisma_get_host_scan_results
from helpers import prisma_get_images_scan_results
from helpers import prisma_get_registry_image_scan_results
from helpers import prisma_get_tanzu_blob_store_scan_results

function_app = func.FunctionApp()


@function_app.function_name(name="export_openshift_applications_csv")
@app.route(route="export_openshift_applications_csv")
def export_openshift_applications_csv(req: func.HttpRequest):
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

    return func.HttpResponse("This HTTP triggered function executed successfully.")


@function_app.function_name(name="export_openshift_containers_csv")
@app.route(route="export_openshift_containers_csv")
def export_openshift_containers_csv(req: func.HttpRequest):
    """
    Gets container data from Prisma and transforms for CSV friendly data.

    Parameters:
        None

    Returns:
        None

    """
    containers_csv_name = os.getenv("OPENSHIFT_CONTAINERS_CSV_NAME")
    collections_filter = ", ".join(
        json.loads(os.getenv("OPENSHIFT_COLLECTIONS_FILTER"))
    )
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

    write_data_to_csv(file_path, csv_rows, csv_fields, new_file=True)

    return func.HttpResponse("This HTTP triggered function executed successfully.")


@function_app.function_name(name="export_openshift_image_vulnerability_csv")
@app.route(route="export_openshift_image_vulnerability_csv")
def export_openshift_image_vulnerability_csv(req: func.HttpRequest):
    """
    Gets container and image data from Prisma and transforms to
        create image vulnerability relevant data.

    Parameters:
        None

    Returns:
        None

    """
    todays_date = str(dt.datetime.today()).split()[0]
    IMAGE_VULNERABILITY_CSV_NAME = os.getenv("IMAGE_VULNERABILITY_CSV_NAME")
    COLLECTIONS_FILTER = ", ".join(
        json.loads(os.getenv("OPENSHIFT_COLLECTIONS_FILTER"))
    )
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")
    csv_fields = [
        "Incremental_ID",
        "Container_ID",
        "Image_ID",
        "CVE",
        "CVSS_Score",
        "Severity",
        "Fix_Status",
        "Package_Name",
        "Package_Path",
        "Time_Discovered",
    ]
    file_path = f"CSVs/{IMAGE_VULNERABILITY_CSV_NAME}_{todays_date}.csv"
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

    ############################################################################################################################################
    # Create the rows for CSV creation

    incremental_id = 0

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

    write_data_to_csv(file_path, csv_rows, csv_fields, new_file=True)

    return func.HttpResponse("This HTTP triggered function executed successfully.")


# @function_app.function_name(name="export_host_containers_csv")
# @function_app.schedule(
#     arg_name="timer",
#     schedule=openshift_applications_csv_cron_schedule,
#     run_on_startup=False,
#     use_monitor=True,
# )
# def export_host_containers_csv(req: func.HttpRequest):
#     """
#     Gets container data from Prisma and transforms for CSV friendly data.

#     Parameters:
#         None

#     Returns:
#         None

#     """
#     containers_csv_name = os.getenv("HOST_CONTAINERS_CSV_NAME")
#     collections_filter = ", ".join(json.loads(os.getenv("HOST_COLLECTIONS_FILTER")))
#     csv_fields = [
#         "Namespace",
#         "Container_Name",
#         "Host_Name",
#         "Collection",
#         "Container_ID",
#         "Account_ID",
#         "Cluster",
#         "Image_ID",
#     ]
#     todays_date = str(dt.datetime.today()).split()[0]
#     prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
#     prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

#     file_path = f"CSVs/{containers_csv_name}_{todays_date}.csv"
#     prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

#     ##########################################################################
#     # Grab containers data from Prisma

#     end_of_page = False
#     offset = 0
#     LIMIT = 50

#     containers_data = list()

#     while not end_of_page:
#         containers_response, status_code = prisma_get_containers_scan_results(
#             prisma_token, offset=offset, limit=LIMIT, collection=collections_filter
#         )

#         if status_code == 200:
#             if containers_response:
#                 containers_data += [container for container in containers_response]
#             else:
#                 end_of_page = True

#             offset += LIMIT
#         elif status_code == 401:
#             logger.error("Prisma token timed out, generating a new one and continuing.")

#             prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
#         else:
#             logger.error("API returned %s.", status_code)

#     csv_rows = list()

#     ###########################################################################
#     # Transform and grab fields of interest

#     if containers_data:
#         for container in containers_data:
#             # Constant fields
#             # Key = CSV Column Name, Value = JSON field
#             for collection in container["collections"]:
#                 row_dict = {
#                     "Container_ID": container["info"]["id"],
#                     "Container_Name": container["info"]["name"],
#                     "Image_ID": container["info"]["imageID"],
#                     "Host_Name": container["hostname"],
#                     "Account_ID": container["info"]["cloudMetadata"]["accountID"],
#                     "Collection": collection,
#                 }

#                 # Variable fields
#                 if "namespace" in container["info"]:
#                     row_dict.update({"Namespace": container["info"]["namespace"]})
#                 else:
#                     row_dict.update({"Namespace": ""})

#                 if "cluster" in container["info"]:
#                     row_dict.update({"Cluster": container["info"]["cluster"]})
#                 else:
#                     row_dict.update({"Cluster": ""})

#                 csv_rows.append(row_dict)

#     write_data_to_csv(file_path, csv_rows, csv_fields, new_file=True)


@function_app.function_name(name="export_host_applications_csv")
@app.route(route="export_host_applications_csv")
def export_host_applications_csv(req: func.HttpRequest):
    """
    Gets host data from Prisma and clean up for exporting to applications CSV.

    Parameters:
        None

    Returns:
        None

    """
    todays_date = str(dt.datetime.today()).split()[0]
    COLLECTIONS_FILTER = ", ".join(json.loads(os.getenv("HOST_COLLECTIONS_FILTER")))
    host_application_csv_name = os.getenv("HOST_APPLICATION_CSV_NAME")
    host_application_fields_of_interest = json.loads(
        os.getenv("HOST_APPLICATION_FIELDS_OF_INTEREST")
    )
    file_path = f"CSVs/{host_application_csv_name}_{todays_date}.csv"
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")
    external_labels_to_include = json.loads(
        os.getenv("HOST_EXTERNAL_LABELS_TO_INCLUDE")
    )
    host_application_fields = [
        "Incremental_ID",
        "repoTag",
        "firewallProtection",
        "history",
        "creationTime",
        "packageManager",
        "complianceIssuesCount",
        "collections",
        "pushTime",
        "scanBuildDate",
        "osDistro",
        "labels",
        "scanVersion",
        "hostDevices",
        "err",
        "packageCorrelationDone",
        "scanID",
        "firstScanTime",
        "complianceDistribution",
        "startupBinaries",
        "vulnerabilityRiskScore",
        "image",
        "agentless",
        "tags",
        "appEmbedded",
        "wildFireUsage",
        "trustStatus",
        "hosts",
        "Secrets",
        "vulnerabilitiesCount",
        "type",
        "riskFactors",
        "osDistroRelease",
        "applications",
        "isARM64",
        "distro",
        "vulnerabilityDistribution",
        "complianceRiskScore",
        "allCompliance",
        "binaries",
        "instances",
        "files",
        "installedProducts",
        "scanTime",
        "complianceIssues",
        "cloudMetadata",
        "hostname",
        "_id",
        "packages",
        "osDistroVersion",
        "repoDigests",
        "externalLabels",
        "rhelRepos",
        "clusters",
        "k8sClusterAddr",
        "stopped",
        "ecsClusterName",
    ]

    for external_label in external_labels_to_include:
        host_application_fields.append(external_label)

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
    # Get hosts from Prisma

    end_of_page = False
    new_file = True
    offset = 0
    incremental_id = 0
    page_limit = 50

    while not end_of_page:
        host_list = list()

        host_response, status_code = prisma_get_host_scan_results(
            prisma_token, offset=offset, limit=page_limit, collection=COLLECTIONS_FILTER
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
                write_data_to_csv(
                    file_path, host_list, host_application_fields, new_file
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

    return func.HttpResponse("This HTTP triggered function executed successfully.")


@function_app.function_name(name="export_host_vulnerability_csv")
@app.route(route="export_host_vulnerability_csv")
def export_host_vulnerability_csv(req: func.HttpRequest):
    """
    Gets host vulnerability data from Prisma and cleans up for exporting to CSV.

    Parameters:
        None

    Returns:
        None

    """
    todays_date = str(dt.datetime.today()).split()[0]
    COLLECTIONS_FILTER = ", ".join(json.loads(os.getenv("HOST_COLLECTIONS_FILTER")))
    host_vulnerability_csv_name = os.getenv("HOST_VULNERABILITY_CSV_NAME")
    host_vulnerability_fields_of_interest = json.loads(
        os.getenv("HOST_VULNERABILITY_FIELDS_OF_INTEREST")
    )
    file_path = f"CSVs/{host_vulnerability_csv_name}_{todays_date}.csv"
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")
    host_vulnerability_fields = [
        "Incremental_ID",
        "Resource_ID",
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
        "Package_Path",
        "Incremental_ID",
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
    # Get hosts from Prisma

    end_of_page = False
    new_file = True
    offset = 0
    incremental_id = 0
    page_limit = 50

    while not end_of_page:
        vulnerability_list = list()

        host_response, status_code = prisma_get_host_scan_results(
            prisma_token, offset=offset, limit=page_limit, collection=COLLECTIONS_FILTER
        )

        if status_code == 200:
            if host_response:
                ###############################################################
                # Flatten vulnerability list for each host
                for host in host_response:
                    if "vulnerabilities" in host:
                        if host["vulnerabilities"]:
                            for vuln in host["vulnerabilities"]:
                                # Add the individual vulnerability information
                                vulnerability_dict = {
                                    key: value
                                    for key, value in vuln.items()
                                    if (key in host_vulnerability_fields_of_interest)
                                }

                                vulnerability_dict.update({"Resource_ID": host["_id"]})

                                # Get the package info and install path
                                PACKAGE_NAME = vuln["packageName"]
                                PACKAGE_VERSION = vuln["packageVersion"]
                                PACKAGE_PATH = "NOT_AVAILABLE"

                                package_found = False

                                if PACKAGE_NAME:
                                    for package_type in host["packages"]:
                                        for package in package_type["pkgs"]:
                                            if (
                                                package["name"] == PACKAGE_NAME
                                                and package["version"]
                                                == PACKAGE_VERSION
                                            ):
                                                if "path" in package:
                                                    PACKAGE_PATH = package["path"]
                                                package_found = True
                                                break

                                    # Check "applications" field for package path
                                    if not package_found:
                                        if "applications" in host:
                                            for app in host["applications"]:
                                                if (
                                                    app["name"] == PACKAGE_NAME
                                                    and app["version"]
                                                    == PACKAGE_VERSION
                                                ):
                                                    PACKAGE_PATH = app["path"]
                                                    package_found = True
                                                    break

                                    # Check "binaries" field for package path
                                    if not package_found:
                                        if "binaries" in host:
                                            for binary in host["binaries"]:
                                                if binary["name"] == PACKAGE_NAME:
                                                    PACKAGE_PATH = binary["path"]
                                                    package_found = True
                                                    break

                                    # Check "startupBinaries" field for package path
                                    if not package_found:
                                        if "binaries" in host:
                                            for binary in host["binaries"]:
                                                if binary["name"] == PACKAGE_NAME:
                                                    PACKAGE_PATH = binary["path"]
                                                    package_found = True
                                                    break

                                if package_found:
                                    vulnerability_dict["Package_Path"] = PACKAGE_PATH

                                vulnerability_dict.update(
                                    {"Incremental_ID": incremental_id}
                                )

                                vulnerability_list.append(vulnerability_dict)

                                incremental_id += 1

                ##############################################################
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

    return func.HttpResponse("This HTTP triggered function executed successfully.")


@function_app.function_name(name="export_tas_containers_csv")
@app.route(route="export_tas_containers_csv")
def export_tas_containers_csv(req: func.HttpRequest):
    """
    Gets container data from Prisma and transforms for CSV friendly data.

    Parameters:
        None

    Returns:
        None

    """
    containers_csv_name = os.getenv("TAS_CONTAINERS_CSV_NAME")
    collections_filter = ", ".join(json.loads(os.getenv("TAS_COLLECTIONS_FILTER")))
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

    write_data_to_csv(file_path, csv_rows, csv_fields, new_file=True)

    return func.HttpResponse("This HTTP triggered function executed successfully.")


@function_app.function_name(name="export_tas_vulnerability_csv")
@app.route(route="export_tas_vulnerability_csv")
def export_tas_vulnerability_csv(req: func.HttpRequest):
    """
    Gets tanzu application service data from Prisma and export to CSV.

    Parameters:
        None

    Returns:
        None

    """
    todays_date = str(dt.datetime.today()).split()[0]
    COLLECTIONS_FILTER = ", ".join(json.loads(os.getenv("TAS_COLLECTIONS_FILTER")))
    tas_blobstore_vulnerability_csv_name = os.getenv("TAS_VULNERABILITY_CSV_NAME")
    tas_blobstore_vulnerability_fields_of_interest = json.loads(
        os.getenv("TAS_VULNERABILITY_FIELDS_OF_INTEREST")
    )

    file_path = f"CSVs/{tas_blobstore_vulnerability_csv_name}_{todays_date}.csv"
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")
    external_labels_to_include = json.loads(os.getenv("TAS_EXTERNAL_LABELS_TO_INCLUDE"))

    tas_csv_fields = [
        "Incremental_ID",
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
        "Package_Path",
        "Incremental_ID",
    ]

    for external_label in external_labels_to_include:
        tas_csv_fields.append(external_label)

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
    # Get images from Prisma and write to CSV

    end_of_page = False
    new_file = True
    offset = 0
    page_limit = 50
    tas_vulnerability_dict = dict()

    while not end_of_page:
        (
            tas_response,
            status_code,
        ) = prisma_get_images_scan_results(
            prisma_token,
            offset=offset,
            limit=page_limit,
            collection=COLLECTIONS_FILTER,
        )

        if status_code == 200:
            if tas_response:
                ###############################################################
                # Flatten vulnerability list for each blob
                for tas in tas_response:
                    external_labels = dict()
                    if "externalLabels" in tas:
                        for external_label in tas["externalLabels"]:
                            if external_label["key"] in external_labels_to_include:
                                external_labels.update(
                                    {external_label["key"]: external_label["value"]}
                                )
                    if "vulnerabilities" in tas:
                        if tas["vulnerabilities"]:
                            for vuln in tas["vulnerabilities"]:
                                vulnerability_dict = {"resourceID": tas["_id"]}

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

                                # Get the package info and install path
                                PACKAGE_NAME = vuln["packageName"]
                                PACKAGE_VERSION = vuln["packageVersion"]
                                PACKAGE_PATH = "NOT_AVAILABLE"

                                package_found = False

                                if PACKAGE_NAME:
                                    for package_type in tas["packages"]:
                                        for package in package_type["pkgs"]:
                                            if (
                                                package["name"] == PACKAGE_NAME
                                                and package["version"]
                                                == PACKAGE_VERSION
                                            ):
                                                if "path" in package:
                                                    PACKAGE_PATH = package["path"]
                                                package_found = True
                                                break

                                    # Check "applications" field for package path
                                    if not package_found:
                                        if "applications" in tas:
                                            for app in tas["applications"]:
                                                if (
                                                    app["name"] == PACKAGE_NAME
                                                    and app["version"]
                                                    == PACKAGE_VERSION
                                                ):
                                                    PACKAGE_PATH = app["path"]
                                                    package_found = True
                                                    break

                                    # Check "binaries" field for package path
                                    if not package_found:
                                        if "binaries" in tas:
                                            for binary in tas["binaries"]:
                                                if binary["name"] == PACKAGE_NAME:
                                                    PACKAGE_PATH = binary["path"]
                                                    package_found = True
                                                    break

                                    # Check "startupBinaries" field for package path
                                    if not package_found:
                                        if "binaries" in tas:
                                            for binary in tas["binaries"]:
                                                if binary["name"] == PACKAGE_NAME:
                                                    PACKAGE_PATH = binary["path"]
                                                    package_found = True
                                                    break

                                if package_found:
                                    vulnerability_dict["Package_Path"] = PACKAGE_PATH

                                if tas["_id"] in tas_vulnerability_dict:
                                    tas_vulnerability_dict[tas["_id"]].append(
                                        vulnerability_dict
                                    )
                                else:
                                    tas_vulnerability_dict.update(
                                        {tas["_id"]: [vulnerability_dict]}
                                    )

                ###############################################################
                # Write to CSV
                # write_data_to_csv(
                #     file_path, vulnerability_list, tas_csv_fields, new_file
                # )
                # new_file = False

                offset += page_limit
            else:
                end_of_page = True
                break
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
        else:
            logger.error("API returned %s.", status_code)

    ###########################################################################
    # Get collection IDs for TAS vulnerability correlation and write to CSV

    end_of_page = False
    offset = 0
    LIMIT = 50
    incremental_id = 0
    new_file = True

    while not end_of_page:
        containers_response, status_code = prisma_get_containers_scan_results(
            prisma_token, offset=offset, limit=LIMIT, collection=COLLECTIONS_FILTER
        )
        if status_code == 200:
            if containers_response:
                csv_rows = list()

                for container in containers_response:
                    IMAGE_ID = container["info"]["imageID"]
                    if IMAGE_ID in tas_vulnerability_dict:
                        for vuln in tas_vulnerability_dict[IMAGE_ID]:
                            vuln.update({"Incremental_ID": incremental_id})

                            csv_rows.append(vuln)

                            incremental_id += 1

                        # remove the image ID as it's already been added to the CSV
                        tas_vulnerability_dict.pop(IMAGE_ID)

                write_data_to_csv(file_path, csv_rows, tas_csv_fields, new_file)
                new_file = False
            else:
                end_of_page = True

            offset += LIMIT
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
        else:
            logger.error("API returned %s.", status_code)

    return func.HttpResponse("This HTTP triggered function executed successfully.")


@function_app.function_name(name="export_tas_application_csv")
@app.route(route="export_tas_application_csv")
def export_tas_application_csv(req: func.HttpRequest):
    """
    Gets tanzu application service data from Prisma and export to CSV.

    Parameters:
        None

    Returns:
        None

    """
    todays_date = str(dt.datetime.today()).split()[0]
    COLLECTIONS_FILTER = ", ".join(json.loads(os.getenv("TAS_COLLECTIONS_FILTER")))
    tas_blobstore_application_csv_name = os.getenv("TAS_APPLICATION_CSV_NAME")
    tas_blobstore_application_fields_of_interest = json.loads(
        os.getenv("TAS_APPLICATION_FIELDS_OF_INTEREST")
    )

    file_path = f"CSVs/{tas_blobstore_application_csv_name}_{todays_date}.csv"
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")
    external_labels_to_include = json.loads(os.getenv("TAS_EXTERNAL_LABELS_TO_INCLUDE"))

    tas_csv_fields = [
        "Incremental_ID",
        "osDistroVersion",
        "packageCorrelationDone",
        "complianceIssues",
        "pushTime",
        "applications",
        "isARM64",
        "hosts",
        "_id",
        "id",
        "startupBinaries",
        "repoTag",
        "appEmbedded",
        "vulnerabilitiesCount",
        "installedProducts",
        "osDistro",
        "scanID",
        "err",
        "scanVersion",
        "collections",
        "allCompliance",
        "firstScanTime",
        "vulnerabilityDistribution",
        "firewallProtection",
        "wildFireUsage",
        "scanTime",
        "tags",
        "complianceDistribution",
        "instances",
        "osDistroRelease",
        "packageManager",
        "complianceIssuesCount",
        "hostname",
        "agentless",
        "vulnerabilityRiskScore",
        "type",
        "complianceRiskScore",
        "clusters",
        "Secrets",
        "image",
        "cloudMetadata",
        "trustStatus",
        "distro",
        "creationTime",
        "repoDigests",
        "binaries",
        "packages",
        "files",
        "riskFactors",
        "history",
    ]

    for external_label in external_labels_to_include:
        tas_csv_fields.append(external_label)

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
    # Get images from Prisma and write to CSV

    end_of_page = False
    new_file = True
    offset = 0
    page_limit = 50
    tas_application_dict = dict()

    while not end_of_page:
        (
            tas_response,
            status_code,
        ) = prisma_get_images_scan_results(
            prisma_token, offset=offset, limit=page_limit, collection=COLLECTIONS_FILTER
        )

        if status_code == 200:
            if tas_response:
                ###############################################################
                # Flatten application list for each blob
                for tas in tas_response:
                    external_labels = dict()
                    if "externalLabels" in tas:
                        for external_label in tas["externalLabels"]:
                            if external_label["key"] in external_labels_to_include:
                                external_labels.update(
                                    {external_label["key"]: external_label["value"]}
                                )
                    # Grab base host information
                    vulnerability_dict = {
                        key: value
                        for key, value in tas.items()
                        if (key in tas_blobstore_application_fields_of_interest)
                    }

                    if tas["_id"] in tas_application_dict:
                        tas_application_dict[tas["_id"]].append(vulnerability_dict)
                    else:
                        tas_application_dict.update({tas["_id"]: [vulnerability_dict]})

                offset += page_limit
            else:
                end_of_page = True
                break
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
        else:
            logger.error("API returned %s.", status_code)

    ###########################################################################
    # Get collection IDs for TAS vulnerability correlation and write to CSV

    end_of_page = False
    offset = 0
    LIMIT = 50
    incremental_id = 0
    new_file = True

    while not end_of_page:
        containers_response, status_code = prisma_get_containers_scan_results(
            prisma_token, offset=offset, limit=LIMIT, collection=COLLECTIONS_FILTER
        )
        if status_code == 200:
            if containers_response:
                csv_rows = list()

                for container in containers_response:
                    IMAGE_ID = container["info"]["imageID"]
                    if IMAGE_ID in tas_application_dict:
                        for vuln in tas_application_dict[IMAGE_ID]:
                            vuln.update({"Incremental_ID": incremental_id})

                            csv_rows.append(vuln)

                            incremental_id += 1

                        # remove the image ID as it's already been added to the CSV
                        tas_application_dict.pop(IMAGE_ID)

                write_data_to_csv(file_path, csv_rows, tas_csv_fields, new_file)
                new_file = False
            else:
                end_of_page = True

            offset += LIMIT
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)
        else:
            logger.error("API returned %s.", status_code)

    return func.HttpResponse("This HTTP triggered function executed successfully.")


@function_app.function_name(name="export_nexus_repo_application_csv")
@app.route(route="export_nexus_repo_application_csv")
def export_nexus_repo_application_csv(req: func.HttpRequest):
    """
    Gets registry image data from Prisma and export to CSV.

    Parameters:
        None

    Returns:
        None

    """
    todays_date = str(dt.datetime.today()).split()[0]
    registry_image_blobstore_application_csv_name = os.getenv(
        "REGISTRY_IMAGE_APPLICATION_CSV_NAME"
    )
    registry_image_blobstore_application_fields_of_interest = json.loads(
        os.getenv("REGISTRY_IMAGE_APPLICATION_FIELDS_OF_INTEREST")
    )
    file_path = (
        f"CSVs/{registry_image_blobstore_application_csv_name}_{todays_date}.csv"
    )
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    registry_image_csv_fields = [
        "Incremental_ID",
        "pushTime",
        "startupBinaries",
        "history",
        "vulnerabilitiesCount",
        "wildFireUsage",
        "osDistroVersion",
        "isARM64",
        "repoDigests",
        "packageCorrelationDone",
        "osDistro",
        "repoTag",
        "vulnerabilityRiskScore",
        "installedProducts",
        "files",
        "hosts",
        "firstScanTime",
        "trustStatus",
        "complianceIssuesCount",
        "firewallProtection",
        "complianceRiskScore",
        "collections",
        "Secrets",
        "err",
        "image",
        "riskFactors",
        "complianceIssues",
        "cloudMetadata",
        "allCompliance",
        "scanTime",
        "appEmbedded",
        "creationTime",
        "agentless",
        "packages",
        "_id",
        "complianceDistribution",
        "binaries",
        "packageManager",
        "tags",
        "instances",
        "osDistroRelease",
        "vulnerabilityDistribution",
        "resourceID",
        "type",
        "hostname",
        "id",
        "scanID",
        "registryType",
        "distro",
        "topLayer",
        "scanVersion",
        "scanBuildDate",
        "layers",
        "applications",
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
    # Get registry images from Prisma and write to CSV

    end_of_page = False
    new_file = True
    offset = 0
    incremental_id = 0
    page_limit = 50

    while not end_of_page:
        registry_image_list = list()

        (
            registry_image_response,
            status_code,
        ) = prisma_get_registry_image_scan_results(
            prisma_token, offset=offset, limit=page_limit
        )

        if status_code == 200:
            if registry_image_response:
                ###############################################################
                # Flatten application list for each blob
                repo_application_dict = dict()

                for registry_image in registry_image_response:
                    resource_id = f"{registry_image['repoTag']['repo']}:{registry_image['repoTag']['tag']}"
                    repo_application_dict.update({resource_id: {}})

                    application_dict = {
                        "Incremental_ID": incremental_id,
                        "resourceID": resource_id,
                    }

                    # Add the base application information
                    application_dict.update(
                        {
                            key: value
                            for key, value in registry_image.items()
                            if (
                                key
                                in registry_image_blobstore_application_fields_of_interest
                            )
                        }
                    )

                    registry_image_list.append(application_dict)

                    incremental_id += 1

                ##############################################################
                # Write to CSV
                write_data_to_csv(
                    file_path, registry_image_list, registry_image_csv_fields, new_file
                )
                new_file = False

                offset += page_limit
            else:
                end_of_page = True
                break
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    return func.HttpResponse("This HTTP triggered function executed successfully.")


@function_app.function_name(name="export_nexus_repo_vulnerability_csv")
@app.route(route="export_nexus_repo_vulnerability_csv")
def export_nexus_repo_vulnerability_csv(req: func.HttpRequest):
    """
    Gets registry image data from Prisma and export to CSV.

    Parameters:
        None

    Returns:
        None

    """
    todays_date = str(dt.datetime.today()).split()[0]
    registry_image_blobstore_vulnerability_csv_name = os.getenv(
        "REGISTRY_IMAGE_VULNERABILITY_CSV_NAME"
    )
    registry_image_blobstore_vulnerability_fields_of_interest = json.loads(
        os.getenv("REGISTRY_IMAGE_VULNERABILITY_FIELDS_OF_INTEREST")
    )
    file_path = (
        f"CSVs/{registry_image_blobstore_vulnerability_csv_name}_{todays_date}.csv"
    )
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    registry_image_csv_fields = [
        "Incremental_ID",
        "Resource_ID",
        "riskFactors",
        "twistlock",
        "cri",
        "cve",
        "cvss",
        "fixDate",
        "published",
        "description",
        "resourceID",
        "packageVersion",
        "text",
        "status",
        "functionLayer",
        "vecStr",
        "layerTime",
        "exploit",
        "title",
        "link",
        "type",
        "packageName",
        "templates",
        "applicableRules",
        "discovered",
        "id",
        "binaryPkgs",
        "severity",
        "cause",
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
    # Get registry images from Prisma and write to CSV

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
                repo_vulnerability_dict = dict()

                for registry_image in registry_image_response:
                    if "vulnerabilities" in registry_image:
                        if registry_image["vulnerabilities"]:
                            resource_id = f"{registry_image['repoTag']['repo']}:{registry_image['repoTag']['tag']}"
                            repo_vulnerability_dict.update({resource_id: {}})

                            for vuln in registry_image["vulnerabilities"]:
                                vulnerability_dict = {"Resource_ID": resource_id}

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

                                repo_vulnerability_dict[resource_id].update(
                                    {vuln["cve"]: vulnerability_dict}
                                )

                ###############################################################
                # Write to CSV
                incremental_id = 0
                for repo in repo_vulnerability_dict.items():
                    for vuln in repo_vulnerability_dict[repo[0]].items():
                        vuln[1].update({"Incremental_ID": incremental_id})
                        write_data_to_csv(
                            file_path,
                            [vuln[1]],
                            registry_image_csv_fields,
                            new_file,
                        )
                        new_file = False
                        incremental_id += 1
                offset += page_limit
            else:
                end_of_page = True
                break
        elif status_code == 401:
            logger.error("Prisma token timed out, generating a new one and continuing.")

            prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    return func.HttpResponse("This HTTP triggered function executed successfully.")


@function_app.function_name(name="export_tanzu_blobstore_application_csv")
@app.route(route="export_tanzu_blobstore_application_csv")
def export_tanzu_blobstore_application_csv(req: func.HttpRequest):
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
    file_path = f"CSVs/{tanzu_blobstore_application_csv_name}_{todays_date}.csv"
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    tanzu_csv_fields = [
        "Incremental_ID",
        "packages",
        "creationTime",
        "name",
        "osDistro",
        "accountID",
        "repoTag",
        "complianceRiskScore",
        "repoDigests",
        "osDistroVersion",
        "applications",
        "cloudMetadata",
        "timeout",
        "version",
        "defenderLayerARN",
        "vulnerabilitiesCount",
        "image",
        "packageManager",
        "collections",
        "provider",
        "region",
        "lastModified",
        "tags",
        "riskFactors",
        "id",
        "pushTime",
        "vulnerabilityDistribution",
        "installedProducts",
        "history",
        "labels",
        "complianceIssues",
        "scanTime",
        "binaries",
        "allCompliance",
        "complianceDistribution",
        "defended",
        "hash",
        "complianceIssuesCount",
        "files",
        "scannerVersion",
        "vulnerabilityRiskScore",
        "firstScanTime",
        "type",
        "isARM64",
        "runtime",
        "hostname",
        "distro",
        "Secrets",
        "_id",
        "architecture",
        "osDistroRelease",
        "memory",
        "description",
        "handler",
        "resourceGroupName",
        "cloudControllerAddress",
        "applicationName",
        "startupBinaries",
        "packageCorrelationDone",
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
    # Get blobstore data from Prisma and write to CSV

    end_of_page = False
    new_file = True
    offset = 0
    incremental_id = 0
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
                # Flatten application list for each blob
                application_list = list()

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

                ###############################################################
                # Write to CSV
                write_data_to_csv(
                    file_path, application_list, tanzu_csv_fields, new_file
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

    return func.HttpResponse("This HTTP triggered function executed successfully.")


@function_app.function_name(name="export_tanzu_blobstore_vulnerability_csv")
@app.route(route="export_tanzu_blobstore_vulnerability_csv")
def export_tanzu_blobstore_vulnerability_csv(req: func.HttpRequest):
    """
    Gets tanzu blobstore data from Prisma and cleans up for exporting to CSV.

    Parameters:
        None

    Returns:
        None

    """
    todays_date = str(dt.datetime.today()).split()[0]

    tanzu_blobstore_vulnerability_csv_name = os.getenv(
        "TANZU_BLOBSTORE_VULNERABILITY_CSV_NAME"
    )
    tanzu_blobstore_vulnerability_fields_of_interest = json.loads(
        os.getenv("TANZU_BLOBSTORE_VULNERABILITY_FIELDS_OF_INTEREST")
    )
    file_path = f"CSVs/{tanzu_blobstore_vulnerability_csv_name}_{todays_date}.csv"
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")

    tanzu_csv_fields = [
        "Incremental_ID",
        "Resource_ID",
        "link",
        "description",
        "cri",
        "cvss",
        "templates",
        "vecStr",
        "applicableRules",
        "fixDate",
        "packageVersion",
        "status",
        "twistlock",
        "text",
        "packageName",
        "exploit",
        "layerTime",
        "title",
        "functionLayer",
        "severity",
        "discovered",
        "cve",
        "type",
        "id",
        "cause",
        "published",
        "riskFactors",
        "exploits",
    ]

    ######################################################################################################################
    # Generate Prisma Token

    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    ###########################################################################
    # Delete the CSV file if it exists from a previous run

    try:
        os.remove(file_path)
    except FileNotFoundError:
        pass

    ###########################################################################
    # Get blobstore data from Prisma and write to CSV

    end_of_page = False
    new_file = True
    offset = 0
    incremental_id = 0
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
                                vulnerability_dict = {
                                    "Incremental_ID": incremental_id,
                                    "Resource_ID": blob["_id"],
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
                                incremental_id += 1

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
        else:
            logger.error("API returned %s.", status_code)

    return func.HttpResponse("This HTTP triggered function executed successfully.")
