"""
Exports application data to CSV on
    tanzu application service resources in Prisma Cloud.

This script is used to retrieve application data
    for tanzu application service resources and
    exports it to a CSV file with the following actions,
        - Generate Prisma Token
        - Delete the CSV file if it exists from a previous run
        - Grab tanzu application service scan results
        - For each API call,
            - Flatten application list for each tanzu application service
            - Write to CSV (Create a CSV directory and file.)

Usage:
    python export_tas_application_csv.py

Options:

Requirements:
    - Python 3.10 or higher
    - .env configured with the following variables,
        - PRISMA_ACCESS_KEY
        - PRISMA_SECRET_KEY

Example:
    python export_tas_application_csv.py

Note:
    This script is meant to be deployed in the following platforms,
        - docker container
            - the app directory
        - azure function
            - the azure-function directory
        - aws lambda function
            - the aws-lambda directory
"""
import os
import json
import datetime as dt
from helpers import logger
from helpers import prisma_get_images_scan_results
from helpers import generate_prisma_token
from helpers import write_data_to_csv
from helpers import prisma_get_containers_scan_results


def etl_tas_application_csv():
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


if __name__ == "__main__":
    logger.info("Creating tanzu application service vulnerabilities CSV...")

    etl_tas_application_csv()
