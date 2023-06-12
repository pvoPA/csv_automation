"""
Exports application data to CSV on registry image resources in Prisma Cloud.

This script is used to retrieve application data for registry image resources
and exports it to a CSV file with the following actions,
    - Generate Prisma Token
    - Delete the CSV file if it exists from a previous run
    - Grab registry image scan results
    - For each API call,
        - Flatten application list for each registry image
        - Write to CSV (Create a CSV directory and file.)

Usage:
    python export_registry_image_application_csv.py

Options:

Requirements:
    - Python 3.10 or higher
    - .env configured with the following variables,
        - PRISMA_ACCESS_KEY
        - PRISMA_SECRET_KEY

Example:
    python export_registry_image_application_csv.py

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
from helpers import prisma_get_registry_image_scan_results
from helpers import generate_prisma_token
from helpers import write_data_to_csv


def etl_registry_image_application_csv():
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


if __name__ == "__main__":
    logger.info("Creating registry images applications CSV...")

    etl_registry_image_application_csv()
