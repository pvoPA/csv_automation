"""
Exports application data to CSV on tanzu blob store resources
    in Prisma Cloud.

This script is used to retrieve application data for
    tanzu blob store resources and exports it to
    a CSV file with the following actions,
        - Generate Prisma Token
        - Delete the CSV file if it exists from a previous run
        - Grab tanzu blob store scan results
        - For each API call,
            - Flatten application list for each blob
            - Write to CSV (Create a CSV directory and file.)

Usage:
    python export_tanzu_blobstore_application_csv.py

Options:

Requirements:
    - Python 3.10 or higher
    - .env configured with the following variables,
        - PRISMA_ACCESS_KEY
        - PRISMA_SECRET_KEY

Example:
    python export_tanzu_blobstore_application_csv.py

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
from helpers import prisma_get_tanzu_blob_store_scan_results
from helpers import generate_prisma_token
from helpers import write_data_to_csv


def etl_tanzu_blobstore_applications_csv():
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


if __name__ == "__main__":
    logger.info("Creating tanzu blobstore applications CSV...")

    etl_tanzu_blobstore_applications_csv()
