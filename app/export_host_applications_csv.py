"""
Exports application data to CSV on host resources in Prisma Cloud.

This script is used to retrieve application data for host resources
and exports it to a CSV file with the following actions,
    - Generate Prisma Token
    - Delete the CSV file if it exists from a previous run
    - Grab host scan results
    - For each API call,
        - Flatten application list for each host
        - Write to CSV (Create a CSV directory and file.)

Usage:
    python export_host_application_csv.py

Options:

Requirements:
    - Python 3.10 or higher
    - .env configured with the following variables,
        - PRISMA_ACCESS_KEY
        - PRISMA_SECRET_KEY

Example:
    python export_host_application_csv.py

Note:
    This script is meant to be deployed in a docker container or azure function.
"""
import os
import json
import datetime as dt
from helpers import logger
from helpers import generate_prisma_token
from helpers import write_data_to_csv
from helpers import prisma_get_host_scan_results


def etl_host_applications_csv():
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


if __name__ == "__main__":
    logger.info("Creating host applications CSV...")

    etl_host_applications_csv()
