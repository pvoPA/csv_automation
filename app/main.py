import os
import json
from helpers import logger
from export_openshift_applications_csv import etl_applications_csv
from export_openshift_image_vulnerability_csv import (
    etl_images_vulnerabilities_csv,
)
from export_containers_csv import etl_containers_csv
from export_host_vulnerability_csv import etl_host_vulnerabilities_csv
from export_registry_image_vulnerability_csv import (
    etl_registry_image_vulnerability_csv,
)
from export_tanzu_blobstore_vulnerability_csv import (
    etl_tanzu_blobstore_vulnerabilities_csv,
)
from export_tas_vulnerability_csv import etl_tas_vulnerability_csv


def main(data="", context=""):
    OPENSHIFT_COLLECTIONS_FILTER = ", ".join(
        json.loads(os.getenv("OPENSHIFT_COLLECTIONS_FILTER"))
    )
    OPENSHIFT_CONTAINERS_CSV_NAME = os.getenv("OPENSHIFT_CONTAINERS_CSV_NAME")
    HOST_COLLECTIONS_FILTER = ", ".join(
        json.loads(os.getenv("HOST_COLLECTIONS_FILTER"))
    )
    HOST_CONTAINERS_CSV_NAME = os.getenv("HOST_CONTAINERS_CSV_NAME")
    TAS_COLLECTIONS_FILTER = ", ".join(json.loads(os.getenv("TAS_COLLECTIONS_FILTER")))
    TAS_CONTAINERS_CSV_NAME = os.getenv("TAS_CONTAINERS_CSV_NAME")

    logger.info("Generating OpenShift CSV reports")
    logger.info("\tCreating openshift containers CSV...")
    etl_containers_csv(OPENSHIFT_COLLECTIONS_FILTER, OPENSHIFT_CONTAINERS_CSV_NAME)
    logger.info("\tCreating openshift applications CSV...")
    etl_applications_csv()
    logger.info("\tCreating openshift image vulnerabilities CSV...")
    etl_images_vulnerabilities_csv()

    logger.info("Generating Azure Host CSV reports")
    logger.info("\tCreating host containers CSV...")
    etl_containers_csv(HOST_COLLECTIONS_FILTER, HOST_CONTAINERS_CSV_NAME)
    logger.info("\tCreating host vulnerabilities CSV...")
    etl_host_vulnerabilities_csv()

    logger.info("Generating TAS CSV reports")
    logger.info("\tCreating tas containers CSV...")
    etl_containers_csv(TAS_COLLECTIONS_FILTER, TAS_CONTAINERS_CSV_NAME)
    logger.info("\tCreating tas vulnerabilities CSV...")
    etl_tas_vulnerability_csv()

    logger.info("Creating Nexus Repository vulnerabilities CSV...")
    etl_registry_image_vulnerability_csv()

    logger.info("Creating Tanzu Blobstore vulnerabilities CSV...")
    etl_tanzu_blobstore_vulnerabilities_csv()


if __name__ == "__main__":
    main()
