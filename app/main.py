from helpers import logger
from export_applications_csv import etl_applications_csv
from export_containers_csv import etl_containers_csv
from export_image_vulnerability_csv import etl_images_vulnerabilities_csv
from export_host_vulnerability_csv import etl_host_vulnerabilities_csv
from export_registry_image_vulnerability_csv import etl_registry_image_vulnerability_csv
from export_tanzu_blobstore_vulnerability_csv import (
    etl_tanzu_blobstore_vulnerabilities_csv,
)
from export_tas_vulnerability_csv import etl_tas_vulnerability_csv


def main(data="", context=""):
    logger.info("Creating applications CSV...")
    # etl_applications_csv()

    logger.info("Creating containers CSV...")
    # etl_containers_csv()

    logger.info("Creating image vulnerabilities CSV...")
    # etl_images_vulnerabilities_csv()

    logger.info("Creating host vulnerabilities CSV...")
    etl_host_vulnerabilities_csv()

    logger.info("Creating registry image vulnerabilities CSV...")
    etl_registry_image_vulnerability_csv()

    logger.info("Creating tanzu blobstore vulnerabilities CSV...")
    etl_tanzu_blobstore_vulnerabilities_csv()

    logger.info("Creating tas vulnerabilities CSV...")
    etl_tas_vulnerability_csv()


if __name__ == "__main__":
    main()
