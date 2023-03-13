from helpers import *
from export_applications_csv import ETL_applications_csv
from export_containers_csv import ETL_containers_csv
from export_vulnerabilities_csv import ETL_vulnerabilities_csv


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
