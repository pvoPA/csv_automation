"""
This file contains a collection of helper functions for automating tasks.

Functions:
- generate_prisma_token(access_key, secret_key):
    Returns a PRISMA token.
- prisma_get_host_scan_results(token, offset, limit):
    Returns host scan reports.
- prisma_get_registry_image_scan_results(token, offset, limit):
    Returns registry image scan reports.
- prisma_get_images_scan_results(token, offset, limit, collection, cluster):
    Returns image scan reports.
- prisma_get_containers_scan_results(token, offset, limit, collection):
    Returns container scan reports.
- prisma_get_tanzu_blob_store_scan_results(token, offset, limit):
    Returns tanzu blob store scan reports.
- write_data_to_csv(file_path, data_list, field_names, new_file):
    Creates CSV directory and file from data.

Usage:
Simply import this file and call the function. For example:

    from helpers import generate_prisma_token
    prisma_token = generate_prisma_token()

Note:
Before using these functions, be sure to configure the .env appropriately.
"""
import os
import csv
import json
import logging
from typing import Tuple
import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

cwp_endpoint = os.getenv("CWPP_API")
cspm_endpoint = os.getenv("CSPM_API")


def generate_prisma_token(access_key: str, secret_key: str) -> str:
    """
    Generate the token for Prisma API access.

    Parameters:
    access_key (str): Prisma generated access key
    secret_key (str): Prisma generated secret key

    Returns:
    str: Prisma token

    """
    endpoint = f"https://{cspm_endpoint}/login"

    logger.info("Generating Prisma token using endpoint: %s", endpoint)

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }

    body = {"username": access_key, "password": secret_key}

    response = requests.post(endpoint, headers=headers, json=body, timeout=360)

    data = json.loads(response.text)

    return data["token"]


def prisma_get_tanzu_blob_store_scan_results(
    token: str, offset: int, limit: int
) -> Tuple[list, int]:
    """
    Retrieves all tanzu blobstore scan reports.

    Not available in documentation.

    Args:
        token (str): Prisma token for API access.

    Returns:
        Tuple[list, int]: the tanzu blobstore scan reports
            and response status code.
    """

    endpoint = f"https://{cwp_endpoint}/api/v1/tas-droplets?offset={str(offset)}&limit={str(limit)}"

    logger.info(
        "Getting tanzu blob store scan results from Prisma using endpoint: %s", endpoint
    )

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    response = requests.get(endpoint, headers=headers, timeout=360)

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        return None, response.status_code


def prisma_get_host_scan_results(
    token: str, offset: int, limit: int
) -> Tuple[list, int]:
    """
    Retrieves all host scan reports.

    https://pan.dev/prisma-cloud/api/cwpp/get-hosts/

    Args:
        token (str): Prisma token for API access.

    Returns:
        Tuple[list, int]: the host scan reports
            and response status code.
    """

    endpoint = (
        f"https://{cwp_endpoint}/api/v1/hosts?offset={str(offset)}&limit={str(limit)}"
    )

    logger.info("Getting host scan results from Prisma using endpoint: %s", endpoint)

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    response = requests.get(endpoint, headers=headers, timeout=360)

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        return None, response.status_code


def prisma_get_registry_image_scan_results(
    token: str, offset: int, limit: int
) -> Tuple[list, int]:
    """
    Retrieves registry image scan reports.

    https://pan.dev/prisma-cloud/api/cwpp/get-registry/

    Args:
        token (str): Prisma token for API access.

    Returns:
        Tuple[list, int]: the registry image scan reports
            and response status code.
    """

    endpoint = f"https://{cwp_endpoint}/api/v1/registry?offset={str(offset)}&limit={str(limit)}"

    logger.info(
        "Getting registry image scan results from Prisma using endpoint: %s", endpoint
    )

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    response = requests.get(endpoint, headers=headers, timeout=360)

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        return None, response.status_code


def prisma_get_images_scan_results(
    token: str, limit: int, offset: int, collection="", cluster=""
) -> Tuple[list, int]:
    """
    Retrieves image scan reports.

    https://pan.dev/prisma-cloud/api/cwpp/get-images/

    Parameters:
        token (str): Prisma token for API access.
        collection (str): Scopes the query by collection.
        cluster (str): Filters results by cluster name.
        limit (int): Number of documents to return.

    Returns:
        Tuple[list, int]: the image scan reports
            and response status code.

    """
    endpoint = (
        f"https://{cwp_endpoint}/api/v1/images?offset={str(offset)}&limit={str(limit)}"
    )

    if collection:
        endpoint += f"&collections={collection}"
    if cluster:
        endpoint += f"&clusters={cluster}"

    logger.info("Getting images from Prisma using endpoint: %s", endpoint)

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    response = requests.get(endpoint, headers=headers, timeout=360)

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        return None, response.status_code


def prisma_get_containers_scan_results(
    token: str, limit: int, offset: int, collection=""
) -> Tuple[list, int]:
    """
    Retrieves container scan reports.

    https://pan.dev/prisma-cloud/api/cwpp/get-containers/

    Parameters:
        token (str): Prisma token for API access.

    Returns:
        Tuple[list, int]: the container scan reports
            and response status code.

    """
    endpoint = f"https://{cwp_endpoint}/api/v1/containers?offset={str(offset)}&limit={str(limit)}"

    if collection:
        endpoint += f"&collections={collection}"

    logger.info("Getting containers from Prisma using endpoint: %s", endpoint)

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    response = requests.get(endpoint, headers=headers, timeout=360)

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    else:
        return None, response.status_code


def write_data_to_csv(
    file_path: str, data_list: list[dict], field_names: list[str], new_file=False
) -> None:
    """
    Writes list of iterable data to CSV.

    Parameters:
    file_path (str): File path
    data_list (list[dict]): List of dictionaries

    """
    logger.info("Writing data to %s", file_path)

    try:
        csv_file = open(file_path, "a", newline="", encoding="utf-8")

    except FileNotFoundError:
        os.mkdir("CSVs")
        csv_file = open(file_path, "w", newline="", encoding="utf-8")

    writer = csv.DictWriter(csv_file, fieldnames=field_names)

    if new_file:
        writer.writeheader()

    # Write the CSV rows
    for data in data_list:
        writer.writerow(data)

    csv_file.close()
