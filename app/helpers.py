import os
import requests
import json
import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Global environment variables.
CSPM_api_endpoint = os.getenv("CSPM_API")
CWPP_api_endpoint = os.getenv("CWPP_API")
prisma_access_key = os.getenv("ACCESS_KEY")
prisma_secret_key = os.getenv("SECRET_KEY")


def generate_prisma_token(access_key: str, secret_key: str) -> str:
    """
    Generate the token for PRISMA API access.

    Parameters:
    access_key (str): PRISMA generated access key
    secret_key (str): PRISMA generated secret key

    Returns:
    str: PRISMA token

    """
    endpoint = f"https://{CSPM_api_endpoint}/login"

    logger.info(f" Generating PRISMA token using endpoint: {endpoint}")

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }

    body = {"username": access_key, "password": secret_key}

    response = requests.post(endpoint, headers=headers, json=body)

    data = json.loads(response.text)

    return data["token"]


def get_images(token: str, collection="", cluster="", limit="", offset="") -> list:
    """
    Retrieves image scan reports.

    This function can be expanded as it does not use the full capabilities of the API.

    Parameters:
    token (str): PRISMA token for API access.
    collection (str): Scopes the query by collection.
    cluster (str): Filters results by cluster name.
    limit (int): Number of documents to return.

    Returns:
    list: the image scan reports.

    """
    endpoint = f"https://{CWPP_api_endpoint}/api/v1/images?"

    if collection:
        endpoint += f"&collections={collection}"
    if cluster:
        endpoint += f"&clusters={cluster}"
    if limit:
        endpoint += f"&limit={limit}"
    if offset:
        endpoint += f"&offset={offset}"

    logger.info(f" Getting images from Prisma using endpoint: {endpoint}")

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    response = requests.get(endpoint, headers=headers)

    data = json.loads(response.text)

    return data


def get_containers(token: str, offset="", limit="") -> list:
    """
    Retrieves a list of all containers.

    This function can be expanded as it does not use the full capabilities of the API.

    Parameters:
    token (str): PRISMA token for API access.

    Returns:
    list: list of containers.

    """
    endpoint = f"https://{CWPP_api_endpoint}/api/v1/containers?"

    if limit:
        endpoint += f"&limit={limit}"
    if offset:
        endpoint += f"&offset={offset}"

    logger.info(f" Getting containers from Prisma using endpoint: {endpoint}")

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    response = requests.request("GET", endpoint, headers=headers)

    data = json.loads(response.text)

    return data


def write_data_to_csv(csv_name: str, data_list: list[dict]) -> None:
    """
    Writes list of iterable data to CSV.

    Parameters:
    csv_name (str): File name
    data_list (list[dict]): List of dictionaries

    """
    directory = "CSVs"

    logger.info(f" Writing data to {directory}/{csv_name}")

    try:
        file = open(f"{directory}/{csv_name}", "w")
    except FileNotFoundError:
        os.mkdir(f"{directory}")

        file = open(f"{directory}/{csv_name}", "w")

    # Create the CSV headers
    headers = ""
    for key in data_list[0].keys():
        headers += f"{key},"

    # Remove the leading comma
    headers = headers.rstrip(headers[-1])
    file.write(headers + "\n")

    # Write the CSV rows
    for data in data_list:
        line = ""
        for key in data:
            line += f'"{data[key]}",'

        # Remove the leading comma
        line = line.rstrip(line[-1])
        file.write(line + "\n")

    file.close()
