from helpers import *


def main(data="", context=""):
    token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    ############################################################################################################################################
    # Get collection IDs for image vulnerability correlation

    end_of_page = False
    offset = 0
    LIMIT = 50

    containers_data = list()

    while not end_of_page:
        containers_response = get_containers(token, offset=offset, limit=LIMIT)

        if containers_response:
            containers_data += [container for container in containers_response]
        else:
            end_of_page = True

        offset += LIMIT

    ############################################################################################################################################
    # Get images from Prisma to extract vulnerabilities

    end_of_page = False
    offset = 0
    LIMIT = 50

    images_data = list()

    while not end_of_page:
        images_response = get_images(token, offset=offset, limit=LIMIT)

        if images_response:
            images_data += [image for image in images_response]
        else:
            end_of_page = True

        offset += LIMIT

    ############################################################################################################################################
    # Transform and create the CSVs

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

    if csv_rows:
        write_data_to_csv("prisma_vulnerabilities.csv", csv_rows)


if __name__ == "__main__":
    main()
