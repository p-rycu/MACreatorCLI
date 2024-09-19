#!/usr/bin/env python3
import os
import re
import time
import argparse
import requests

OUI_SRC_URL = "https://www.wireshark.org/download/automated/data/manuf"
TMP_OUI_SRC_PATH = "/tmp/MACreatorCLI/"
TMP_OUI_SRC_FILE = "oui_data.txt"


def does_oui_file_exist():
    return os.path.isfile(os.path.join(TMP_OUI_SRC_PATH, TMP_OUI_SRC_FILE))

def is_oui_file_up_to_date():
    actual_time = time.time()
    file_path = os.path.join(TMP_OUI_SRC_PATH, TMP_OUI_SRC_FILE)
    creation_file_time = os.path.getmtime(file_path)

    # if OUI Data file is older than 7 days
    if (actual_time - creation_file_time) > 604800:
        return False
    return True


def validate_mac(mac):
    patterns = {
        r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}",
        r"([0-9A-Fa-f]{2}.){5}[0-9A-Fa-f]{2}",
        r"([0-9A-Fa-f]{4}-){2}[0-9A-Fa-f]{4}",
    }
    if len(mac) not in {17, 14}:
        raise argparse.ArgumentTypeError(f"Wrong MAC length")
    for pattern in patterns:
        if re.match(pattern, mac):
            mac = re.sub(r"[-:.]", "", mac)
            formatted_mac = lambda mac: ":".join((mac[i:i+2]) for i in range (0, 12, 2))
            return formatted_mac(mac)
    raise argparse.ArgumentTypeError(
        f"Wrong MAC format\nAllowed: XX:XX:XX:XX:XX:XX, xx.xx.xx.xx.xx.xx, xxxx-xxxx-xxxx"
    )


def download_oui_data():
    if not os.path.exists(TMP_OUI_SRC_PATH):
        os.makedirs(TMP_OUI_SRC_PATH)

    try:
        response = requests.get(OUI_SRC_URL, timeout=10)

    except requests.ConnectionError:
        return False

    with open(TMP_OUI_SRC_PATH + TMP_OUI_SRC_FILE, "w") as file:
        file.write(response.text)

    return True

def get_vendor(mac):
    if not does_oui_file_exist() or not is_oui_file_up_to_date():
        download_oui_data()

    with open(TMP_OUI_SRC_PATH + TMP_OUI_SRC_FILE, "r") as file:
        lines = file.read().split("\n")
        for line in lines:
            if mac[0:8].upper() in line:
                line = line.split("\t")
                vendor = line[2]
                return vendor
    return "Not found"

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="A program for checking the Network Card Vendor based on a MAC address (OUI)."
    )

    parser.add_argument(
        "mac_address",
        type=validate_mac,
        help="MAC address (formats: XX:XX:XX:XX:XX:XX, xx.xx.xx.xx.xx.xx, xxxx-xxxx-xxxx)",
    )

    args = parser.parse_args()
    print(get_vendor(args.mac_address))
