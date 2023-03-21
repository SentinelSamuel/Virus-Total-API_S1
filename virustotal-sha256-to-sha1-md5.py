#!/usr/bin/env python3

import requests
import argparse
import time
import sys


API_KEY = "VIRUS-TOTAL-API-KEY"

# Function to recover SHA1 from SHA256
def get_sha1(sha256):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if "data" in data:
            attributes = data["data"]["attributes"]
            if "sha1" in attributes:
                return attributes["sha1"]
    return None

# Function to recover MD5 from SHA256
def get_md5(sha256):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if "data" in data:
            attributes = data["data"]["attributes"]
            if "md5" in attributes:
                return attributes["md5"]
    return None

# Parameters
parser = argparse.ArgumentParser(description='Retrieves the SHA1 and MD5 corresponding to a list of SHA256 hashes in a text file')
parser.add_argument('-f', '--file', dest='file', action="store", type=str, help='Text file containing the SHA256 hashes')
parser.add_argument('sha256', nargs='*', help='List of SHA256 hashes')
args = parser.parse_args()

if args.file:
    # Reading the SHA256 hashes from the text file
    with open(args.file) as f:
        sha256_list = f.read().splitlines()

    # Retrieving the corresponding SHA1 and MD5 for each SHA256
    for sha256 in sha256_list:
        print("\033[1m\033[34m" + f"[i] For the sha256 : {sha256}" + "\033[0m")
        # Retrieving the corresponding SHA1 and MD5
        sha1 = get_sha1(sha256)
        md5 = get_md5(sha256)
        # SHA1 result display
        if sha1:
            print("\033[32m" + f"[+] The corresponding SHA1 is : {sha1}" + "\033[0m")
        else:
            print("\033[31m" + f"[-] Unable to retrieve the corresponding SHA1 for {sha256}." + "\033[0m")

        # MD5 result display
        if md5:
            print("\033[32m" + f"[+] The corresponding MD5 is : {md5}" + "\033[0m")
        else:
            print("\033[31m" + f"[-]  Unable to retrieve the corresponding MD5 for {sha256}." + "\033[0m")
        print("------------------------------------------------------------------\n")
        # sleep 15 s
        time.sleep(15)

if args.sha256:
    # Retrieving the corresponding SHA1 and MD5 for each SHA256
    for sha256 in args.sha256:
        print("\033[1m\033[34m" + f"[i] For the sha256 : {sha256}" + "\033[0m")
        # Retrieving the corresponding SHA1 and MD5
        sha1 = get_sha1(sha256)
        md5 = get_md5(sha256)
        # SHA1 result display
        if sha1:
            print("\033[32m" + f"[+] The corresponding SHA1 is : {sha1}" + "\033[0m")
        else:
            print("\033[31m" + f"[-] Unable to retrieve the corresponding SHA1 for {sha256}." + "\033[0m")

        # MD5 result display
        if md5:
            print("\033[32m" + f"[+] The corresponding MD5 is : {md5}" + "\033[0m")
        else:
            print("\033[31m" + f"[-]  Unable to retrieve the corresponding MD5 for {sha256}." + "\033[0>")
        print("------------------------------------------------------------------")
        # sleep 15 s
        time.sleep(15)
