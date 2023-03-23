#!/usr/bin/env python3

import requests
import argparse
import time
import sys
from colorama import Fore, Style

API_KEY = "VIRUS-TOTAL-API-KEY"

# Parameters
parser = argparse.ArgumentParser(description='Retrieves the SHA1 and MD5 corresponding to a list of SHA256 hashes in a text file')
parser.add_argument('-f', '--file', dest='file', action="store", type=str, help='Text file containing the SHA256 hashes')
parser.add_argument('--sha1', action="store_true", help='Get SHA1 from SHA256 on virustotal')
parser.add_argument('--md5', action="store_true", help='Get MD5 from SHA256 on virustotal')
parser.add_argument('--file-type', action="store_true", help='Get file type of the SHA256 on virustotal')
parser.add_argument('--file-extension', action="store_true", help='Get file extension of the SHA256 on virustotal')
parser.add_argument('--threat-category', action="store_true", help='Get threat category (ransomware, trojan, ...) of the SHA256 on virustotal')
parser.add_argument('--last-time', action="store_true", help='Get last time seen threat by virustotal')
parser.add_argument('--all', action="store_true", help='Get maximum infos of the SHA256 on virustotal')
parser.add_argument('sha256', nargs='*', help='List of SHA256 hashes')

args = parser.parse_args()

# Info message
def infotext(msg) -> str:
    '''Display informational message on console in blue

    Arguments: the creation date, hash, OS, scope, source, user as a verbose option.

    msg -- text to be printed
    '''
    print(Fore.BLUE + "[i] " + msg + Style.RESET_ALL)

# Error message
def errortext(msg) -> str:
    '''Display success message on console in green

    Arguments:

    msg -- text to be printed
    '''
    print(Fore.RED + "[-] " + msg + Style.RESET_ALL)

# Warning message
def warntext(msg) -> str:
    '''Display success message on console in green

    Arguments:

    msg -- text to be printed
    '''
    print(Fore.YELLOW + "[w] " + msg + Style.RESET_ALL)

# Success message
def successtext(msg) -> str:
    '''Display success message on console in green

    Arguments:

    msg -- text to be printed
    '''
    print(Fore.GREEN + "[+] " + msg + Style.RESET_ALL)

# To get every infos in on param (--all)
if args.all:
    args.sha1 = True
    args.md5 = True
    args.file_type = True
    args.file_extension = True
    args.sha1 = True
    args.threat_category = True
    args.last_time = True

# if --file or -f has been used
if args.file:
    # Reading the SHA256 hashes from the text file
    with open(args.file) as f:
        sha256_list = f.read().splitlines()
    # Retrieving infos corresponding for each SHA256
    for sha256 in sha256_list:
        # Recover every data from the sha256 in virustotal
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {
            "x-apikey": API_KEY
        } 
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if "data" in data:
                attributes = data["data"]["attributes"]
            print("\n")
            infotext(f"Infos collected on VirusTotal from : {sha256}")
            successtext("Response from Virustoal succeded")
            if args.sha1:
                if "sha1" in attributes:
                    successtext("SHA1 : " + attributes["sha1"])
                else:
                    errortext("SHA1 : No infos")
            if args.md5:
                if "md5" in attributes:
                    successtext("MD5 : " + attributes["md5"])
                else:
                    errortext("MD5 : No infos")
            if args.file_type:
                if "type_description" in attributes:
                    successtext("File type : " + attributes["type_description"])
                else:
                    errortext("File type : No infos")
            if args.file_extension:
                if "FileTypeExtension" in attributes["exiftool"]:
                    successtext("File extension : " + attributes["exiftool"]["FileTypeExtension"])
                else:response
                    errortext("File extension : No infos")
            if args.threat_category:
                if not None in attributes["popular_threat_classification"]["popular_threat_category"]:
                    tr_category = ""
                    for t_category in attributes["popular_threat_classification"]["popular_threat_category"]:
                        if tr_category == "":
                            tr_category = t_category["value"]
                        else:
                            tr_category = tr_category + ", " + t_category["value"]
                    successtext("Threat Category : " + tr_category)
                else:
                    errortext("File extension : No infos") 
            if args.last_time:
                if "TimeStamp" in attributes["exiftool"]:
                    successtext("Last time seen : " + attributes["exiftool"]["TimeStamp"])
                else:
                    errortext("Last time seen : No infos")
            # sleep 15 s
            time.sleep(15)
if args.sha256:
    # Retrieving infos corresponding for each SHA256
    for sha256 in args.sha256:
        # Recover every data from the sha256 in virustotal
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {
            "x-apikey": API_KEY
        } 
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if "data" in data:
                attributes = data["data"]["attributes"]
            print("\n")
            infotext(f"Infos collected on VirusTotal from : {sha256}")
            successtext("Response from VirusTotal succeded")
            if args.sha1:
                if "sha1" in attributes:
                    successtext("SHA1 : " + attributes["sha1"])
                else:
                    errortext("SHA1 : No infos")
            if args.md5:
                if "md5" in attributes:
                    successtext("MD5 : " + attributes["md5"])
                else:
                    errortext("MD5 : No infos")
            if args.file_type:
                if "type_description" in attributes:
                    successtext("File type : " + attributes["type_description"])
                else:
                    errortext("File type : No infos")
            if args.file_extension:
                if "FileTypeExtension" in attributes["exiftool"]:
                    successtext("File extension : " + attributes["exiftool"]["FileTypeExtension"])
                else:
                    errortext("File extension : No infos")
            if args.threat_category:
                if not None in attributes["popular_threat_classification"]["popular_threat_category"]:
                    tr_category = ""
                    for t_category in attributes["popular_threat_classification"]["popular_threat_category"]:
                        if tr_category == "":
                            tr_category = t_category["value"]
                        else:
                            tr_category = tr_category + ", " + t_category["value"]
                    successtext("Threat Category : " + tr_category)
                else:
                    errortext("File extension : No infos") 
            if args.last_time:
                if "TimeStamp" in attributes["exiftool"]:
                    successtext("Last time seen : " + attributes["exiftool"]["TimeStamp"])
                else:
                    errortext("Last time seen : No infos")
            # sleep 15 s
            time.sleep(15)
