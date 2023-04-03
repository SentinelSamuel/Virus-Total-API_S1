#!/usr/bin/env python3

import time
import argparse
import requests
from colorama import Fore, Style

API_KEY = "VIRUS-TOTAL-API-KEY"

# Parameters
parser = argparse.ArgumentParser(description='Retrieves the hashes corresponding to a list of hashes in a text file')
parser.add_argument('-f', '--file', dest='file', action="store", type=str, help='Text file containing the Hashes')
parser.add_argument('--sha1', action="store_true", help='Get SHA1 from SHA256 or MD5 on virustotal')
parser.add_argument('--md5', action="store_true", help='Get MD5 from SHA256 or SHA1 on virustotal')
parser.add_argument('--sha256', action="store_true", help='Get SHA256 from SHA1 or MD5 on virustotal')
parser.add_argument('--file-type', action="store_true", help='Get file type of the Hash on virustotal')
parser.add_argument('--file-extension', action="store_true", help='Get file extension of the Hash on virustotal')
parser.add_argument('--threat-category', action="store_true", help='Get threat category (ransomware, trojan, ...) of the Hash on virustotal')
parser.add_argument('--last-time', action="store_true", help='Get last time seen threat by virustotal')
parser.add_argument('-a','--all', action="store_true", help='Get maximum infos of the Hash on virustotal')
parser.add_argument('hashs', nargs='*', help='List of hashes (can be : sha256,md5,sha1)')

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
    args.sha256 = True
    args.file_type = True
    args.file_extension = True
    args.threat_category = True
    args.last_time = True

# if --file or -f has been used
if args.file:
    # Reading the SHA256 hashes from the text file
    with open(args.file, encoding="utf-8") as f:
        hash_list = f.read().splitlines()
    # Retrieving infos corresponding for each SHA256
    for ha in hash_list:
        # Recover every data from the sha256 in virustotal
        url = f"https://www.virustotal.com/api/v3/files/{ha}"
        headers = {
            "x-apikey": API_KEY
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if "data" in data:
                attributes = data["data"]["attributes"]
            print("\n")
            infotext(f"Infos collected on VirusTotal from : {ha}")
            successtext("Response from Virustoal succeded")
            if args.sha256:
                if "sha256" in attributes:
                    successtext("SHA256 : " + attributes["sha256"])
                else:
                    errortext("SHA256 : No infos")
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
                    TR_CATEGORY = ""
                    for t_category in attributes["popular_threat_classification"]["popular_threat_category"]:
                        if TR_CATEGORY == "":
                            TR_CATEGORY = t_category["value"]
                        else:
                            TR_CATEGORY = TR_CATEGORY + ", " + t_category["value"]
                    successtext("Threat Category : " + TR_CATEGORY)
                else:
                    errortext("File extension : No infos")
            if args.last_time:
                if "TimeStamp" in attributes["exiftool"]:
                    successtext("Last time seen : " + attributes["exiftool"]["TimeStamp"])
                else:
                    errortext("Last time seen : No infos")
            # sleep 15 s
            time.sleep(15)
        elif response.status_code == 400:
            errortext(f"The API GET request to didn't succeded. Request status : Bad Request {response.status_code} Invalid user input received. See error details for further information."
                        "\n\n(The HyperText Transfer Protocol (HTTP) 400 Bad Request response status code indicates that the server cannot or will\nnot process the request due to something that is perceived to"
                        "be a client error (for example, malformed request syntax,\ninvalid request message framing, or deceptive request routing).")
        elif response.status_code == 404:
            errortext(f"The API GET request didn't succeded. Request status : HTTP {response.status_code} \n\n"
            "(In computer network communications, the HTTP 404 error page not found or file not found error message is a hypertext transfer protocol " 
            "standard response code, to indicate that the browser was able to communicate with a given server, but the server could not find what was requested).")
        else:
            errortext(f"Unespected API Error : {response.status_code}")

if args.hashs:
    # Retrieving infos corresponding for each SHA256
    for ha in args.hashs:
        # Recover every data from the sha256 in virustotal
        url = f"https://www.virustotal.com/api/v3/files/{ha}"
        headers = {
            "x-apikey": API_KEY
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if "data" in data:
                attributes = data["data"]["attributes"]
            print("\n")
            infotext(f"Infos collected on VirusTotal from : {ha}")
            successtext("Response from VirusTotal succeded")
            if args.sha256:
                if "sha256" in attributes:
                    successtext("SHA256 : " + attributes["sha256"])
                else:
                    errortext("SHA256 : No infos")
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
                    TR_CATEGORY = ""
                    for t_category in attributes["popular_threat_classification"]["popular_threat_category"]:
                        if TR_CATEGORY == "":
                            TR_CATEGORY = t_category["value"]
                        else:
                            TR_CATEGORY = TR_CATEGORY + ", " + t_category["value"]
                    successtext("Threat Category : " + TR_CATEGORY)
                else:
                    errortext("File extension : No infos")
            if args.last_time:
                if "TimeStamp" in attributes["exiftool"]:
                    successtext("Last time seen : " + attributes["exiftool"]["TimeStamp"])
                else:
                    errortext("Last time seen : No infos")
            # sleep 15 s
            time.sleep(15)
        elif response.status_code == 400:
            errortext(f"The API GET request to didn't succeded. Request status : Bad Request {response.status_code} Invalid user input received. See error details for further information."
                        "\n\n(The HyperText Transfer Protocol (HTTP) 400 Bad Request response status code indicates that the server cannot or will\nnot process the request due to something that is perceived to"
                        "be a client error (for example, malformed request syntax,\ninvalid request message framing, or deceptive request routing).")
        elif response.status_code == 404:
            errortext(f"The API GET request didn't succeded. Request status : HTTP {response.status_code} \n\n"
            "(In computer network communications, the HTTP 404 error page not found or file not found error message is a hypertext transfer protocol " 
            "standard response code, to indicate that the browser was able to communicate with a given server, but the server could not find what was requested).")
        else:
            errortext(f"Unespected API Error : {response.status_code}")
