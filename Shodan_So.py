#!/usr/bin/env python
# coding=utf-8
# Shodan_So - By Zev3n
# THanks to the legend Hood3dRob1n & Lucifer HR

# in case you got shodan error use command below
# pip install shodan netaddr
# This is a free API key for you =>  api_key = "pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM"
# You can change the key ;)


class bcolors:
    HEADER = '\033[1;36m'
    OKWHITE = "\033[0;37m"
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKWHITE = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''


import argparse
from netaddr import *
import os
import re
import shodan
import sys
import json
import time


def ip_port_list(result, en_port, en_hostname=False, flag=False):
    ip_str = result["ip_str"]
    lists = ip_str
    if flag:
        var_p = "port"
    else:
        var_p = "ports"
    if en_port:
        port = result[var_p]
        lists += ':' + str(port)
    if en_hostname:
        print("{0:21}\t{1}".format(lists, str(result['hostnames'])))
    else:
        print(lists)


def cli_parser():

    # Command line argument parser
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Shodan_So - Search Assistant: Searching shodan via API." +
        bcolors.HEADER + "\n--By: Zev3n \n" + bcolors.ENDC)
    parser.add_argument(
        "-f", metavar="ips.txt", default=None,
        help="Using THe Ips List - File containing IPs to search shodan for.")
    parser.add_argument(
        "--ip", metavar='217.140.75.46-217.140.75.56', default=False,
        help="Shodan Host Search against IP/IP range & return results from Shodan about a it/them.")
    parser.add_argument(
        "--search", metavar="Apache", default=False,
        help="when searching Shodan for a string.")
    parser.add_argument(
        "--hostnameonly", action='store_true',
        help="Only provide results with a Shodan stored hostname.")
    parser.add_argument(
        "--history", action='store_true',
        help="Return all historical banners.")
    parser.add_argument(
        "--page", metavar='1', default=1,
        help="Page number of results to return (default 1 (first page)).")
    parser.add_argument(
        "--list_ip", action='store_true',
        help="Singled out IP address from query results.")
    parser.add_argument(
        "--list_ip_port", action='store_true',
        help="Singled out IP address with port from query results.")
    parser.add_argument(
        '-H', '-h', '-?', '--h', '-help', '--help', action="store_true",
        help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.h:
        parser.print_help()
        sys.exit()

    return args.search, args.ip, args.hostnameonly, args.history, args.page, args.list_ip, args.list_ip_port, args.f


def create_shodan_object():
    # Add your shodan API key here
    # Free api_key(Some functions are restricted)
    api_key = "pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM"
    shodan_object = shodan.Shodan(api_key)

    return shodan_object


def host_print(shodan_search_object, ip, search_history, serial_number, list_port, info):

    ip = str(ip).replace("\n", "")
    if info is True:
        print("[*] Searching Shodan for info about " + ip + "...")

    # Search Shodan
    history = search_history
    host = shodan_search_object.host(ip, history)
    if list_port is not False:
        ip_port_list(host, True)
    else:
        # Display basic info of result
        print("{}\n***** RESULT {}*****{}".format(bcolors.OKBLUE,
                                                  serial_number, bcolors.ENDC))
        print("""
IP: {}
ISP: {}
Country: {}
Organization: {}
Operating System: {}""".format(host['ip_str'], host.get('isp', 'n/a'), host.get('country_name', 'n/a'), host.get('org', 'n/a'), host.get('os', 'n/a')))

        # Loop through other info
        ports_count = 0
        for item in host['data']:
            ports_count += 1
            sort_list = []
            print("""
\t{}*** PORT {}***{}
\tPort: {}
\tBanner:--↓↓↓↓--
\t{}
\t---------↑↑↑↑--""".format(bcolors.OKBLUE, item['timestamp'][:-7] if history is not False else ports_count, bcolors.ENDC, item['port'], item['data'].replace('\n', '\n\t')))

        print(
            "{}[+] No.{} Host {} Found Ports Record: {}".format(bcolors.OKGREEN, serial_number, ip, str(ports_count)))
        for item in host['data']:
            sort_list += [int(item['port'])]
        sort_list = list(set(sort_list))
        sort_list.sort()
        print("\t", end='')
        for port in sort_list:
            print(port, end=' ')
        print("\n----------------------\n\n" + bcolors.ENDC)


def shodan_ip_search(shodan_search_object, shodan_search_ip, input_file_ips, search_history, list_port):

    title()
    info = False
    serial_number = 1
    if shodan_search_ip is not False:
        if validate_ip(shodan_search_ip) is not False:
            print("{}[*] Searching Shodan for info about {}{}".format(
                bcolors.OKWHITE, shodan_search_ip, bcolors.ENDC))
            # Create iprg notated list
            network = validate_ip(shodan_search_ip)
        else:
            print(
                "{}[!] ERROR: Please provide valid ip/iprg notation!{}".format(bcolors.FAIL, bcolors.ENDC))
            sys.exit()

    elif input_file_ips is not False:
        try:
            with open(input_file_ips, 'r') as ips_provided:
                network = ips_provided.readlines()
        except IOError:
            print("{}[!] ERROR: You didn't provide a valid input file.{}".format(
                bcolors.FAIL, bcolors.ENDC))
            print(
                "{}[!] ERROR: Please re-run and provide a valid file.{}".format(bcolors.FAIL, bcolors.ENDC))
            sys.exit()

    # search shodan for each IP

    for ip in IPSet(network):
        time.sleep(1.5)
        try:
            host_print(shodan_search_object, ip,
                       search_history, serial_number, list_port, info)

        except Exception as e:
            if str(e).strip() == "Invalid API key":
                print("{}[!] You provided an invalid API Key!\n[!] Please provide a valid API Key and re-run!{}".format(
                    bcolors.FAIL, bcolors.ENDC))
                sys.exit()
            elif str(e).strip() == "No information available for that IP.":
                print(
                    "{}[-]No information on Shodan about {}{}".format(bcolors.WARNING, ip, bcolors.ENDC))
            else:
                print("{}[!]Unknown Error: {}{}".format(bcolors.FAIL,
                                                        str(e), bcolors.ENDC))
        else:
            serial_number += 1


def shodan_string_search(shodan_search_object, shodan_search_string,
                         hostname_only, page_to_return, list_ip, list_port):

    title()
    print("[*] Searching Shodan...\n")
    # Time to search Shodan
    results = shodan_search_object.search(
        shodan_search_string, page=page_to_return)

    print("Total number of results back: " +
          str(results['total']) + "\n\n")
    result_count = 100 * (int(page_to_return) - 1)
    for result in results['matches']:
        if hostname_only:
            for item in result['hostnames']:
                result_count += 1
                if list_ip or list_port:
                    if list_port:

                        ip_port_list(result, True, en_hostname=True, flag=True)
                    else:
                        ip_port_list(result, False, en_hostname=True)
                    continue

                print("*** RESULT {0}***".format(result_count))
                print("IP Address: " + result['ip_str'])
                if result['timestamp'] is not None:
                    print("Last updated: " + result['timestamp'])
                if result['port'] is not None:
                    print("Port: " + str(result['port']))
                print("Data: " + result['data'])
                for item in result['hostnames']:
                    print("Hostname: " + item)
                print("\n\n")

        else:
            result_count += 1
            if list_ip or list_port:
                if list_port:
                    ip_port_list(result, True, flag=True)
                else:
                    ip_port_list(result, False)
                continue
            print("*** RESULT %s***" % (result_count))
            print("IP Address: " + result['ip_str'])
            if result['timestamp'] is not None:
                print("Last updated: " + result['timestamp'])
            if result['port'] is not None:
                print("Port: " + str(result['port']))
            print("Data: " + result['data'])
            print("\n\n")

def title():
    os.system('clear')
    print("\n" + bcolors.HEADER +
          "   ______           __             ____    ")
    print("  / __/ /  ___  ___/ /__ ____     / __/__  ")
    print(" _\ \/ _ \/ _ \/ _  / _ `/ _ \   _\ \/ _ \ ")
    print("/___/_//_/\___/\_,_/\_,_/_//_/__/___/\___/ ")
    print("                            /___/          " + bcolors.ENDC)

    return 0

def validate_ip(val_ip):

    try:
        if len(val_ip.split('-')) > 2:
            return False
        ip_range = IPRange(val_ip.split(
            '-')[0], val_ip.split('-')[1] if len(val_ip.split('-')) == 2 else val_ip.split('-')[0])

        return ip_range
    except Exception as e:
        return False

if __name__ == '__main__':
    # if os.name == 'nt':      #disable the shell color if system does not support.
    #     bcolors.disable(bcolors)

    # Parse command line options
    search_string, search_ip, search_hostnameonly,\
        search_history, search_page_number, list_ip, list_port, search_file = cli_parser()

    # Create object used to search Shodan
    shodan_api_object = create_shodan_object()

    # Determine which action will be performed
    if search_string is not False:
        shodan_string_search(shodan_api_object, search_string,
                             search_hostnameonly, search_page_number, list_ip, list_port)

    elif search_ip is not False or search_file is not None:

        shodan_ip_search(shodan_api_object, search_ip,
                         search_file, search_history, list_port)

    else:
        print("\n" + bcolors.HEADER +
              "   ___ __           __             ____    ")
        print("  / __/ /  ___  ___/ /__  ___     / __/__  ")
        print(" _\ \/ _ \/ _ \/ _  / _ `/ _ \   _\ \/ _ \ ")
        print("/___/_//_/\___/\_,_/\_,_/_//_/__/___/\___/ ")
        print("                            /___/          " + bcolors.ENDC)
        print(bcolors.OKWHITE +
              "\nShodan_So - Search Assistant: Searching shodan via API." + bcolors.ENDC)

        print(bcolors.HEADER +
              "                               --By: Zev3n \n" + bcolors.ENDC)
        print(bcolors.OKGREEN +
              "Usage: ./ShodanAPI.py [Options]" + bcolors.ENDC)
        print(bcolors.OKGREEN + "Options:           " + bcolors.ENDC)
        print(bcolors.OKGREEN + "   -f ips.txt" + bcolors.ENDC)
        print(bcolors.OKWHITE +
              "\tShodan search with ipts.txt list  " + bcolors.ENDC)
        print(bcolors.OKGREEN + "   --search <string>" + bcolors.ENDC)
        print(bcolors.OKWHITE +
              "\tUse this when searching Shodan for a string. " + bcolors.ENDC)
        print(bcolors.OKGREEN + "   --ip 217.140.75.46" + bcolors.ENDC)
        print(bcolors.OKWHITE +
              "\tUsed to return results from Shodan about a IP/IP range. " + bcolors.ENDC)
        print(bcolors.OKGREEN +
              "   -H, -h, -?, --h, -help, --help " + bcolors.ENDC)
        print(bcolors.OKWHITE + "\tFor more options " + bcolors.ENDC)
