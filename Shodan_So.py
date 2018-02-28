#!/usr/bin/env python
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
from netaddr import IPNetwork
import os
import re
import shodan
import sys
import json


def ip_port_list(result, bool):
    # file = open(path, "rb")
    # results = json.load(file)
    # for result in results["matches"]:
    ip_str = result["ip_str"]
    port = result["port"]
    list = ip_str.encode('unicode-escape').decode('string_escape')
    if bool:
        list += ':' + str(port)
    print(list)


def cli_parser():

    # Command line argument parser
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Shodan_So - Search Assistant: Searching shodan via API." +
        bcolors.HEADER + "\n--By: Zev3n \n" + bcolors.ENDC)
    parser.add_argument(
        "-search", metavar="Apache", default=False,
        help="\033[0;37mwhen searching Shodan for a string.")
    parser.add_argument(
        "-f", metavar="ips.txt", default=None,
        help="Using THe Ips List - File containing IPs to search shodan for.")
    parser.add_argument(
        "-ip", metavar='217.140.75.46', default=False,
        help="Shodan Host Search against IP & return results from Shodan about a specific IP.")
    parser.add_argument(
        "-iprg", metavar='217.140.75.46/24', default=False,
        help="Used to return results from Shodan about a specific CIDR to IP range .")
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

    return args.search, args.ip, args.iprg, args.hostnameonly, args.history, args.page, args.list_ip, args.list_ip_port, args.f


def create_shodan_object():
    # Add your shodan API key here
    # Free api_key(Some functions are restricted)
    api_key = "pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM"
    shodan_object = shodan.Shodan(api_key)

    return shodan_object


def host_print(shodan_search_object, ip, search_history, serial_number):

    ip = str(ip).replace("\n", "")
    print "[*] Searching Shodan for info about " + ip + "..."

    try:
        # Search Shodan
        history = search_history
        host = shodan_search_object.host(ip, history)

        # Display basic info of result
        print "\n***** RESULT %s*****" % (serial_number)
        print """
IP: %s
Organization: %s
Operating System: %s
        """ % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'))

        # Loop through other info
        ports_count = 0
        for item in host['data']:
            ports_count += 1
            sort_list = []
            print """
*** PORT %s***
Port: %s
Banner:
%s

            """ % (ports_count, item['port'], item['data'])

        print "[+] Host " + ip + " Found ports Record:" + str(ports_count)
        for item in host['data']:
            sort_list += [int(item['port'])]
        sort_list = list(set(sort_list))
        sort_list.sort()
        for port in sort_list:
            print port,

    except Exception, e:
        if str(e).strip() == "API access denied":
            print "You provided an invalid API Key!"
            print "Please provide a valid API Key and re-run!"
            sys.exit()
        elif str(e).strip() == "No information available for that IP.":
            print "No information on Shodan about " + str(ip)
        else:
            print "[*]Unknown Error: " + str(e)


def shodan_iprg_search(shodan_search_object, shodan_search_iprg, input_file_ips, search_history):

    title()

    serial_number = 0
    if shodan_search_iprg is not False:

        if not validate_iprg(shodan_search_iprg):
            print "[*] ERROR: Please provide valid iprg notation!"
            sys.exit()

        else:
            print "[*] Searching Shodan for info about " + shodan_search_iprg

            # Create iprg notated list
            network = IPNetwork(shodan_search_iprg)

    elif input_file_ips is not False:
        try:
            with open(input_file_ips, 'r') as ips_provided:
                network = ips_provided.readlines()
        except IOError:
            print "[*] ERROR: You didn't provide a valid input file."
            print "[*] ERROR: Please re-run and provide a valid file."
            sys.exit()

    # search shodan for each IP

    for ip in network:
        serial_number += 1
        host_print(shodan_search_object, ip, search_history, serial_number)


def shodan_ip_search(shodan_search_object, shodan_search_ip, search_history):

    title()

    serial_number = ""
    if validate_ip(shodan_search_ip):
        host_print(shodan_search_object, shodan_search_ip,
                   search_history, serial_number)
    else:
        print "[*]ERROR: You provided an invalid IP address!"
        print "[*]ERROR: Please re-run and provide a valid IP."
        sys.exit()


def shodan_string_search(shodan_search_object, shodan_search_string,
                         hostname_only, page_to_return, list_ip, list_port):

    title()

    # Try/catch for searching the shodan api
    print "[*] Searching Shodan...\n"
    try:
        # Time to search Shodan
        results = shodan_search_object.search(
            shodan_search_string, page=page_to_return)

        print "Total number of results back: " + str(results['total']) + "\n\n"
        result_count = 100 * (int(page_to_return) - 1)
        for result in results['matches']:
            if hostname_only:
                for item in result['hostnames']:
                    result_count += 1
                    if list_ip or list_port:
                        if list_port:
                            ip_port_list(result, True)
                        else:
                            ip_port_list(result, False)
                        continue

                    print "*** RESULT %s***" % (result_count)
                    print "IP Address: " + result['ip_str']
                    if result['timestamp'] is not None:
                        print "Last updated: " + result['timestamp']
                    if result['port'] is not None:
                        print "Port: " + str(result['port'])
                    print "Data: " + result['data']
                    for item in result['hostnames']:
                        print "Hostname: " + item
                    print "\n\n"

            else:
                result_count += 1
                if list_ip or list_port:
                    if list_port:
                        ip_port_list(result, True)
                    else:
                        ip_port_list(result, False)
                    continue
                print "*** RESULT %s***" % (result_count)
                print "IP Address: " + result['ip_str']
                if result['timestamp'] is not None:
                    print "Last updated: " + result['timestamp']
                if result['port'] is not None:
                    print "Port: " + str(result['port'])
                print "Data: " + result['data']
                print "\n\n"

        # jsObj = json.dumps(results, indent=4)
        # fileObject = open('jsonFile.json', 'w')
        # fileObject.write(jsObj)
        # fileObject.close()

    except Exception, e:
        if str(e).strip() == "API access denied":
            print "You provided an invalid API Key!"
            print "Please provide a valid API Key and re-run!"
        else:
            print e
        sys.exit()


def title():
    os.system('clear')
    print "\n" + bcolors.HEADER + \
          "   ______           __             ____    "
    print "  / __/ /  ___  ___/ /__ ____     / __/__  "
    print " _\ \/ _ \/ _ \/ _  / _ `/ _ \   _\ \/ _ \ "
    print "/___/_//_/\___/\_,_/\_,_/_//_/__/___/\___/ "
    print "                            /___/          " + bcolors.ENDC

    return


def validate_iprg(val_iprg):
    # This came from (Mult-line link for pep8 compliance)
    # http://python-iptools.googlecode.com/svn-history/r4
    # /trunk/iptools/__init__.py
    iprg_re = re.compile(r'^(\d{1,3}\.){0,3}\d{1,3}/\d{1,2}$')
    if iprg_re.match(val_iprg):
        ip, mask = val_iprg.split('/')
        if validate_ip(ip):
            if int(mask) > 32:
                return False
        else:
            return False
        return True
    return False


def validate_ip(val_ip):
    # This came from (Mult-line link for pep8 compliance)
    # http://python-iptools.googlecode.com/svn-history/r4
    # /trunk/iptools/__init__.py
    ip_re = re.compile(r'^(\d{1,3}\.){0,3}\d{1,3}$')
    if ip_re.match(val_ip):
        quads = (int(q) for q in val_ip.split('.'))
        for q in quads:
            if q > 255:
                return False
        return True
    return False


if __name__ == '__main__':

    # Parse command line options
    search_string, search_ip, search_iprg, search_hostnameonly,\
        search_history, search_page_number, list_ip, list_port, search_file = cli_parser()

    # Create object used to search Shodan
    shodan_api_object = create_shodan_object()

    # Determine which action will be performed
    if search_string is not False:
        shodan_string_search(shodan_api_object, search_string,
                             search_hostnameonly, search_page_number, list_ip, list_port)

    elif search_ip is not False:
        shodan_ip_search(shodan_api_object, search_ip, search_history)

    elif search_iprg is not False or search_file is not None:
        shodan_iprg_search(shodan_api_object, search_iprg,
                           search_file, search_history)

    else:
        print "\n" + bcolors.HEADER + \
              "   ______           __             ____    "
        print "  / __/ /  ___  ___/ /__ ____     / __/__  "
        print " _\ \/ _ \/ _ \/ _  / _ `/ _ \   _\ \/ _ \ "
        print "/___/_//_/\___/\_,_/\_,_/_//_/__/___/\___/ "
        print "                            /___/          " + bcolors.ENDC
        print(bcolors.OKWHITE +
              "\nShodan_So - Search Assistant: Searching shodan via API." + bcolors.ENDC)

        print(bcolors.HEADER +
              "                               --By: Zev3n \n" + bcolors.ENDC)
        print(bcolors.OKGREEN +
              "Usage: ./ShodanAPI.py [Options]" + bcolors.ENDC)
        print(bcolors.OKGREEN + "Options:           " + bcolors.ENDC)
        print(bcolors.OKGREEN + "     -f ips.txt" + bcolors.ENDC)
        print(bcolors.OKWHITE +
              "    Shodan search with ipts.txt list  " + bcolors.ENDC)
        print(bcolors.OKGREEN + "     -search <string>" + bcolors.ENDC)
        print(bcolors.OKWHITE +
              "    Use this when searching Shodan for a string. " + bcolors.ENDC)
        print(bcolors.OKGREEN + "     -ip 217.140.75.46" + bcolors.ENDC)
        print(bcolors.OKWHITE +
              "    Used to return results from Shodan about a specific IP. " + bcolors.ENDC)
        print(bcolors.OKGREEN + "     -H, -h, -?, --h, -help, --help " + bcolors.ENDC)
        print(bcolors.OKWHITE + "    For more options " + bcolors.ENDC)

#
#
# END ~
#
