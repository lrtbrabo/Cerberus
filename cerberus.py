__author__ = "Tom"

import nmap3
import argparse
from colorama import init, Fore, Back, Style
from datetime import datetime
from tabulate import tabulate
from googlesearch import search

##########################################################################################

class Scanner:
    def __init__(self, domain, arguments = None):
        self.nmap = nmap3.Nmap()
        self.domain = domain
        self.arguments = arguments
        self.final = []

    def makeScan(self):
        return self.nmap.scan_top_ports(self.domain, args=self.arguments)

    def makeScanOnSubdomains(self):
        for subdomains in self.final:
            table_output = []
            table_output_headers = ["Port","Service","State","Product","Version","OS","Exploits"]
            ip = subdomains['address']
            host = subdomains['hostname']
            version_scan = self.nmap.scan_top_ports(host, args=self.arguments)

            try:
                version_scan = version_scan[ip]['ports']
                
                print(Fore.MAGENTA + "------------------------------------------------------------------------------------------")
                print(Fore.MAGENTA + "Scanning Ports for " + host)
                for port in version_scan:
                    
                    try:
                        product_to_search = port['service']['product'] + port['service']['version']
                        exploits = exploitdb_search(product_to_search)
                        exploits = ', '.join(exploits)
                        out_for_table = [port['portid'], port['state'], port['service']['name'], port['service']['product'], port['service']['version'], port['service']['ostype'], exploits]
                    except:
                        out_for_table = [port['portid'], port['state'], port['service']['name'], "None", "None", "None"]

                    table_output.append(out_for_table)

                print(tabulate(table_output, table_output_headers, tablefmt='orgtbl'))
            
            except:
                continue

          
    def subdomainScan(self):
        subdomains_found = self.nmap.nmap_dns_brute_script(self.domain)
        
        for subdomain in subdomains_found:
            print(Fore.GREEN + "[+] " + "Discovered subdomain:", subdomain['hostname'], " | IP: ", subdomain['address'])
            self.final = subdomains_found
        print("\n")
        return 0

    def forEachSubdomain(self, function):
        for subdomains in self.final:
            function(subdomains['hostname'])

###############################################################################################


def exploitdb_search(name):
    exploit_array = []
    query = name + ' ' + 'site:https://www.exploit-db.com'
    teste = search(query)
    for data in teste:
        if "https://www.exploit-db.com/exploits" in data:
            exploit_array.append(data)
    return exploit_array


def main():

    #CREATES A PARSER FOR THE ARGUMENTS
    parser = argparse.ArgumentParser()

    #ADD OPTIONS TO TERMINAL
    parser.add_argument("-sS", "--syn", help="Requires site domain")
    parser.add_argument("-sT", "--tcp", help="Requires site domain")
    parser.add_argument("-sU", "--udp", help="Requires site domain, only works with subdomains parameter")
    parser.add_argument("-o", "--opsys", help="Requires site domain, only works with subdomains parameter")
    parser.add_argument("-s", "--subdomain", help="Requires site domain, only works with subdomains parameter")
    parser.add_argument("-sV", "--version", help="Requires site domain, only works with subdomains parameter")
    parser.add_argument("-f", "--firewall", help="Requires site domain, only works with subdomains parameter")

    #PARSE PASSED ARGS
    args = parser.parse_args()
    
    if args.syn is not None:
        scan = Scanner(args.syn, "-sS")
        print(scan.makeScan())
    if args.subdomain is not None:
        scan = Scanner(args.subdomain, "-sV")
        scan.subdomainScan()
        scan.makeScanOnSubdomains()

##########################################################################################

tool_name = """
          ___          _                         
         / __\___ _ __| |__   ___ _ __ _   _ ___ 
        / /  / _ \ '__| '_ \ / _ \ '__| | | / __|
       / /___  __/ |  | |_) |  __/ |  | |_| \__ \\
       \____/\___|_|  |_.__/ \___|_|   \__,_|___/
"""

init(autoreset=True)

if __name__ == '__main__':
    print(Fore.GREEN + tool_name)
    print("       Developed by: " + Fore.GREEN + __author__)
    startTime = datetime.now()
    main()
    print("\n")
    print(datetime.now() - startTime)