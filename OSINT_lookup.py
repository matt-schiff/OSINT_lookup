import requests
import json
import urllib3
import os
import ipaddress
import sys
from datetime import datetime, timedelta

def validate_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def process_date(date):
    dateobj = datetime.strptime(date,"%Y-%m-%dT%H:%M:%S+00:00")
    return [datetime.strftime(dateobj, "%Y-%m-%d %H:%M:%S UTC"), dateobj < datetime.now() - timedelta(days=14), dateobj < datetime.now() - timedelta(days=30)]
    
def process_IP(inputIPs, isColor):
    outputStr = ""
    inputIPs = inputIPs.replace(' ', ',')
    inputIPs = inputIPs.replace('\n', ',')
    inputIPList = inputIPs.split(',')
    for IP in inputIPList:
        if len(IP) > 0 and validate_ip_address(IP):
            vt = False
            ipdb = False
            ipdb_reported = False
            if isColor:
                outputStr += f"\033[95mIP Address: {IP}\033[0m\n"
            else:
                outputStr += f"IP Address: {IP}\n"
            if APIKEY_VIRUSTOTAL:
                url2 = f'https://www.virustotal.com/api/v3/ip_addresses/{IP}'
                r2 = requests.get(url2, verify = False, headers = {"x-apikey":APIKEY_VIRUSTOTAL})
                if r2.status_code == 200:
                    output2 = json.loads(r2.text)
                    vt = True
            if APIKEY_ABUSEIPDB:
                url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={IP}&maxAgeInDays=365'
                r = requests.get(url, verify = False, headers={"Key":APIKEY_ABUSEIPDB})
                if r.status_code != 200:
                    print(r.status_code)
                    print(r.text)
                    print("error in ABUSEIPDB")
                else:
                    output = json.loads(r.text)['data']
                    if output['isTor']:
                        if isColor:
                            outputStr += "\033[91mThis IP address has been reported to be a TOR Exit Node\033[0m\n"
                        else:
                            outputStr += "This IP address has been reported to be a TOR Exit Node"
                    ipdb = True
                    ipdb_reported = output['lastReportedAt'] and 1
            if ipdb and isColor:
                if int(output['abuseConfidenceScore']) < 1:
                    color = '\033[92m'
                elif int(output['abuseConfidenceScore']) < 33:
                    color = '\033[93m'
                else:
                    color = '\033[91m'
                outputStr += f"Abuse Confidence: {color}{output['abuseConfidenceScore']}%{noColor}\n"
            elif ipdb:
                outputStr += f"Abuse Confidence: {output['abuseConfidenceScore']}%\n"       
            try:
                if ipdb_reported and isColor:
                    if int(output['totalReports']) < 1:
                        color = '\033[92m'
                    elif int(output['totalReports']) < 5:
                        color = '\033[93m'
                    else:
                        color = '\033[91m'
                    date = process_date(output['lastReportedAt'])
                    outputStr += f"Number of reports: {color}{output['totalReports']}{noColor}\n"
                    if date[1]:
                        color = '\033[92m'
                    elif date[2]:
                        color = '\033[93m'
                    else:
                        color = '\033[91m'
                    outputStr += f"Last Reported: {color}{date[0]}{noColor}\n"
                elif ipdb_reported:
                    date = process_date(output['lastReportedAt'])
                    outputStr += f"Number of reports: {output['totalReports']}\n"
                    outputStr += f"Last Reported: {date[0]}\n"
                if vt and isColor:
                    if int(output2['data']['attributes']['reputation']) < 0:
                        color = '\033[91m'
                    elif int(output2['data']['attributes']['reputation']) < 1:
                        color = '\033[93m'
                    else:
                        color = '\033[92m'
                    outputStr += f"VT Community Score: {color}{output2['data']['attributes']['reputation']}{noColor}\n"
                    if int(output2['data']['attributes']['last_analysis_stats']['malicious']) < 1:
                        color = '\033[92m'
                    elif int(output2['data']['attributes']['last_analysis_stats']['malicious']) < 3:
                        color = '\033[93m'
                    else:
                        color = '\033[91m'
                    outputStr += f"VT Malicious Reports: {color}{output2['data']['attributes']['last_analysis_stats']['malicious']}{noColor}\n"
                    if int(output2['data']['attributes']['last_analysis_stats']['suspicious']) < 1:
                        color = '\033[92m'
                    elif int(output2['data']['attributes']['last_analysis_stats']['suspicious']) < 3:
                        color = '\033[93m'
                    else:
                        color = '\033[91m'
                    outputStr += f"VT Suspicious Reports: {color}{output2['data']['attributes']['last_analysis_stats']['suspicious']}{noColor}\n"
                    if int(output2['data']['attributes']['last_analysis_stats']['harmless']) < 1:
                        color = '\033[93m'
                    elif int(output2['data']['attributes']['last_analysis_stats']['harmless']) < 3:
                        color = '\033[93m'
                    else:
                        color = '\033[92m'
                    outputStr += f"VT Harmless Reports: {color}{output2['data']['attributes']['last_analysis_stats']['harmless']}{noColor}\n"
                elif vt:
                    outputStr += f"VT Community Score: {output2['data']['attributes']['reputation']}\n"
                    outputStr += f"VT Malicious Reports: {output2['data']['attributes']['last_analysis_stats']['malicious']}\n"
                    outputStr += f"VT Suspicious Reports: {output2['data']['attributes']['last_analysis_stats']['suspicious']}\n"
                    outputStr += f"VT Harmless Reports: {output2['data']['attributes']['last_analysis_stats']['harmless']}\n"
                if ipdb:
                    outputStr += f"Country: {output['countryCode']}\n"
                    outputStr += f"Domain: {output['domain']}\n"
                    outputStr += f"ISP: {output['isp']}\n"
                    outputStr += f"Usage Type: {output['usageType']}\n\n"
                
            except KeyError:
                print()
            try:
                if int(r.headers["X-RateLimit-Remaining"]) < 100:
                    print(f"Warning! {int(r.headers['X-RateLimit-Remaining'])} requests remaining today\n")
            except KeyError:
                pass
        else: 
            pass
    return outputStr

os.system("")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
noColor = '\033[0m'

APIKEY_ABUSEIPDB = ''
APIKEY_VIRUSTOTAL = ''

if len(sys.argv) > 1:
    if (sys.argv[1] == '-f' or sys.argv[1] == '--file') and len(sys.argv) == 3:
        f  = open(sys.argv[2], 'r')
        IPs = f.read()
        f.close()
        fn = sys.argv[2]
        fn = fn.split('.')
        fn[-2] += ('_processed')
        fn = '.'.join(fn)
        f = open(fn, 'w')
        f.write(process_IP(IPs, False))
        f.close()
        print(f'File has been written to {fn}')
        quit()
    if sys.argv[1] == '-u' or sys.argv[1] == '--usage':
        print(f"""\033[95mUSAGE: python3 {sys.argv[0]}\033[0m
IP Addresses (both IPv4 and IPv6) can be entered as a comma separated list, space separated list, or individually
This script will provide a warning if the limit of API calls available in a day drops below 100

\033[95mUSAGE: python3 {sys.argv[0]} -u/--usage\033[0m
Prints this usage message.

\033[95mUSAGE: python3 {sys.argv[0]} -f/--file [file]\033[0m
Processes a text file specified by [file] and outputs the results

""")
        quit()
        
if not APIKEY_ABUSEIPDB and not APIKEY_VIRUSTOTAL:
    print("\033[95mPlease update your API KEYs. Instructions for updating the API keys can be found in the python script.\033[0m")
    quit()

while(True):
    print("Paste IP Addresses (q to quit): ", end="")
    inputIPs = input()
    if inputIPs.lower() == "q":
        break
    print(process_IP(inputIPs, True))