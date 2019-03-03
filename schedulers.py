import psutil
import datetime
from sentinelbackend.utils import getCompany
import requests
from sentinelbackend.models import badIPdetected
from sentinelbackend.virustotal import lookup_process
from apscheduler.schedulers.background import BackgroundScheduler
import geoip2

registeredCompanies = ['microsoft', 'facebook', 'yahoo']

def scanIp(ip):
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'ip': str(ip), 'apikey': 'b93c0b8303dce792601b675ad8cd05b4366b2841a9261115ad4ad6a88398d20d'}
    response = requests.get(url, params=params)
    if response.status_code != 200:
        return

    json_response = response.json()

    if json_response.get("detected_downloaded_samples") is not None and len(json_response.get("detected_downloaded_samples")) != 0:
        # Mark as unsafe
        badIPdetected(ip)



class Sets:
    # Class Variable
    def __init__(self):
        self.ipSet = set()  # Instance Variable
        self.vtSet = set()


currentSets = Sets()
print(currentSets.ipSet)


def ipscanner():
    for ip in list(map(lambda z: z.ip, filter(lambda y: len(y) ==2, (map(lambda x: x.raddr, psutil.net_connections()))))):
        if ip not in currentSets.ipSet:
            scanIp(ip)
            currentSets.ipSet.add(ip)

def quickscanner():

    for process in list(psutil.net_connections()):
        if process not in currentSets.vtSet:
            try:
                currentSets.vtSet.add(process)
                company = getCompany(process.raddr.ip)
                if company == 'localhost' or company == 'local address':
                    continue
                if company not in registeredCompanies:
                    print(lookup_process(process.pid) if process.pid != None else "")
            except geoip2.errors.AddressNotFoundError:
                print(lookup_process(process.pid) if process.pid != None else "")
            except AttributeError:
                continue
            # if (getCompany(ip))
            # currentSets.vtSet.add(ip)



scheduler = BackgroundScheduler()
scheduler.add_job(func=ipscanner, trigger="interval", seconds=4)
# scheduler.add_job(func=quickscanner, trigger="interval", seconds=600)
# scheduler.start()

