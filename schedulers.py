import psutil
import datetime
import requests
from sentinelbackend.models import badIPdetected
registeredCompanies = ['google', 'microsoft', 'facebook', 'yahoo']
from apscheduler.schedulers.background import BackgroundScheduler


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



def getProcesstobeScanned():
    processes = psutil.net_connections()
    # processes = list(map(lambda x : {"process":x, "company":getCompany(x.raddr)}, processes))
    # toBeScanned = processes[processes['company'] not in registeredCompanies]
    # # toBeScanned = [processes[i] for i
    tempList = list()
    for process in processes:
        if process.raddr != None:
            tempList.append({"process": process, "company": getCompany(process.raddr)})
    processes = tempList
    tobeScanned = list()
    for process in processes:
        if process['company'] not in registeredCompanies:
            tobeScanned.append(process['process'])
    return tobeScanned


def startScan():
    tobeScanned = getProcesstobeScanned()
    print(tobeScanned)
    result = list()
    for process in tobeScanned:
        ip = process.raddr.ip
        if str(ip)._contains_("192.168"):
            result.append({"process": process, "status": "safe"})
        elif str(ip) == '127.0.0.1' or str(ip) == '0.0.0.0':
            result.append({"process": process, "status": "safe", "scan_time": str(datetime.datetime.now())})
        else:
            result.append({'process': process, "status": ("safe" if scanIp(str(ip)) >= 60 else "unsafe"),
                           "scan_time": str(datetime.datetime.now())})
    # print(result)
    saveinlogs(result)


def saveinlogs(result):
    f = open("demofile.txt", "a")
    f.write(result)


def getCompany(ip):
    if str(ip)._contains_("192.168"):
        return "local area network"
    elif str(ip) == '127.0.0.1' or str(ip) == '0.0.0.0':
        return "localhost"
    # reader = geoip2.database.Reader(resource_filename(_name_, "asndb.mmdb"))
    # return reader.asn(ip).autonomous_system_organization
    return "x"


def print_date_time():
    print(time.strftime("%A, %d. %B %Y %I:%M:%S %p"))


class Sets:
    # Class Variable
    def __init__(self):
        self.ipSet = set()  # Instance Variable
        self.vtSet = set()


currentSets = Sets()
print(currentSets.ipSet)


def ipscanner():
    print("I am running")
    # aip = "12.12.12.12"
    # scanIp(aip)
    # currentSets.ipSet.add(aip)
    for ip in list(map(lambda z: z.ip, filter(lambda y: len(y) ==2, (map(lambda x: x.raddr, psutil.net_connections()))))):
        if ip not in currentSets.ipSet:
            scanIp(ip)
            currentSets.ipSet.add(ip)


def quickscanner():
    pass


scheduler = BackgroundScheduler()
scheduler.add_job(func=ipscanner, trigger="interval", seconds=600)
scheduler.add_job(func=quickscanner, trigger="interval", seconds=600)
scheduler.start()
