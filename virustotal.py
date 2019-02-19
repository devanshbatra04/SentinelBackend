import psutil
import requests
from sentinelbackend.utils import hash_file
from sentinelbackend.models import addScheduledFile


def quickScan(file):
    params = {'apikey': 'd21b1c0487ea217eda6e715bd9a6663c05c7a1655a3167767c0d85528a402344',
              'resource': hash_file(file)}
    headers = {"Accept-Encoding": "gzip, deflate",
               "User-Agent": "gzip,  My Python requests library example client or username"}
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        json_response = response.json()

        return {
            'total scans': json_response.get('total'),
            'positives': json_response.get('positives'),
            'scan date': json_response.get('scan_date'),
            'message': json_response.get('verbose_msg'),
            'file': file
        }
    except:
        return {
            'message': 'Too many VirusTotal requests, try again later'
        }


def lookup_process(id):
    file_list = psutil.Process(int(id)).open_files()
    open_files = map(lambda x: x.path, file_list)
    return list(map(lambda file: quickScan(file), list(open_files)))


def adv_scan(filePath):
    params = {'apikey': 'd21b1c0487ea217eda6e715bd9a6663c05c7a1655a3167767c0d85528a402344'}
    files = {'file': (filePath.split('/')[-1], open(filePath, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    try:
        json_response = response.json()
        if json_response["verbose_msg"] == "Scan request successfully queued, come back later for the report":
            addScheduledFile(filePath, json_response["sha1"])
        return {
            'message': json_response["verbose_msg"]
        }
    except:
        print(json_response)
        return {
            'message': 'Too many VirusTotal requests, try again later'
        }
