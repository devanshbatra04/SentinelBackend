import psutil
import requests
from sentinelbackend.utils import hash_file
from sentinelbackend.models import addScheduledFile


def quickScan(file):
    params = {'apikey': 'b93c0b8303dce792601b675ad8cd05b4366b2841a9261115ad4ad6a88398d20d',
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

def scanIp(ip):
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'ip': str(ip), 'apikey': 'b93c0b8303dce792601b675ad8cd05b4366b2841a9261115ad4ad6a88398d20d'}
    response = requests.get(url, params=params)
    print(response)
    json_response = response.json()
    print(json_response)

def adv_scan(filePath):
    params = {'apikey': 'b93c0b8303dce792601b675ad8cd05b4366b2841a9261115ad4ad6a88398d20d'}
    files = {'file': (filePath.split('/')[-1], open(filePath, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    try:
        json_response = response.json()
        if json_response["verbose_msg"] == "Scan request successfully queued, come back later for the report":
            addScheduledFile(filePath, json_response["sha1"], user="Devansh")
        return {
            'message': json_response["verbose_msg"]
        }
    except:
        print(json_response)
        return {
            'message': 'Too many VirusTotal requests, try again later'
        }
