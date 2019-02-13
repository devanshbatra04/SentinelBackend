import psutil
import requests
from sentinelbackend.utils import hash_file


def lookup_process(id):
    file_list = psutil.Process(int(id)).open_files()
    open_files = map(lambda x: x.path, file_list)
    for data in open_files:

        params = {'apikey': 'd21b1c0487ea217eda6e715bd9a6663c05c7a1655a3167767c0d85528a402344',
                  'resource': hash_file(data)}
        headers = {"Accept-Encoding": "gzip, deflate",
                   "User-Agent": "gzip,  My Python requests library example client or username"}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        json_response = response.json()
        print(json_response)

