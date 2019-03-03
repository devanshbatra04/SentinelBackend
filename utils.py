from pkg_resources import resource_filename
import psutil
import geoip2.database
import hashlib
from os.path import expanduser

def convertforWindows(pid):
    try:
        process = psutil.Process(pid).connections()[0]
        country = ''
        company = ''
        try:
            if process.raddr and process.raddr.ip == '127.0.0.1':
                country = company = "local address"
            elif process.raddr:
                country = getcountry(process.raddr.ip)
                company = getCompany(process.raddr.ip)
        except:
            country = "could not trace in current database"

        return {
            # TODO return correct connection type/protocol also
            'localAddr': process.laddr,
            'remoteAddr': process.raddr,
            'PID': str(pid),
            'status': process.status,
            'country': country,
            "Pname": psutil.Process(pid).name(),
            "User": psutil.Process(pid).username(),
            "cType": "tcp",
            'company': company
        }
    except:
        pass
    


def getcountry(ip):
    if str(ip).__contains__("192.168"):
        return "local area network"
    elif str(ip) == '127.0.0.1' or str(ip) == '0.0.0.0':
        return "localhost"
    reader = geoip2.database.Reader(resource_filename(__name__, "./static/ipdb.mmdb"))
    return reader.country(ip).country.name

def getCompany(ip):
    if str(ip).__contains__("192.168"):
        return "local area network"
    elif str(ip) == '127.0.0.1' or str(ip) == '0.0.0.0':
        return "localhost"
    reader = geoip2.database.Reader(resource_filename(__name__, "./static/asndb.mmdb"))
    return reader.asn(ip).autonomous_system_organization


def hash_file(filename):
    h = hashlib.sha1()

    # open file for reading in binary mode
    with open(filename,'rb') as file:
        # loop till the end of the file
        chunk = 0
        while chunk != b'':
            # read only 1024 bytes at a time
            chunk = file.read(1024)
            h.update(chunk)
    # return the hex representation of digest
    return str(h.hexdigest())


def fetchScanResults(path):
    f = open(expanduser(path), "r")
    contents = f.read()
    contents = contents.split('\n')
    # print(list(map(lambda x: x, contents)))
    # def filterer(x):
    #     return x.includes(" : ")
    # list(lambda y: y.split(" : "), contents)
    return list(map(lambda y:
                   {
                       "infection_name" : y.split(" : ")[0],
                       "scan_result": y.split(" : ")[1]
    }, filter(lambda x: (" : ") in x, contents)))


def getSuspectFiles(path):
    path = expanduser("~/chkrootkitLogs/suspectedPaths.txt")
    f = open(expanduser(path), "r")
    contents = f.read()
    contents = contents.split('\n')
    contents = list(map(lambda c: c.split(' '), contents))
    return contents
