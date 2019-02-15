from pkg_resources import resource_filename
import psutil
import geoip2.database
import hashlib

def convert(process):
    country = ''
    try:
        if process.raddr and process.raddr.ip == '127.0.0.1':
            country = "local address"
        elif process.raddr:
            country = getcountry(process.raddr.ip)
    except:
        country = "could not trace in current database"

    return {
        # TODO return correct connection type/protocol also
        'localAddr': process.laddr,
        'remoteAddr': process.raddr,
        'PID': str(process.pid),
        'status': process.status,
        'country': country,
        "Pname": psutil.Process(process.pid).name(),
        "User": psutil.Process(process.pid).username(),
        "cType": "tcp"
    }


def getcountry(ip):
    if str(ip).__contains__("192.168"):
        return "local area network"
    elif str(ip) == '127.0.0.1' or str(ip) == '0.0.0.0':
        return "localhost"
    reader = geoip2.database.Reader(resource_filename(__name__, "./static/ipdb.mmdb"))
    return reader.country(ip).country.name


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
