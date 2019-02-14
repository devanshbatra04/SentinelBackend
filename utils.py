from pkg_resources import resource_filename
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
        print("could not trace ip " + str(process.raddr.ip))

    return {
        'localAddr': process.laddr,
        'remoteAddr': process.raddr,
        'PID': process.pid,
        'status': process.status,
        'country': country
    }


def getcountry(ip):
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
