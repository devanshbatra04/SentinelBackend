import sqlalchemy
from sentinelbackend.utils import hash_file
from sentinelbackend import db
import os
import datetime

if os.name != 'nt':
    import iptc

class Blacklist(db.Model):
    # sno = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String, primary_key=True)
    port = db.Column(db.String(6), primary_key=True)

class badIP(db.Model):
    # sno = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String, primary_key=True)
    count = db.Column(db.Integer)

def getbadIphealth(ip):
    if ip == 0:
        return 0
    result = list(badIP.query.filter_by(ip=ip))
    if len(result) > 0:
        return 6 + int((result.count % 10) / 5) if result.count > 5 else result.count
    else:
        return 0

class scheduledFiles(db.Model):
    file = db.Column(db.String, primary_key=True)
    hash = db.Column(db.String)
    time = db.Column(db.String)
    user = db.Column(db.String)

class badProcess(db.Model):
    PID = db.Column(db.Integer, primary_key=True)
    IP = db.Column(db.String, primary_key=True)
    positives = db.Column(db.Integer)
    totals = db.Column(db.Integer)

def addToBlacklist(ip, port):
    user = Blacklist(ip=ip, port=port)
    try:
        db.session.add(user)
        db.session.commit()
        if port != '*':
            command = ("iptables -A INPUT -p tcp --sport {} -s {} -j DROP").format(str(port), str(ip))
            if os.name == 'nt':
                command = "netsh advfirewall firewall add rule name=IPblock dir=in protocol=tcp remoteip={} localport={} action=block".format(ip, port)
                print(command)
            os.system(command)
            return "blocked"
        else:
            if os.name == 'nt':
                command = "netsh advfirewall firewall add rule name=IPblock dir=in protocol=tcp remoteip={} action=block".format(ip)
                print(command)
                os.system(command)
                return "blocked"
            rule = iptc.Rule()
            rule.protocol = 0
            rule.src = str(ip)
            target = iptc.Target(rule, "DROP")
            rule.target = target
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            chain.insert_rule(rule)
        return "blocked"
    except sqlalchemy.exc.IntegrityError:
        return "ip {} is already blocked on {} port".format(ip, port if port != '*' else "all")


def removeFromBlacklist(ip, port):
    if os.name == 'nt':
        user = Blacklist.query.filter_by(ip=ip).filter_by(port=port)
        user.delete()
        db.session.commit()
        command = "netsh advfirewall firewall delete rule name=IPblock dir=in protocol=tcp remoteip={} localport={}".format(ip, port)
        if port=='*':
            command = "netsh advfirewall firewall delete rule name=IPblock dir=in protocol=tcp remoteip={}".format(ip)
        os.system(command)
        return "unblocked"
    if port != '*':
        user = Blacklist.query.filter_by(ip=ip).filter_by(port=port)
        check = 0 if len(list(user)) == 0 else 1
        if check == 1:
            command = ("iptables -D INPUT -p tcp --sport {} -s {} -j DROP").format(str(port), str(ip))
            os.system(command)
            user.delete()
            db.session.commit()
            return "unblocked"
        else:
            return "no such rule present"
    else:
        blockedIPlist = Blacklist.query.filter_by(ip = ip)
        for blackList in blockedIPlist:
            if blackList.port == '*':
                rule = iptc.Rule()
                rule.protocol = 0
                rule.src = str(ip)
                target = iptc.Target(rule, "DROP")
                rule.target = target
                chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
                chain.delete_rule(rule)
            else:
                command = ("iptables -D INPUT -p tcp --sport {} -s {} -j DROP").format(str(blackList.port), str(blackList.ip))
                os.system(command)
        blockedIPlist.delete()
        db.session.commit()
        return "unblocked"

def getRules():
    return list(map(lambda x: {
        "ip": x.ip,
        "port": x.port
    }, Blacklist.query.all()))


def getScheduledFiles():
    return list(map(lambda x: {
        "file": x.file,
        "hash": x.hash,
        "time": x.time,
        "user": x.user
    }, scheduledFiles.query.all()))


def addScheduledFile(filepath, hash, user="Devansh"):
    print(str(datetime.datetime.now()), user)
    newFile = scheduledFiles(file=filepath, hash=hash, time=str(datetime.datetime.now()), user=user)
    db.session.add(newFile)
    db.session.commit()

def removeFileFromScheduled(filepath):
    file = scheduledFiles.query.filter_by(file=filepath)
    file.delete()
    db.session.commit()

def badIPdetected(ip):
    oldIp = badIP.query.filter_by(ip=ip)
    # print(list(oldIp)[0])
    if oldIp is None or len(list(oldIp)) == 0:
        newIp = badIP(ip=ip, count=1)
        db.session.add(newIp)
        db.session.commit()
    else:
        ip = oldIp.first()
        ip.count = ip.count + 1
        db.session.commit()
        pass


# db.drop_all()

db.create_all()
# addToBlascklist()
# removeFromBlacklist()
# badIPdetected("12.12.12.12")
