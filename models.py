import sqlalchemy

from sentinelbackend import db
from sentinelbackend.utils import hash_file
import os
import iptc
import datetime


class Blacklist(db.Model):
    # sno = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String, primary_key=True)
    port = db.Column(db.String(6), primary_key=True)


class scheduledFiles(db.Model):
    file = db.Column(db.String, primary_key=True)
    hash = db.Column(db.String)
    time = db.Column(db.String)
    user = db.Column(db.String)


def addToBlacklist(ip, port):
    user = Blacklist(ip=ip, port=port)
    try:
        db.session.add(user)
        db.session.commit()
        if port != '*':
            command = ("iptables -A INPUT -p tcp --sport {} -s {} -j DROP").format(str(port), str(ip))
            os.system(command)
        else:
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

# db.drop_all()
db.create_all()
# addToBlascklist()
# removeFromBlacklist()
