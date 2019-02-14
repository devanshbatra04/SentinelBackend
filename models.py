from sentinelbackend import db
from sentinelbackend.utils import hash_file
import os
import iptc


class Blacklist(db.Model):
    # sno = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String, primary_key=True)
    port = db.Column(db.String(5), nullable=False)


class scheduledFiles(db.Model):
    file = db.Column(db.String, primary_key=True)
    hash = db.Column(db.String)


def addToBlacklist(ip, port='*'):
    user = Blacklist(ip=ip, port=port)
    rule = iptc.Rule()
    rule.protocol = 0
    rule.src = str(ip)
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)
    db.session.add(user)
    db.session.commit()


def removeFromBlacklist(ip, port='*'):
    user = Blacklist.query.filter_by(ip=ip)
    user.delete()
    rule = iptc.Rule()
    rule.protocol = 0
    rule.src = str(ip)
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.delete_rule(rule)
    db.session.commit()


def getRules():
    return list(map(lambda x: {
        "ip": x.ip,
        "port": x.port
    }, Blacklist.query.all()))


def addScheduledFile(filepath, hash):
    newFile = scheduledFiles(file=filepath, hash=hash)
    db.session.add(newFile)
    db.session.commit()

db.drop_all()
db.create_all()
# addToBlascklist()
# removeFromBlacklist()
