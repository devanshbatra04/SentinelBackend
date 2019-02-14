from sentinelbackend import db
import os


class Blacklist(db.Model):
    # sno = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String, primary_key=True)
    port = db.Column(db.String(5), nullable=False)


def addToBlacklist(ip, port='*'):
    user = Blacklist(ip=ip, port=port)
    os.system('echo root | sudo -S iptables -A INPUT -s ' + ip + ' -j DROP')
    db.session.add(user)
    db.session.commit()


def removeFromBlacklist(ip, port='*'):
    user = Blacklist.query.filter_by(ip=ip)
    user.delete()
    os.system('echo root | sudo -S iptables -D INPUT -s ' + ip + ' -j DROP')
    db.session.commit()


def getRules():
    return list(map(lambda x: {
        "ip": x.ip,
        "port": x.port
    }, Blacklist.query.all()))


# db.drop_all()
# db.create_all()
# addToBlascklist()
# removeFromBlacklist()
