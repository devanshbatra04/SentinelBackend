from sentinelbackend import db
from flask_sqlalchemy import SQLAlchemy
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
    user = Blacklist(ip=ip, port=port)
    os.system('echo root | sudo -S iptables -D INPUT -s ' + ip + ' -j DROP')
    db.session.commit()


# db.drop_all()
# db.create_all()
# addToBlacklist()
# removeFromBlacklist()
