from flask import Flask
app = Flask(__name__)
from flask_sqlalchemy import SQLAlchemy
import os
if os.name == "nt"
  app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
else:
  app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)


from sentinelbackend import routes
from sentinelbackend.models import addToBlacklist
