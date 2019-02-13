from flask import Flask, redirect, url_for, request, jsonify
import geoip2.database
import psutil
app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Hello World!'


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
        'leftAddr': process.laddr,
        'rightAddr': process.raddr,
        'PID': process.pid,
        'status': process.status,
        'country': country
    }


def getcountry(ip):
    reader = geoip2.database.Reader("./static/ipdb.mmdb")
    return reader.country(ip).country.name


@app.route('/getProcesses', methods=['POST'])
def getprocesses():
    if request.method == 'POST':
        processes = psutil.net_connections()
        result = list(map(convert, processes))
        return jsonify(
            {
                "processes": result
            }
        )


if __name__ == '__main__':
    app.run(debug=True)

