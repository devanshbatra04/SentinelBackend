from flask import request, jsonify
from sentinelbackend import app
from sentinelbackend.utils import convert, getcountry
from sentinelbackend.virustotal import lookup_process
import psutil


@app.route('/')
def hello_world():
    return 'Hello World!'


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


@app.route('/quickScan', methods=['POST'])
def quickscan():
    if request.method == 'POST':
        lookup_process(request.form.get('PID'))
    return "bAS BSDK"