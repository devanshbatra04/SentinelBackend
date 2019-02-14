from flask import request, jsonify
from sentinelbackend import app
from sentinelbackend.utils import convert, getcountry
from sentinelbackend.virustotal import lookup_process
from sentinelbackend.models import addToBlacklist, removeFromBlacklist, getRules
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


@app.route('/blockIP', methods=['POST'])
def block_ip():
    if request.method == 'POST':
        addToBlacklist(request.form.get('IP'))
    return "blocked"


@app.route('/unblockIP', methods=['POST'])
def unblock_ip():
    if request.method == 'POST':
        removeFromBlacklist(request.form.get('IP'))
    return "unblocked"


@app.route('/getRules', methods=['POST'])
def get_rules():
    return jsonify(
        {
            "rules": list(getRules())
        }
    )
