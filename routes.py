import os
from flask import request, jsonify
from sentinelbackend import app
from sentinelbackend.utils import convert, getcountry, fetchScanResults, getSuspectFiles
from sentinelbackend.virustotal import lookup_process, adv_scan, quickScan, scanIp as virusTotalIPScan
from sentinelbackend.models import addToBlacklist, removeFromBlacklist, getRules, getScheduledFiles, removeFileFromScheduled
import psutil
from os.path import expanduser

@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/getProcesses', methods=['GET', 'POST'])
def getprocesses():
    if request.method == 'POST':
        processes = psutil.net_connections()
        result = list(map(convert, processes))
        return jsonify(
            {
                "processes": list(filter(lambda x: len(x['remoteAddr']), result))
            }
        )

@app.route('/getSystemUsage', methods=['POST'])
def getsystemUsage():
    # TODO something wrong here
    n_c = tuple(psutil.disk_io_counters())
    n_b = tuple(psutil.net_io_counters())
    print(n_c, n_b)
    return jsonify(
        {
            "num_process": str(len(list(psutil.net_connections()))),
            "cpu_usage": str(psutil.cpu_percent(interval=None, percpu=False)),
            "memory_usage": str(dict(psutil.virtual_memory()._asdict())["percent"]),
            "disk_io_percent": [(100.0*n_c[i+1]) / (n_c[i] if n_c[i] != 0 else 1) for i in range(0, len(n_c)-1, 2)],
            "network_io_percent": [(100.0*n_b[i+1]) / (n_b[i] if n_b[i] != 0 else 1) for i in range(0, len(n_b)-1, 2)]
        }
    )

@app.route('/getProcessUsage', methods=['POST'])
def getProcessUsageStats():
    # TODO implement full function
    if request.method == 'POST':
        pid = request.form.get('PID')
        return jsonify(
            {
                "cpu_uasage":"40",
                "memory_usage": "40",
                "disk_io_percent": [(100.0 * n_c[i + 1]) / (n_c[i] if n_c[i] != 0 else 1) for i in range(0, len(n_c) - 1, 2)],
                "network_io_percent": ""
            }
        )

@app.route('/lookupProcess', methods=['POST'])
def quickscan():
    if request.method == 'POST':
        return jsonify(
            {
                "results":  lookup_process(request.form.get('PID'))

            }
        )


@app.route('/blockIP', methods=['POST'])
def block_ip():
    if request.method == 'POST':
        response = addToBlacklist(request.form.get('IP'), request.form.get('port') if request.form.get('port') != None else "*")
        return response


@app.route('/unblockIP', methods=['POST'])
def unblock_ip():
    if request.method == 'POST':
        response = removeFromBlacklist(request.form.get('IP'), request.form.get('port') if request.form.get('port') != None else "*")
        return response


@app.route('/getRules', methods=['POST'])
def get_rules():
    return jsonify(
        {
            "rules": list(getRules())
        }
    )


@app.route('/advancedScan', methods=['POST'])
def advanced_scan():
    return jsonify(adv_scan(request.form.get('filepath')))


@app.route('/getScheduledFiles', methods=['POST'])
def getS():
    return jsonify(
        {
            "files": getScheduledFiles()
        }
    )

@app.route('/removeFromScheduledFilesList', methods=['POST'])
def removeFromList():
    removeFileFromScheduled(request.form.get('filepath'))
    return "removed from list"


@app.route('/deleteFile', methods=['POST'])
def deleteme():
    os.remove(request.form.get('filepath'))
    return "deleted"

@app.route('/scanIP', methods=['POST'])
def scanIP():
    return jsonify({
        "results": virusTotalIPScan(request.form.get('IP'))
    })


@app.route('/getReport', methods=['POST'])
def quick_scan():
    return jsonify(quickScan(request.form.get('filepath')))


@app.route('/killProcess', methods=['POST'])
def killProcess():
    if request.method == 'POST':
        try:
            pid = int(request.form.get('PID'))
            process = psutil.Process(pid)
            process.kill()
            return "process terminated"
        except:
            return "some error occured. Are you sure you have sudo priviledge"


@app.route('/getchkrScanResults', methods=['POST'])
def chkscan():
    if request.method == 'POST':
        return jsonify({
            "results": fetchScanResults("~/chkrootkitLogs/fileLog.txt")
        })


@app.route('/chkrScan', methods=['POST'])
def scan():
    if request.method == 'POST':
        os.system(expanduser("~/chkrootkit2 -q"))
    return "Scan Complete"


@app.route('/getSuspectFiles', methods=['POST'])
def getf():
    if request.method == 'POST':
        ans = []
        for e in getSuspectFiles(' '):
            if isinstance(e, list):
                for i in e:
                    ans.append(i)
            else:
                ans.append(e)
        return jsonify(
            {
                "files": ans
            })