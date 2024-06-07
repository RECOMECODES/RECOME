import json
import os
import shutil
import subprocess
import time

import yaml
from flask import Flask, request

app = Flask(__name__)
process_running = False


@app.route('/')
def hello():
    return 'Hello, World!'


def overwrite_yml(yml_change_dict):
    if os.path.exists("config.default.yml"):
        with open("config.default.yml", "r") as f:
            config = yaml.safe_load(f)
        for key, value in yml_change_dict.items():
            config[key] = value
        with open("config.yml", "w") as f:
            yaml.dump(config, f)
    else:
        raise "config.default.yml not found"


@app.route('/process')
def process():
    global process_running

    if not process_running:
        process_running = True
        try:
            if json.loads(request.args.get('local', 'false')):
                use_local = True
                local_path = request.args.get('path', '')
            else:
                use_local = False
                git_url = request.args.get('git_url', '')
                branch = request.args.get('branch', '')
            overwrite_dict = {
                "metrics_choice": json.loads(request.args.get('metrics_choice', '[0, 2]')),
                "target_recall": float(request.args.get('target_recall', '0.9')),
                "hash_sim_threshold": float(request.args.get('hash_sim_threshold', '0.7')),
                "use_full_set": json.loads(request.args.get('use_full_set', 'false')),
                "bypass_metrics_filter": json.loads(request.args.get('bypass_metrics_filter', 'false')),
                "bypass_patch_compare": json.loads(request.args.get('bypass_patch_compare', 'false'))
            }
            overwrite_yml(overwrite_dict)

            if not use_local:
                if git_url and branch:
                    git_name = os.path.basename(git_url.rstrip('/'))
                    subprocess.call('git clone --branch %s --depth=1 %s' % (branch, git_url), shell=True)
                    path = git_name
                else:
                    process_running = False
                    return json.dumps({'Error': 'Missing git_url or branch parameter.'}), 400
            else:
                if os.path.exists(local_path):
                    path = local_path
                else:
                    process_running = False
                    return json.dumps({'Error': 'Local Path Not Exist.'}), 400

            start_time = time.time()
            code = subprocess.call('python3 main.py %s' % path, shell=True)
            end_time = time.time()
            if not use_local:
                shutil.rmtree(git_name)

            if code != 0:
                process_running = False
                return json.dumps({'Error': 'Detect Failed'}), 500
            if not use_local:
                name = git_name
            else:
                name = path.rstrip("/").split("/")[-1]
            log_file = f'result/{name}/{name}.json'
            info_file = f'result/{name}/{name}.detect_info.json'
            if os.path.exists(log_file):

                with open(log_file, 'r') as f:
                    orig_vul_json = json.load(f)

                vul_cnt = orig_vul_json["all"]
                vul_json = {}
                for vul in orig_vul_json["vul"]:
                    if vul["dst"] not in vul_json:
                        vul_json[vul["dst"]] = vul["sim"]
                    else:
                        vul_json[vul["dst"]].extend(vul["sim"])

                if os.path.exists(info_file):
                    with open(info_file, "r") as f:
                        detect_info = json.load(f)
                else:
                    detect_info = {}

                response = json.dumps(
                    {"time": end_time - start_time, "vul": vul_json, "vul_cnt": vul_cnt, "detect_info": detect_info})
            else:
                return json.dumps({'Error': 'Log file not found.'}), 500

            process_running = False
            return response

        except Exception as e:
            process_running = False
            return json.dumps({'Error': str(e)}), 500

    else:
        return json.dumps({'Error': 'Another process is already running.'}), 429


if __name__ == '__main__':
    app.run("0.0.0.0", port=8000)
