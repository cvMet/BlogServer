from flask import Flask
from flask import request
import subprocess
import hmac
import os
import json

app = Flask(__name__)


def verify_sha256(data: bytes, signature: str) -> bool:
    key = os.getenv('SECRET_TOKEN', default='123456789')
    hash_obj = hmac.new(key.encode('utf-8'), msg=data, digestmod='sha256')
    return hmac.compare_digest('sha256=' + hash_obj.hexdigest(), signature)


@app.route('/')
def hello_world():
    print(request.data)
    return 'Hello World!'


@app.route('/hook', methods=["POST"])
def json_request():
    try:
        signature = request.headers['X-Hub-Signature-256']
    except KeyError:
        return 'format error', 401
    data = request.data

    # 验证秘钥
    if not verify_sha256(data, signature):
        return 'sha256 verify error', 401

    json_data = json.loads(data)

    # 使用zen来区分新建还是更新
    try:
        zen = json_data['zen']
    except KeyError:
        zen = None

    full_name = json_data['repository']['full_name']
    cwd = './static/blog/{}'.format(full_name)

    if zen is None:
        # 更新仓库
        pop = subprocess.Popen('git pull', cwd=cwd, shell=True)
        pop.wait()
    else:
        # 新建文件夹
        pop = subprocess.Popen('mkdir -p {}'.format(cwd), shell=True)
        pop.wait()
        # clone 仓库
        token = os.getenv('GITHUB_TOKEN', default='')
        pop = subprocess.Popen(
            'git clone https://{}@github.com/{}.git'.format(token, full_name), cwd='{}/..'.format(cwd), shell=True)
        pop.wait()

    return '200'


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=25001,
        debug=True
    )
