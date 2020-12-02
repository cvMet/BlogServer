from flask import Flask
from flask import request
import subprocess
import hmac
import os

app = Flask(__name__)


def verify_sha256(data: bytes, signature: str) -> bool:
    key = os.getenv('SECRET_TOKEN', default='123456789')
    hash_obj = hmac.new(key.encode('utf-8'), msg=data, digestmod='sha256')
    return hmac.compare_digest('sha256=' + hash_obj.hexdigest(), signature)


@app.route('/')
def hello_world():
    print(request.data)
    return 'Hello World!'


@app.route('/json', methods=["POST"])
def json_request():
    # 接收处理json数据请求
    try:
        signature = request.headers['X-Hub-Signature-256']
    except KeyError:
        return 'format error', 401
    data = request.data

    if not verify_sha256(data, signature):
        return 'sha256 verify error', 401

    pop = subprocess.Popen('git pull', cwd='./static/blog', shell=True)
    pop.wait()
    return '200'


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=25001,
        debug=True
    )
