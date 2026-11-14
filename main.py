import time
import re
import json
import base64
import hashlib
import rsa
import requests
import os

# 变量 ty_username（手机号）, ty_password（密码）
ty_username = os.getenv("TYYP_USERNAME", "").split('&')
ty_password = os.getenv("TYYP_PSW", "").split('&')

BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
B64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def int2char(a):
    return BI_RM[a]


def b64tohex(a):
    d = ""
    e = 0
    c = 0
    for ch in a:
        if ch != "=":
            v = B64MAP.index(ch)
            if e == 0:
                e = 1
                d += int2char(v >> 2)
                c = 3 & v
            elif e == 1:
                e = 2
                d += int2char(c << 2 | v >> 4)
                c = 15 & v
            elif e == 2:
                e = 3
                d += int2char(c)
                d += int2char(v >> 2)
                c = 3 & v
            else:
                e = 0
                d += int2char(c << 2 | v >> 4)
                d += int2char(15 & v)
    if e == 1:
        d += int2char(c << 2)
    return d


def rsa_encode(j_rsakey, string):
    rsa_key = f"-----BEGIN PUBLIC KEY-----\n{j_rsakey}\n-----END PUBLIC KEY-----"
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
    result = b64tohex((base64.b64encode(rsa.encrypt(f'{string}'.encode(), pubkey))).decode())
    return result


def login(username_str, password_str):
    s = requests.Session()
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    })

    # 直接请求统一认证跳转入口，绕过失效的旧版 WAP 页面
    login_entry = "https://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https://cloud.189.cn/web/redirect.html"
    r = s.get(login_entry, timeout=10)

    # 提取登录页关键参数
    captcha_match = re.findall(r"captchaToken' value='(.+?)'", r.text)
    lt_match = re.findall(r'lt = "(.+?)"', r.text)
    return_url_match = re.findall(r"returnUrl= '(.+?)'", r.text)
    param_id_match = re.findall(r'paramId = "(.+?)"', r.text)
    rsa_key_match = re.findall(r'j_rsaKey" value="(\S+)"', r.text, re.M)

    if not (captcha_match and lt_match and param_id_match and rsa_key_match):
        raise RuntimeError("未能获取到登录页加密参数，可能触发了验证码或登录入口已变更")

    captchaToken = captcha_match[0]
    lt = lt_match[0]
    returnUrl = return_url_match[0] if return_url_match else "https://cloud.189.cn/web/redirect.html"
    paramId = param_id_match[0]
    j_rsakey = rsa_key_match[0]

    s.headers.update({"lt": lt})

    enc_username = rsa_encode(j_rsakey, username_str)
    enc_password = rsa_encode(j_rsakey, password_str)

    url = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
    headers = {
        'Referer': 'https://open.e.189.cn/',
        'Origin': 'https://open.e.189.cn',
    }
    data = {
        "appKey": "cloud",
        "accountType": '01',
        "userName": f"{{RSA}}{enc_username}",
        "password": f"{{RSA}}{enc_password}",
        "validateCode": "",
        "captchaToken": captchaToken,
        "returnUrl": returnUrl,
        "mailSuffix": "@189.cn",
        "paramId": paramId
    }

    r = s.post(url, data=data, headers=headers, timeout=10)
    res_json = r.json()
    print(f"登录状态: {res_json.get('msg', res_json)}")

    if res_json.get('result') != 0:
        raise RuntimeError(f"登录失败: {res_json.get('msg')}")

    redirect_url = res_json['toUrl']
    s.get(redirect_url, timeout=10)
    return s


def print_growth_size(idx, response):
    try:
        data = response.json()
        if "errorCode" in data:
            print(f"第{idx}次抽奖失败：{data.get('errorMsg', '可能是次数不足了')}")
        else:
            print(f"第{idx}次抽奖成功：获得{data.get('prizeName', '未知奖品')}")
    except Exception as e:
        print(f"第{idx}次抽奖返回解析异常: {e}")


def run_account(username_str, password_str):
    s = login(username_str, password_str)
    rand = str(round(time.time() * 1000))

    # 1. 每日签到接口（注意移除固定写死的 Host 头，避免 api.cloud.189.cn 拒绝请求）
    surl = f'https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K'
    app_headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
        'Referer': 'https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1',
        'Accept': 'application/json, text/plain, */*',
    }

    response = s.get(surl, headers=app_headers, timeout=10)
    sign_data = response.json()
    netdiskBonus = sign_data.get('netdiskBonus', 0)
    if str(sign_data.get('isSign')).lower() == "false":
        print(f"未签到，签到获得{netdiskBonus}M空间")
    else:
        print(f"已经签到过了，本次获得{netdiskBonus}M空间")

    # 2. 抽奖任务接口
    tasks = [
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN',
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN',
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_2022_FLDFS_KJ&activityId=ACT_SIGNIN',
    ]
    for idx, task_url in enumerate(tasks, start=1):
        res = s.get(task_url, headers=app_headers, timeout=10)
        print_growth_size(idx, res)


if __name__ == "__main__":
    for i in range(len(ty_username)):
        if not ty_username[i].strip():
            continue
        print(f'开始执行帐号{i + 1}')
        try:
            run_account(ty_username[i].strip(), ty_password[i].strip())
        except Exception as e:
            print(f'帐号{i + 1}执行出错: {e}')
