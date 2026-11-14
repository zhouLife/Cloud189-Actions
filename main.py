import time
import json
import base64
import rsa
import requests
import os

# 支持多账号（用 & 分隔）
ty_username = [u.strip() for u in os.getenv("TYYP_USERNAME", "").split('&') if u.strip()]
ty_password = [p.strip() for p in os.getenv("TYYP_PSW", "").split('&') if p.strip()]
# 可选：如果 GitHub 海外 IP 触发验证码，可填入抓包获取的 COOKIE_LOGIN_USER（多账号同样用 & 分隔）
ty_cookies = [c.strip() for c in os.getenv("TYYP_COOKIE", "").split('&') if c.strip()]

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
    return b64tohex((base64.b64encode(rsa.encrypt(string.encode(), pubkey))).decode())


def login_by_password(username_str, password_str):
    """参考最新开源项目：直接调用官方开放平台 API 获取加密公钥与登录配置"""
    s = requests.Session()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Referer': 'https://open.e.189.cn/',
        'Origin': 'https://open.e.189.cn',
    }
    s.headers.update(headers)

    # 1. 获取动态 RSA 公钥
    enc_res = s.post(
        "https://open.e.189.cn/api/logbox/config/encryptConf.do",
        data={"appId": "cloud"},
        timeout=10
    ).json()
    pub_key = enc_res.get("data", {}).get("pubKey")
    if not pub_key:
        raise RuntimeError(f"获取加密公钥失败: {enc_res}")

    # 2. 获取登录初始化参数 (lt, paramId, reqId)
    # 先访问跳转接口拿到 lt 和 reqId
    redirect_res = s.get(
        "https://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https://cloud.189.cn/web/redirect.html",
        allow_redirects=True,
        timeout=10
    )
    # 从最终跳转 URL 中解析 query 参数
    from urllib.parse import urlparse, parse_qs
    query_params = parse_qs(urlparse(redirect_res.url).query)
    lt = query_params.get("lt", [""])[0]
    req_id = query_params.get("reqId", [""])[0]

    app_conf = s.post(
        "https://open.e.189.cn/api/logbox/oauth2/appConf.do",
        data={"version": "2.0", "appKey": "cloud"},
        headers={"lt": lt, "reqId": req_id},
        timeout=10
    ).json()

    conf_data = app_conf.get("data", {})
    param_id = conf_data.get("paramId")
    return_url = conf_data.get("returnUrl", "https://cloud.189.cn/web/redirect.html")
    if not param_id:
        raise RuntimeError(f"获取 appConf 失败: {app_conf}")

    # 3. 加密账号密码并提交登录
    enc_username = rsa_encode(pub_key, username_str)
    enc_password = rsa_encode(pub_key, password_str)

    login_data = {
        "version": "v2.0",
        "apToken": "",
        "appKey": "cloud",
        "accountType": "01",
        "userName": f"{{RSA}}{enc_username}",
        "password": f"{{RSA}}{enc_password}",
        "validateCode": "",
        "captchaToken": "",
        "returnUrl": return_url,
        "mailSuffix": "@189.cn",
        "dynamicCheck": "FALSE",
        "clientType": "1",
        "cb_SaveName": "0",
        "isOauth2": "false",
        "state": "",
        "paramId": param_id
    }

    r = s.post(
        "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do",
        data=login_data,
        headers={"lt": lt, "reqId": req_id},
        timeout=10
    )
    res_json = r.json()
    if res_json.get("result") != 0:
        raise RuntimeError(f"登录失败 (code={res_json.get('result')}): {res_json.get('msg')}")

    print(f"登录成功: {res_json.get('msg')}")
    s.get(res_json["toUrl"], timeout=10)
    return s


def login_by_cookie(cookie_str):
    """Cookie 免密模式（彻底规避海外 IP 验证码风控）"""
    s = requests.Session()
    # 兼容直接填 COOKIE_LOGIN_USER 的值，或填完整的 Cookie 字符串
    if "COOKIE_LOGIN_USER=" in cookie_str:
        for item in cookie_str.split(";"):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                s.cookies.set(k, v, domain=".cloud.189.cn")
    else:
        s.cookies.set("COOKIE_LOGIN_USER", cookie_str, domain=".cloud.189.cn")
    return s


def print_growth_size(idx, response):
    try:
        data = response.json()
        if "errorCode" in data:
            print(f"第{idx}次抽奖失败：{data.get('errorMsg', '次数不足或活动已结束')}")
        else:
            print(f"第{idx}次抽奖成功：获得{data.get('prizeName', '未知奖品')}")
    except Exception as e:
        print(f"第{idx}次抽奖返回解析异常: {e} | 原始内容: {response.text[:100]}")


def do_sign_and_draw(s):
    rand = str(round(time.time() * 1000))
    app_headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 11; SM-G9810 Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/92.0.4515.131 Mobile Safari/537.36 Ecloud/9.2.1 Android/30 clientId/355325117317828 clientModel/SM-G9810 clientChannelId/qq proVersion/1.0.6',
        'Referer': 'https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1',
        'Accept': 'application/json, text/plain, */*',
    }

    # 1. 每日签到
    surl = f'https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=9.2.1&model=SM-G9810'
    response = s.get(surl, headers=app_headers, timeout=10)
    sign_data = response.json()

    if "netdiskBonus" not in sign_data:
        raise RuntimeError(f"签到接口返回异常（可能登录态失效）: {sign_data}")

    netdiskBonus = sign_data.get('netdiskBonus', 0)
    if str(sign_data.get('isSign')).lower() == "false":
        print(f"未签到，签到获得 {netdiskBonus}M 空间")
    else:
        print(f"已经签到过了，本次获得 {netdiskBonus}M 空间")

    # 2. 每日抽奖任务
    tasks = [
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN',
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN',
        'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_2022_FLDFS_KJ&activityId=ACT_SIGNIN',
    ]
    for idx, task_url in enumerate(tasks, start=1):
        res = s.get(task_url, headers=app_headers, timeout=10)
        print_growth_size(idx, res)


if __name__ == "__main__":
    total = max(len(ty_username), len(ty_cookies))
    if total == 0:
        print("未检测到任何账号配置（请检查 TYYP_USERNAME 或 TYYP_COOKIE）")

    for i in range(total):
        print(f'开始执行帐号{i + 1}')
        try:
            if i < len(ty_cookies) and ty_cookies[i]:
                print("使用 Cookie 模式登录...")
                session = login_by_cookie(ty_cookies[i])
            else:
                session = login_by_password(ty_username[i], ty_password[i])
            do_sign_and_draw(session)
        except Exception as e:
            print(f'帐号{i + 1}执行出错: {e}')
