import requests
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64
import json
from loguru import logger
import execjs
import time
import ddddocr
import threading
from functools import partial
# from PIL import Image
from tiku import load_folder, get_by_id, update_answer
import random


ocr = ddddocr.DdddOcr(show_ad=False)
with open('encrypt.js', 'r', encoding='utf-8') as f:
    js_code = f.read()
ctx = execjs.compile(js_code)


KEY = b'31113001'      # 8 字节
IV  = b'31113001'      # 8 字节

def des_encrypt(plain_text: str) -> str:
    """返回 base64 字符串，与 CryptoJS.encrypt 输出一致"""
    cipher = DES.new(KEY, DES.MODE_CBC, IV)
    ct_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), DES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')

def des_decrypt(b64_cipher: str) -> str:
    """输入 base64 字符串，返回明文"""
    cipher = DES.new(KEY, DES.MODE_CBC, IV)
    ct_bytes = base64.b64decode(b64_cipher.encode('utf-8'))
    return unpad(cipher.decrypt(ct_bytes), DES.block_size).decode('utf-8')

def verification():
    # 验证码识别
    with open('captcha.jpg', 'rb') as f:
        img_bytes = f.read()
    res = ocr.classification(img_bytes)
    print(res)
    text = res[:3]  # 提取前三位子串
    print(text)  # 输出：8*4
    if "+" in text or "-" in text or "*" in text or "/" in text:
        # print("字符串中包含 +、-、* 或 / 符号")
        first_char = text[0]  # 第一位字符
        last_char = text[-1]  # 最后一位字符
        # print("第一位字符：", first_char)
        # print("最后一位字符：", last_char)
        if "+" in text:
            result=int(first_char)+int(last_char)
        if "-" in text:
            result=int(first_char)-int(last_char)
        if "*" in text:
            result=int(first_char)*int(last_char)
        if "/" in text:
            result=int(first_char)/int(last_char)
        # print(f"计算结果为{result}")
        return result
    else:
        # print("字符串中不包含 +、-、* 或 / 符号")
        return None

def login(username,password):
    wxAuthorization=des_encrypt('{"f":"GetUIToken","c":"PublicInterface"}')
    logger.debug(f"初始化--->wxAuthorization: {wxAuthorization}")
    headers = {
        "Host": "sysaqglxt.gxmzu.edu.cn",
        "Connection": "keep-alive",
        "Content-Length": "26",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-ch-ua": "\"Chromium\";v=\"140\", \"Not=A?Brand\";v=\"24\", \"Google Chrome\";v=\"140\"",
        "sec-ch-ua-mobile": "?0",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "wxAuthorization": wxAuthorization,
        "Content-Type": "application/json",
        "Origin": "https://sysaqglxt.gxmzu.edu.cn",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://sysaqglxt.gxmzu.edu.cn/customer/index/index.html",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9"
    }
    url = "https://sysaqglxt.gxmzu.edu.cn/WebService/wxPublicInterface.asmx/IoControl"
    data = {
        "DESJson": des_encrypt('{}')
    }
    data = json.dumps(data, separators=(',', ':'))
    response = requests.post(url, headers=headers, data=data)
    response=des_decrypt(response.json()['d'])
    token= json.loads(response)['token']
    logger.debug(f"初始化token--->{token}")
    
    headers = {
    'Host': 'cas.gxmzu.edu.cn',
    'Connection': 'keep-alive',
    'sec-ch-ua-platform': '"Windows"',
    'loginUserToken': '',
    'X-Requested-With': 'XMLHttpRequest',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
    'sec-ch-ua-mobile': '?0',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Referer': 'https://cas.gxmzu.edu.cn/lyuapServer/login?service=https://sysaqglxt.gxmzu.edu.cn/caslogin.aspx',
    # 'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    }
    headers['loginUserToken']=ctx.call('get_loginUserToken')
    logger.debug(f"loginUserToken--->{headers['loginUserToken']}")
    params = {
        '_t': str(int(time.time())),
        'uid': '',
    }
    # time.sleep(1)
    response = requests.get('https://cas.gxmzu.edu.cn/lyuapServer/kaptcha', params=params, headers=headers)
    logger.info(f"验证码请求状态--->{response.text}")
    with open('captcha.jpg', 'wb') as f:
        f.write(base64.b64decode(response.json()['content'].split(',', 1)[1] ))
    uid=response.json()['uid']
    logger.debug(f"uid--->{uid}")
    yzm=verification()
    logger.debug(f"验证码结果--->{yzm}")
    headers['loginUserToken']=ctx.call('get_loginUserToken')
    logger.debug(f"loginUserToken--->{headers['loginUserToken']}")
    password=ctx.call('encrypt_pwd',password)

    data = {
        'username': username,
        'password': password,
        'service': 'https://sysaqglxt.gxmzu.edu.cn/caslogin.aspx',
        'loginType': '',
        'id': uid,
        'code': yzm,
    }

    response = requests.post('https://cas.gxmzu.edu.cn/lyuapServer/v1/tickets', headers=headers, data=data)
    logger.info(f"登录请求结果--->{response.text}")
    # cookie=requests.cookies.get_dict()
    # logger.info(f"登录请求cookies--->{cookie}")


    headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Pragma': 'no-cache',
    'Referer': 'https://cas.gxmzu.edu.cn/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-site',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    # 'Cookie': 'UIToken=UIToken=29a59f45-dbcd-45b7-a75c-5f37d5b74101; ASP.NET_SessionId=d2txi20inxflh51oxceg4m5e',
}

    params = {
        'ticket': response.json()['ticket'],
    }

    response = requests.get('https://sysaqglxt.gxmzu.edu.cn/caslogin.aspx', params=params, headers=headers)
    # logger.info(f"登录后请求cookies--->{requests.cookies.get_dict()}")
#     print(response.status_code)
#     print(response.text)
# #     response = requests.get(
# #     'https://sysaqglxt.gxmzu.edu.cn/Customer/MasterPage/UserCenterPage.html',
# #     headers=headers,
# # )
# #     print(response.status_code)
# #     print(response.text)
    headers = {
    'accept': 'application/json, text/javascript, */*; q=0.01',
    'accept-language': 'zh-CN,zh;q=0.9',
    'cache-control': 'no-cache',
    'content-type': 'application/json',
    'origin': 'https://sysaqglxt.gxmzu.edu.cn',
    'pragma': 'no-cache',
    'priority': 'u=0, i',
    'referer': 'https://sysaqglxt.gxmzu.edu.cn/customer/index/index.html',
    'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'uitoken': token,
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
    'wxauthorization': des_encrypt('{"f":"checklogin","c":"PublicInterface"}'),
    'x-requested-with': 'XMLHttpRequest',
    # 'cookie': 'UIToken=UIToken=dccb3818-b780-44a1-a042-9272d631e1b2; ASP.NET_SessionId=1y1bbema3kmc1dx15d0khp5z',
}

    json_data = {
        'DESJson': des_encrypt('{}'),
    }

    response = requests.post(
        'https://sysaqglxt.gxmzu.edu.cn/WebService/wxPublicInterface.asmx/IoControl',
        headers=headers,
        json=json_data,
    )
    response=des_decrypt(response.json()['d'])
    logger.info(f"登录后请求结果--->{response}")
    return token


def get_titm(token,id,ksid,papersetid,ksanswer):
    headers = {
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'zh-CN,zh;q=0.9',
        'authorization': 'WanXinKey2019',
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'origin': 'https://sysaqglxt.gxmzu.edu.cn',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'token': 'EAAAAIBSQYkjCTzP1Pb7M3eilmo7uLxvpXTvPNBFxy0pcBzi3elb+ZORk2Oi9lF6d7Y0Tw==',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
        # 'cookie': 'UIToken=UIToken=50ef4f12-2558-4d25-a528-04e3c9bdc8e6; ASP.NET_SessionId=3or0ewg103npdrazpma0itwz',
    }

    data = "{id:'" + id + "',ksid:'" + ksid + "',papersetid:'" + papersetid + "',ksanswer:'" + ksanswer + "'}"

    response = requests.post(
        'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/index.asmx/tjtm',
        headers=headers,
        data=data,
    )
    logger.info(f"提交试题请求结果--->{response.text}")


def get_info(token):
    headers = {
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'zh-CN,zh;q=0.9',
        'authorization': 'WanXinKey2019',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'origin': 'https://sysaqglxt.gxmzu.edu.cn',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'referer': 'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/model/TwoGradePageZH/SecurityKind.html',
        'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'token': token,
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
        # 'cookie': 'UIToken=UIToken=50ef4f12-2558-4d25-a528-04e3c9bdc8e6; ASP.NET_SessionId=3or0ewg103npdrazpma0itwz',
    }

    data = {
        'PageIndex': '1',
        'PageSize': '10',
        'strOrder': '',
        'strJson': '{"data":[{}]}',
    }

    response = requests.post(
        'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/index1.asmx/getExamPaperSetListNew2',
        headers=headers,
        data=data,
    )
    logger.info(f"练习请求结果--->{response.text}")
    towcode=json.loads(response.text)["rows"][0]["TWOCODE"]  # 0,2,3,8,6,7
    id=str(json.loads(response.text)["rows"][0]["ID"])  # 101
    return towcode,id
    

def lianxi(token,towcode,id):
    headers = {
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'zh-CN,zh;q=0.9',
        'authorization': 'WanXinKey2019',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'origin': 'https://sysaqglxt.gxmzu.edu.cn',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'referer': 'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/model/TwoGradePageZH/SecurityKind.html',
        'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'token': token,
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
        # 'cookie': 'UIToken=UIToken=50ef4f12-2558-4d25-a528-04e3c9bdc8e6; ASP.NET_SessionId=3or0ewg103npdrazpma0itwz',
    }

    # data = {
    #     'PageIndex': '1',
    #     'PageSize': '10',
    #     'strOrder': '',
    #     'strJson': '{"data":[{}]}',
    # }

    # response = requests.post(
    #     'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/index1.asmx/getExamPaperSetListNew2',
    #     headers=headers,
    #     data=data,
    # )
    # logger.info(f"练习请求结果--->{response.text}")
    # towcode=json.loads(response.text)["rows"][0]["TWOCODE"]  # 0,2,3,8,6,7
    # id=str(json.loads(response.text)["rows"][0]["ID"])  # 101
    data = "{SecurityKindID:'" + towcode + "',PaperSetID:'" + id + "'}"
    headers['content-type']='application/json'


    response = requests.post(
        'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/index.asmx/selfOnePaper',
        headers=headers,
        data=data,
    )
    logger.info(f"练习试题请求结果--->{response.text}")
    paperid=str(json.loads(response.json()["d"])['data'][0]["PaperID"]) # 276858
    logger.info(f"练习试题ID--->{paperid}")
    data = "{ID:'" + towcode + "',Type:'lx',IsXj:'',bmid:'0',strTop:500}"

    response = requests.post(
        'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/index.asmx/selfStudy',
        headers=headers,
        data=data,
    )
    questions=json.loads(response.json()["d"])['data'][0]
    for question in questions['A']:
        logger.info(f"练习id--->{question['ID']}")
        answer=get_by_id(question['ID'])['answer']
        logger.info(f"练习答案--->{answer}")
        get_titm(token,question['ID'],paperid,id,answer)
    for question in questions['B']:
        logger.info(f"练习id--->{question['ID']}")
        answer=get_by_id(question['ID'])['answer']
        logger.info(f"练习答案--->{answer}")
        get_titm(token,question['ID'],paperid,id,answer)
    for question in questions['C']:
        logger.info(f"练习id--->{question['ID']}")
        answer=get_by_id(question['ID'])['answer']
        logger.info(f"练习答案--->{answer}")
        get_titm(token,question['ID'],paperid,id,answer)

def submit_answer(token, ksid, qid, ans, maxtime):
    url = 'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/AQKS.asmx/tjtm'
    hdr = {
        'Host': 'sysaqglxt.gxmzu.edu.cn',
        'Authorization': 'WanXinKey2019',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/json',
        'Token': token,
        'Origin': 'https://sysaqglxt.gxmzu.edu.cn',
        'Referer': 'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/model/TwoGradePageZH/JoinExam.html?isSelf=0&ID=101'
    }
    data = "{ksid:'" + ksid + "',id:'" + qid + "',ksanswer:'" + ans + "',maxtime:'" + str(maxtime) + "'}"
    response=requests.post(url, headers=hdr, data=data, timeout=10)
    logger.info(f"提交答案请求结果--->{response.text}")


def exam(token,id,isSelf):
    headers = {
    'Host': 'sysaqglxt.gxmzu.edu.cn',
    'Connection': 'keep-alive',
    # 'Content-Length': '21',
    'sec-ch-ua-platform': '"Windows"',
    'Authorization': 'WanXinKey2019',
    'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
    'sec-ch-ua-mobile': '?0',
    'X-Requested-With': 'XMLHttpRequest',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Content-Type': 'application/json',
    'Token': token,
    'Origin': 'https://sysaqglxt.gxmzu.edu.cn',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Referer': 'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/model/TwoGradePageZH/JoinExam.html?isSelf=0&ID=101',
    # 'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    # 'Cookie': 'UIToken=UIToken=50ef4f12-2558-4d25-a528-04e3c9bdc8e6; ASP.NET_SessionId=3or0ewg103npdrazpma0itwz',
}

    data = '{ID:' + id + ',isSelf:' + str(isSelf) + '}'#1自测，0考试

    response = requests.post(
        'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/AQKS.asmx/GetOnePaper',
        headers=headers,
        data=data,
    )
    print(response.text)
    ksid=json.loads(response.json()['d'])['data'][0]['KSID']

    data = '{setID:' + id + ',KSID:' + ksid + '}'

    response = requests.post(
        'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/AQKS.asmx/viewExamLabNew',
        headers=headers,
        data=data,
    )
    questions=json.loads(response.json()['d'])['data'][0]
    stop_beat = threading.Event()
    def beat_loop(pid, hdrs, maxtime: int):
      remain = maxtime
      while not stop_beat.is_set() and remain > 0:
          res=requests.post('https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/AQKS.asmx/tjtime',
                        headers=hdrs, json={'PaperID': pid, 'maxtime': str(remain)}, timeout=10)
          logger.info(f"心跳，剩余时间 {remain} 秒")
          logger.info(f"心跳请求结果--->{res.text}")
          time.sleep(5)
          remain -= 5
    threading.Thread(target=partial(beat_loop, ksid, headers, 7200), daemon=True).start()
    radio_parts = []   # ['qid-A', 'qid-B', ...]
    check_parts = []   # ['qid-A|B|C', 'qid-D|E', ...]
    judge_parts = []   # ['qid-Y', 'qid-N', ...]
    t=7200
    for question in questions['A']:
        logger.info(f"练习id--->{question['ID']}")
        answer=get_by_id(question['ID'])['answer']
        logger.info(f"练习答案--->{answer}")
        # time.sleep(1)
        t= t - 1
        submit_answer(token, ksid, question['ID'], answer, t)
        radio_parts.append(f'{question['ID']}-{answer}')

    for question in questions['B']:
        logger.info(f"练习id--->{question['ID']}")
        answer=get_by_id(question['ID'])['answer']
        logger.info(f"练习答案--->{answer}")
        # time.sleep(1)
        t= t - 1
        submit_answer(token, ksid, question['ID'], answer, t)
        # check_parts.append(f"{question['ID']}-{'|'.join(answer)}")
        check_parts.append(f"{question['ID']}-{answer}")

    for question in questions['C']:
        logger.info(f"练习id--->{question['ID']}")
        answer=get_by_id(question['ID'])['answer']
        logger.info(f"练习答案--->{answer}")
        # time.sleep(1)
        t= t - 1
        submit_answer(token, ksid, question['ID'], answer, t)
        judge_parts.append(f'{question['ID']}-{answer}')
    stop_beat.set()

    radio_str = 'A@' + ','.join(radio_parts)
    check_str = 'B@' + ','.join(check_parts)
    judge_str = 'C@' + ','.join(judge_parts)
    payload = {
    "PaperID": ksid,
    "radio": radio_str,
    "check": check_str,
    "judge": judge_str,
    "jianda": "E@",
    "type": 3,
    "RadioGroup": "0",
    "maxtime": str(random.randint(3200, 4000))
      }
    r = requests.post(
    'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/AQKS.asmx/PaperSubmit',
    headers=headers,
    data=json.dumps(payload)
    )
    print(r.text)

def shipin(token,towcode):

    headers = {
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'zh-CN,zh;q=0.9',
        'authorization': 'WanXinKey2019',
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'origin': 'https://sysaqglxt.gxmzu.edu.cn',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'referer': 'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/model/TwoGradePageZH/StudyDoc.html?ismust=1&SecurityKindID=0,2,3,4,6,7',
        'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'token': token,
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
        # 'cookie': 'UIToken=UIToken=44261e29-ddc8-4e69-b361-d92ab0cbf9fc; ASP.NET_SessionId=4z0dyzp3xen0tjxvqbfj5lxj',
    }

    json_data = {
        'PageIndex': 1,
        'PageSize': 20,
        'strOrder': '',
        'strJson': '{"data":[{"1": "1","DocKind":"0","SecurityKindID":"0,12,3,6,7","MustStudy":"1"}]}',
    }#        'strJson': '{"data":[{"1": "1","DocKind":"0","SecurityKindID":"0,2,3,4,6,7","MustStudy":"1"}]}',
    json_data['strJson'] = json.dumps({"data": [{"1": "1", "DocKind": "0", "SecurityKindID": towcode, "MustStudy": "1"}]})

    response = requests.post(
        'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/index.asmx/getPreStudyDoc',
        headers=headers,
        json=json_data,
    )
    raw = response.json()['d']
    data = json.loads(raw)["rows"]
    videos = [(r["ID"], r["WATCHTIME"]) for r in data if r["DOCKIND"] == 2]

    # 文档类：只要 ID
    docs = [r["ID"] for r in data if r["DOCKIND"] == 1]

    print("videos =", videos)
    print("docs   =", docs)
    for doc_id in docs:
        resp=requests.get('https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/model/TwoGradePageZH/FileDownLoad.aspx?ID='+str(doc_id), headers=headers)
        logger.info(f"下载文档请求结果--->{resp.status_code}")

    for video_id, watch_time in videos:
        data = "{ID:'" + str(video_id) + "'}"

        response = requests.post(
            'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/index.asmx/getPreStudyDocOne',
            headers=headers,
            data=data,
        )
        pkg = json.loads(response.json()["d"])
        rid = pkg["data"][0]["RID"]


        data = "{studyid:" + str(rid) + ",times:" + str(watch_time) + "}"

        response = requests.post(
            'https://sysaqglxt.gxmzu.edu.cn/LMSmini/AQZR/AQZRUI/wxInterface/index.asmx/updateWatchtime',
            headers=headers,
            data=data,
        )
        logger.info(f"更新视频学习时长请求结果--->{response.text}")


def run():
    token=login('这里填账号','这里填账号')
    logger.info(f"最终token--->{token}")
    towcode,id=get_info(token)

    shipin(token,towcode)//做视频和文档任务
    lianxi(token,towcode,id)//做500道练习
    exam(token,id,1)//模拟考试
    exam(token,id,0)//正式考试
    

    pass

if __name__ == '__main__':
    requests=requests.Session()
    run()
