import logging
import requests
import json
import random
import time
import threading
from datetime import datetime, timedelta

USERNAME = ""
PASSWORD = ""
CARDBIN = "528911"
JWT_Default = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGllbnRfaWQiOjQsImZpcnN0X25hbWUiOiJUcmF2ZWwiLCJsYXN0X25hbWUiOiJBcHAiLCJlbWFpbCI6InRyYXZlbGFwcEBmbGV4aXJvYW0uY29tIiwidHlwZSI6IkNsaWVudCIsImFjY2Vzc190eXBlIjoiQXBwIiwidXNlcl9hY2NvdW50X2lkIjo2LCJ1c2VyX3JvbGUiOiJWaWV3ZXIiLCJwZXJtaXNzaW9uIjpbXSwiZXhwaXJlIjoxODc5NjcwMjYwfQ.-RtM_zNG-zBsD_S2oOEyy4uSbqR7wReAI92gp9uh-0Y"

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s.%(msecs)03d [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logging.info("正在启动 Flexiroam 自动注册 MasterCard 免费 3G Plan 脚本程序......")

    session = requests.session()

    logging.info("正在登录获取 token ......")
    
    res, resultLogin = login(session, USERNAME, PASSWORD)
    if not res:
        logging.error("登录获取 token 失败！ 原因: " + resultLogin)
        exit(1)

    logging.info("正在获取 csrf ......")
    res, csrf = getCsrf(session)
    token = resultLogin["token"]

    if not res:
        logging.error("获取 csrf 失败！ 原因: " + csrf)
        exit(1)

    logging.info("正在认证获取 __Secure-authjs.session-token ......")

    # 获取认证 Cookie
    res, resultCredentials = credentials(session, csrf, token)

    if not res:
        logging.error("获取 __Secure-authjs.session-token 失败！ 原因: " + resultCredentials)
        exit(1)

    logging.info("登录成功！正在初始化计划信息，并启用 session 更新......")

    # 启动 session 更新线程
    threading.Thread(target=updateSessionThread, daemon=True, kwargs={ "session": session }).start()

    # 启动 计划管理线程
    threading.Thread(target=autoActivePlansThread, daemon=True, kwargs={ "session": session, "token": token }).start()

    # 梗塞进程
    while True:
        time.sleep(1000)

# 计划管理线程
def autoActivePlansThread(session, token):
    def selectOutPlans(plans):
        newPlans = []

        for plan in plans["plans"]:
            percentage = plan["circleChart"]["percentage"]

            if percentage != 0:
                newPlans.append(plan)

        return newPlans
    
    def getActivePercentage(plans):
        allRate = 0
        
        for plan in plans:
            if plan["status"] == 'Active':
                allRate += plan["circleChart"]["percentage"]
        
        return allRate

    def getInactivePlan(plans):
        allCount = 0
        planId = 0
        allRate = 0

        for plan in plans["plans"]:
            if plan["status"] == 'In-active':
                allCount += 1
                allRate += plan["circleChart"]["percentage"]
                
                if planId == 0:
                    planId = plan["planId"]
                    continue
        
        return allCount, allRate, planId
    
    # 默认时间
    dayGet = 0
    timeSec = 0

    # 一般默认第一个就补充
    lastGetPlansTime = datetime.now() - timedelta(hours=7)
    while True:

        # 默认120秒
        time.sleep(120)

        # 一天最大获取计划上限重置
        timeSec += 120
        if timeSec > 86400:
            dayGet = 0
            timeSec = 0

        # 获取当前计划
        res, resultPlans = getPlans(session)

        if not res:
            logging.error("获取 Plans 失败！ 原因: " + resultPlans)
            continue

        activePlans = selectOutPlans(resultPlans)
        balanceCount, inRate, fristPlanId = getInactivePlan(resultPlans)

        # 获取目前剩余流量
        rateRoam = getActivePercentage(activePlans)

        logging.info("已经激活流量：「" + str((rateRoam / 100) * 3) + " G」,未激活流量：「" + str((inRate / 100) * 3) + " G」,剩余计划数：「" + str(balanceCount) + "」")

        # 判断是否流量不够了
        if rateRoam <= 30 and balanceCount != 0:
            res, resultStartPlan = startPlans(session, token, fristPlanId)
            
            if not res:
                logging.error("启动新 Plans 失败！ 原因: " + resultStartPlan)
                continue
            
            logging.info("启动新 Plans 成功！ PlanId: " + str(fristPlanId))
            continue

        # 自动补充计划
        current_time = datetime.now() 
        if balanceCount < 2 and dayGet < 4 and current_time - lastGetPlansTime >= timedelta(hours=6):
            result = eligibilityAddToAccount(session, token)
            if result == 1:
                # 重置时间
                lastGetPlansTime = datetime.now()

            if result != 0:
                continue
        
            # 获取 +1
            dayGet += 1

            # 重置时间
            lastGetPlansTime = datetime.now()



def eligibilityAddToAccount(session, token):
    # 生成卡号
    cardNumber = generate_card_number(CARDBIN)

    # 确认卡号是否符合规则
    res, resultEligibilityPlan = eligibilityPlan(session, token, cardNumber)
    
    if not res:
        if resultEligibilityPlan == "We are currently processing your previous redemption, kindly retry again later":
            
            logging.warning("确认卡号资格失败！ 原因: 正在等待新计划下发，重置等待时间2小时 cardinfo: " + cardNumber)
            return 1

        logging.error("确认卡号资格失败！ 原因: " + resultEligibilityPlan + " cardinfo: " + cardNumber)
        return 2
    
    # 确认注册计划
    res, resultRedemptionConfirm = redemptionConfirm(session, token, resultEligibilityPlan)

    if not res:
        logging.error("获取新 Plans 失败！ 原因: " + resultRedemptionConfirm + " cardinfo: " + cardNumber)
        return 2

    logging.info("获取新 Plans 成功！ msg: " + resultRedemptionConfirm + " cardinfo: " + cardNumber)
    return 0

# 自动更新 Session 线程
def updateSessionThread(session):
    while True:
        res, result = updateSession(session)

        if not res:
            logging.error("更新 Session 失败！ 原因: " + result)
            exit(1)

        logging.info("更新 Session 成功！")
        time.sleep(43200)

# 信用卡计算工具
############################################

def luhn_checksum(card_number):
    """计算 Luhn 校验和"""
    digits = [int(d) for d in card_number]
    for i in range(len(digits) - 2, -1, -2):  # 从倒数第二位开始，每隔一位翻倍
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9  # 如果翻倍后大于 9，则减去 9
    return sum(digits) % 10  # Luhn 校验值

def generate_card_number(bin_prefix, length=16):
    """基于 BIN 生成符合 Luhn 规则的完整卡号"""
    while True:
        card_number = bin_prefix + ''.join(str(random.randint(0, 9)) for _ in range(length - len(bin_prefix) - 1))
        check_digit = (10 - luhn_checksum(card_number + "0")) % 10  # 计算 Luhn 校验位
        full_card_number = card_number + str(check_digit)
        
        if luhn_checksum(full_card_number) == 0:  # 确保卡号有效
            return full_card_number

# API 列表
############################################

def login(session, user, pwd):
    result = session.post(url="https://prod-enduserservices.flexiroam.com/api/user/login",headers={
        "authorization": "Bearer " + JWT_Default,
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36"
    },json={
        "email": user,
        "password": pwd
    })

    resultJson = result.json()
    if resultJson["message"] != "Login Successful":
        return False, resultJson["message"]
    
    return True, resultJson["data"]

def credentials(session, csrf, token):
    result = session.post(url="https://www.flexiroam.com/api/auth/callback/credentials?", headers={
        "content-type": "application/x-www-form-urlencoded",
        "referer": "https://www.flexiroam.com/en-us/login",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36",
        "x-auth-return-redirect": "1"
    }, data={
        "token": token,
        "redirect": False,
        "csrfToken": csrf,
        "callbackUrl": "https://www.flexiroam.com/en-us/login"
    })

    resultJson = result.json()
    if "url" not in resultJson:
        return False, result.text
    
    return True, ""

def updateSession(session):
    result = session.get(url="https://www.flexiroam.com/api/auth/session", headers={
        "referer": "https://www.flexiroam.com/en-us/home",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36"
    })
    
    resultJson = result.json()
    if "expires" not in resultJson:
        return False, result.text
    
    return True, ""

def getCsrf(session):
    result = session.get(url="https://www.flexiroam.com/api/auth/csrf", headers={
        "referer": "https://www.flexiroam.com/en-us/home",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36"
    })
    
    resultJson = result.json()
    if "csrfToken" not in resultJson:
        return False, result.text
    
    return True, resultJson["csrfToken"]

def getPlans(session):
    result = session.get(url="https://www.flexiroam.com/en-us/my-plans", headers={
        "referer": "https://www.flexiroam.com/en-us/home",
        "rsc": "1",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36"
    })
    
    # 获取只有计划的那个 Json 数据
    for line in result.text.splitlines():
        if '{"plans":[' in line:
            splits = line.split('{"plans":[')
            resultRaw = '{"plans":[' + splits[1][:len(splits[1]) - 1]
            
            return True, json.loads(resultRaw)
    
    return False, "获取计划失败，没有寻找到计划信息！"

def startPlans(session, token, sim_plan_id):
    result = session.post(url="https://prod-planservices.flexiroam.com/api/plan/start", headers={
        "authorization": "Bearer " + token,
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36"
    }, json={
        "sim_plan_id": sim_plan_id
    })

    resultJson = result.json()
    if "data" not in resultJson:
        return False, resultJson["message"]
    
    return True, "激活计划成功！"

def eligibilityPlan(session, token, lookup_value):
    result = session.post(url="https://prod-enduserservices.flexiroam.com/api/user/redemption/check/eligibility", headers={
        "authorization": "Bearer " + token,
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36"
    }, json={
        "email": USERNAME,
        "lookup_value": lookup_value
    })

    resultJson = result.json()
    if "3GB Global Data Plan" not in resultJson["message"]:
        return False, resultJson["message"]
    
    return True, resultJson["data"]["redemption_id"]

def redemptionConfirm(session, token, redemption_id):
    result = session.post(url="https://prod-enduserservices.flexiroam.com/api/user/redemption/confirm", headers={
        "authorization": "Bearer " + token,
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36"
    }, json={
        "redemption_id": redemption_id
    })

    resultJson = result.json()
    if resultJson["message"] != "Redemption confirmed":
        return False, resultJson["message"]
    
    return True, "获取新计划成功！"

main()
