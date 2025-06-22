import logging
import requests
import json
import random
import time
import threading
import os
from datetime import datetime, timedelta

USERNAME = os.environ.get('USERNAME', ''
PASSWORD = os.environ.get('PASSWORD', '')
CARDBIN = "528911"
JWT_Default = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGllbnRfaWQiOjQsImZpcnN0X25hbWUiOiJUcmF2ZWwiLCJsYXN0X25hbWUiOiJBcHAiLCJlbWFpbCI6InRyYXZlbGFwcEBmbGV4aXJvYW0uY29tIiwidHlwZSI6IkNsaWVudCIsImFjY2Vzc190eXBlIjoiQXBwIiwidXNlcl9hY2NvdW50X2lkIjo2LCJ1c2VyX3JvbGUiOiJWaWV3ZXIiLCJwZXJtaXNzaW9uIjpbXSwiZXhwaXJlIjoxODc5NjcwMjYwfQ.-RtM_zNG-zBsD_S2oOEyy4uSbqR7wReAI92gp9uh-0Y"

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s.%(msecs)03d [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logging.info("🔄 Initializing Flexiroam automation service v1.0")

    session = requests.session()

    logging.info("🔐 Authenticating user credentials...")
    
    res, resultLogin = login(session, USERNAME, PASSWORD)
    if not res:
        logging.error("❌ Authentication failed: %s", resultLogin)
        exit(1)
    token = resultLogin["token"]
    logging.info("🔑 Retrieved authToken -> %s", token)
    logging.info("🔐 Retrieving CSRF token...")
    res, csrf = getCsrf(session)


    if not res:
        logging.error("❌ CSRF token retrieval failed: %s", csrf)
        exit(1)
    logging.info("🔑 Retrieved CSRF -> %s", csrf)
    logging.info("🛡️ Establishing secure session...")

    # Get authentication Cookie
    res, resultCredentials = credentials(session, csrf, token)

    if not res:
        logging.error("❌ Session establishment failed: %s", resultCredentials)
        exit(1)

    logging.info("✅ Authentication successful - Service ready")

    # Start session update thread
    threading.Thread(target=updateSessionThread, daemon=True, kwargs={ "session": session }).start()

    # Start plan management thread
    threading.Thread(target=autoActivePlansThread, daemon=True, kwargs={ "session": session, "token": token }).start()

    # Block process
    while True:
        time.sleep(1000)

# Plan management thread
def autoActivePlansThread(session, token):
    def selectOutPlans(plans):
        logging.info("🔍 Looking for plans information...")
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
    
    # Default time
    dayGet = 0
    timeSec = 0

    # Conservative approach
    lastGetPlansTime = datetime.now() - timedelta(hours=7)
    while True:

        # Default 120 seconds
        time.sleep(120)

        # Daily maximum plan acquisition limit reset
        timeSec += 120
        if timeSec > 86400:
            dayGet = 0
            timeSec = 0

        # Get current plans
        res, resultPlans = getPlans(session)

        if not res and "Failed to get plans, no plan information found" not in resultPlans:
            logging.error("❌ Plan retrieval failed: %s", resultPlans)
            continue
        
        if not res:
            resultPlans = { "plans": [] }

        activePlans = selectOutPlans(resultPlans)
        balanceCount, inRate, fristPlanId = getInactivePlan(resultPlans)

        # Get current remaining data
        rateRoam = getActivePercentage(activePlans)

        logging.info("👤 Plan Status: Active %.2f GB | Inactive %.2f GB | Available %d plans", 
                    (rateRoam / 100) * 3, (inRate / 100) * 3, balanceCount)

        current_time = datetime.now() 
        # Check if data is insufficient
        if rateRoam <= 30 and balanceCount != 0:
            res, resultStartPlan = startPlans(session, token, fristPlanId)
            
            if not res:
                logging.error("❌ Plan activation failed: %s", resultStartPlan)
                continue
            
            # If new plan started, wait an hour before registering new plan
            if current_time - lastGetPlansTime >= timedelta(hours=6):
                lastGetPlansTime = datetime.now() - timedelta(hours=5)
                
            logging.info("✅ Plan activated successfully [ID: %s]", str(fristPlanId))
            continue

        # Auto replenish plans
        if balanceCount < 2 and dayGet < 4 and current_time - lastGetPlansTime >= timedelta(hours=6):
            result = eligibilityAddToAccount(session, token)
            if result == 1:
                # Reset time
                lastGetPlansTime = datetime.now()

            if result != 0:
                continue
        
            # Get +1
            dayGet += 1

            # Reset time
            lastGetPlansTime = datetime.now()

def eligibilityAddToAccount(session, token):
    # Generate card number
    cardNumber = generate_card_number(CARDBIN)

    # Check if card number meets requirements
    res, resultEligibilityPlan = eligibilityPlan(session, token, cardNumber)
    
    if not res:
        if resultEligibilityPlan == "We are currently processing your previous redemption, kindly retry again later":
            logging.warning("⏳ Rate limit reached - Delaying next attempt (Card: %s)", cardNumber[-4:])
            return 1
        
        # Stop execution directly
        if "Account banned" in resultEligibilityPlan or "Card number does not meet requirements" in resultEligibilityPlan:
            logging.critical("🚫 Service terminated: %s (Card: %s)", resultEligibilityPlan, cardNumber[-4:])
            exit(-1)
        
        logging.error("❌ Card validation failed: %s (Card: %s)", resultEligibilityPlan, cardNumber[-4:])
        return 2
    
    # Confirm registration plan
    res, resultRedemptionConfirm = redemptionConfirm(session, token, resultEligibilityPlan)

    if not res:
        logging.error("❌ Plan redemption failed: %s (Card: %s)", resultRedemptionConfirm, cardNumber[-4:])
        return 2

    logging.info("🎉 Plan acquired successfully (Card: %s)", cardNumber[-4:])
    return 0

# Auto update Session thread
def updateSessionThread(session):
    while True:
        res, result = updateSession(session)

        if not res:
            logging.error("❌ Session refresh failed: %s", result)
            exit(1)

        logging.debug("🔄 Session refreshed successfully")
        time.sleep(3600)

# Credit card calculation tools
############################################

def luhn_checksum(card_number):
    """Calculate Luhn checksum"""
    digits = [int(d) for d in card_number]
    for i in range(len(digits) - 2, -1, -2):  # Starting from second last digit, double every other digit
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9  # If doubled result is greater than 9, subtract 9
    return sum(digits) % 10  # Luhn check value

def generate_card_number(bin_prefix, length=16):
    """Generate complete card number based on BIN that follows Luhn rule"""
    while True:
        card_number = bin_prefix + ''.join(str(random.randint(0, 9)) for _ in range(length - len(bin_prefix) - 1))
        check_digit = (10 - luhn_checksum(card_number + "0")) % 10  # Calculate Luhn check digit
        full_card_number = card_number + str(check_digit)
        
        if luhn_checksum(full_card_number) == 0:  # Ensure card number is valid
            return full_card_number

# API List
############################################

def login(session, user, pwd):
    result = session.post(url="https://prod-enduserservices.flexiroam.com/api/user/login",headers={
        "authorization": "Bearer " + JWT_Default,
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36"
    },json={
        "email": user,
        "password": pwd,
        "device_udid": "iPhone17,2",
        "device_model": "iPhone17,2",
        "device_platform": "ios",
        "device_version": "18.3.1",
        "have_esim_supported_device": 1,
        "notification_token": "undefined"
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
    try:
        result = session.get(url="https://www.flexiroam.com/en-us/my-plans", headers={
            "referer": "https://www.flexiroam.com/en-us/home",
            "rsc": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36"
        })
        
        # Get the Json data containing only plans
        for line in result.text.splitlines():
            if '{"plans":[' in line:
                splits = line.split('{"plans":[')
                resultRaw = '{"plans":[' + splits[1][:len(splits[1]) - 1]
                
                return True, json.loads(resultRaw)
        
        return False, "Failed to get plans, no plan information found. Maybe the first one wasn't manually registered, try again after operation."
    except:
        time.sleep(1)
        return getPlans(session)

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
    
    return True, "Plan activated successfully!"

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
    if "Authorization Failed" in resultJson["message"]:
        return False, "Account banned, stopping execution."
    
    if "Your Mastercard is not eligible for the offer" in resultJson["message"]:
        return False, "Card number does not meet requirements."
        
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
    
    return True, "Got new plan successfully!"

main()
