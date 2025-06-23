import logging
import requests
import json
import random
import time
import threading
import os
import base64
from datetime import datetime, timedelta

USERNAME = os.environ.get('USERNAME', '')
PASSWORD = os.environ.get('PASSWORD', '')
CARDBIN = "528911"
JWT_Default = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGllbnRfaWQiOjQsImZpcnN0X25hbWUiOiJUcmF2ZWwiLCJsYXN0X25hbWUiOiJBcHAiLCJlbWFpbCI6InRyYXZlbGFwcEBmbGV4aXJvYW0uY29tIiwidHlwZSI6IkNsaWVudCIsImFjY2Vzc190eXBlIjoiQXBwIiwidXNlcl9hY2NvdW50X2lkIjo2LCJ1c2VyX3JvbGUiOiJWaWV3ZXIiLCJwZXJtaXNzaW9uIjpbXSwiZXhwaXJlIjoxODc5NjcwMjYwfQ.-RtM_zNG-zBsD_S2oOEyy4uSbqR7wReAI92gp9uh-0Y"

# Chuyển đổi từ JavaScript gốc - generateRandomUserData()
def generateRandomUserData():
    """Chuyển đổi chính xác từ JavaScript generateRandomUserData()"""
    firstNames = ["Jack", "Tristan", "Shane", "Amity", "Krystan", "Brooke", "Vincent", "Vivian", "Lillian", "Alice"]
    lastNames = ["Erickson", "Gilbert", "Maddox", "Morton", "Lindsey", "Chandler", "Johnson", "Travis", "Kennedy"]
    countryCodes = ["US", "UK", "VN", "CA", "AU", "DE", "FR", "JP", "CN", "IN", "BR", "RU", "IT", "ES", "KR", "MX", "ID", "TH", "SG", "MY"]
    iPhoneModels = ["iPhone11,2-iPhone XS", "iPhone12,1-iPhone 11", "iPhone13,2-iPhone 12", "iPhone14,2-iPhone 13 Pro", "iPhone15,2-iPhone 14 Pro", "iPhone16,1-iPhone 15 Pro"]
    iosVersions = ["17.0", "17.1", "17.2", "17.3", "17.4", "17.5", "18.0", "18.1"]
    
    # Sử dụng chính xác logic từ JavaScript gốc
    randomNum = random.randint(100, 999) + int(str(int(time.time()))[-3:])
    firstName = firstNames[random.randint(0, len(firstNames) - 1)]
    lastName = lastNames[random.randint(0, len(lastNames) - 1)]
    countryCode = countryCodes[random.randint(0, len(countryCodes) - 1)]
    email = f"{first_name.lower()}{last_name.lower()}.{random_num}@simpace.edu.vn"
    iPhoneInfo = iPhoneModels[random.randint(0, len(iPhoneModels) - 1)].split('-')
    iosVersion = iosVersions[random.randint(0, len(iosVersions) - 1)]
    
    return {
        "first_name": firstName,
        "last_name": lastName,
        "home_country_code": countryCode,
        "email": email,
        "password": "@Sadb0iz",
        "language_preference": "en-us",
        "device_udid": iPhoneInfo[0],
        "device_model": iPhoneInfo[1],
        "device_platform": "ios",
        "device_version": iosVersion,
        "have_esim_supported_device": 1,
        "notification_token": "undefined"
    }

def getRandomUserAgent():
    """Chuyển đổi từ JavaScript getRandomUserAgent()"""
    userAgents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
    ]
    return userAgents[random.randint(0, len(userAgents) - 1)]

def getCommonRequest():
    """Chuyển đổi từ JavaScript getCommonRequest()"""
    return {
        "method": "POST",
        "headers": {
            "Authorization": f"Bearer {JWT_Default}",
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Origin": "https://flexiroam.com/",
            "Referer": "https://flexiroam.com/",
            "User-Agent": getRandomUserAgent(),
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Dest": "empty",
            "lang": "en-us"
        }
    }

# Chuyển đổi từ JavaScript gốc - handleRegister()
def handleRegister(session):
    """Chuyển đổi chính xác từ JavaScript handleRegister()"""
    try:
        USER_DATA = generateRandomUserData()
        PAYLOAD = getCommonRequest()
        
        logging.info(f"🔄 Initializing UserData: {json.dumps(USER_DATA)}")
        
        # Gửi yêu cầu đăng ký - URL chính xác từ JavaScript gốc
        result = session.post(
            url="https://prod-enduserservices.flexiroam.com/api/registration/request/create",
            headers=PAYLOAD["headers"],
            json=USER_DATA,
            timeout=30
        )
        
        registrationResponse = result.json()
        
        if registrationResponse["message"] == "An email has been sent with verification link, please check your email inbox to verify your account.":
            logging.info(f"{registrationResponse['message']} -> {USER_DATA['email']}")
            
            authToken = None
            
            # Thử 3 lần để lấy email verification - logic từ JavaScript gốc
            for attempt in range(1, 4):
                logging.info(f"🔍 Looking for verification email... (Attempt {attempt}/3)")
                time.sleep(15)  # Chờ 15 giây như trong JavaScript gốc
                
                try:
                    # Sử dụng chính xác URL email service từ JavaScript gốc
                    emailResponse = session.get(f"https://hunght1890.com/{USER_DATA['email']}")
                    emailResult = emailResponse.json()
                    
                    logging.info(f"Email response: {emailResult}")
                    
                    if emailResult and "body" in emailResult:
                        # Sử dụng chính xác regex từ JavaScript gốc
                        import re
                        regex = r"verify\?token=([a-zA-Z0-9]+)"
                        match = re.search(regex, emailResult["body"])
                        
                        if match and match.group(1):
                            authToken = match.group(1)
                            logging.info(f"📨 Verification email found, token: {authToken}")
                            break
                            
                except Exception as emailError:
                    logging.info(f"Email check attempt {attempt} failed: {str(emailError)}")
            
            if not authToken:
                logging.error("No verification email found. Email verification timeout")
                return False, "Email verification timeout", None, None
            
            # Xác thực email - URL chính xác từ JavaScript gốc
            verificationResult = session.post(
                url="https://prod-enduserservices.flexiroam.com/api/registration/token/verify",
                headers=PAYLOAD["headers"],
                json={"token": authToken},
                timeout=30
            )
            
            verificationResponse = verificationResult.json()
            
            if verificationResponse["message"] == "Email verification successfully. Please proceed to login":
                logging.info(f"Sign up successful! Account ready: {USER_DATA['email']}")
                return True, "Registration successful", USER_DATA["email"], USER_DATA["password"]
            else:
                logging.error("Email verification failed")
                return False, "Email verification failed", None, None
        else:
            logging.error(f"Registration failed: {registrationResponse['message']}")
            return False, registrationResponse["message"], None, None
            
    except Exception as error:
        logging.error(f"Execution error: {str(error)}")
        return False, str(error), None, None

def check_account_status(session, username, password):
    """Kiểm tra trạng thái tài khoản hiện tại"""
    if not username or not password or username == '' or password == '':
        logging.info("📋 No credentials provided, registration needed")
        return False, "No credentials"
        
    try:
        # Thử đăng nhập với thông tin hiện tại
        res, result = login(session, username, password)
        if res:
            logging.info("✅ Current credentials are valid")
            return True, "Valid credentials"
        else:
            # Kiểm tra nếu tài khoản bị cấm
            if "Authorization Failed" in str(result) or "banned" in str(result).lower():
                logging.warning("🚫 Account appears to be banned")
                return False, "Account banned"
            else:
                logging.warning("❌ Login failed with current credentials")
                return False, "Invalid credentials"
                
    except Exception as e:
        logging.error(f"❌ Error checking account status: {str(e)}")
        return False, f"Error: {str(e)}"

def update_github_secrets(username, password, repo_owner, repo_name, github_token):
    """Cập nhật GitHub repository secrets với thông tin đăng nhập mới"""
    try:
        # Kiểm tra xem PyNaCl có sẵn không
        try:
            from nacl import encoding, public
        except ImportError:
            logging.warning("⚠️ PyNaCl not available, skipping GitHub secrets update")
            return False, "PyNaCl library not installed"
        
        # Lấy public key để mã hóa
        public_key_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/public-key"
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(public_key_url, headers=headers)
        if response.status_code != 200:
            return False, f"Failed to get public key: {response.text}"
            
        public_key_data = response.json()
        public_key = public_key_data["key"]
        key_id = public_key_data["key_id"]
        
        # Mã hóa secrets
        def encrypt_secret(secret_value, public_key):
            sealed_box = public.SealedBox(public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder()))
            encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
            return base64.b64encode(encrypted).decode("utf-8")
        
        # Cập nhật USERNAME secret
        username_data = {
            "encrypted_value": encrypt_secret(username, public_key),
            "key_id": key_id
        }
        
        username_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/USERNAME"
        username_response = requests.put(username_url, headers=headers, json=username_data)
        
        # Cập nhật PASSWORD secret
        password_data = {
            "encrypted_value": encrypt_secret(password, public_key),
            "key_id": key_id
        }
        
        password_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/PASSWORD"
        password_response = requests.put(password_url, headers=headers, json=password_data)
        
        if username_response.status_code in [201, 204] and password_response.status_code in [201, 204]:
            return True, "GitHub secrets updated successfully"
        else:
            return False, f"Failed to update secrets: USERNAME({username_response.status_code}), PASSWORD({password_response.status_code})"
            
    except Exception as e:
        return False, f"Error updating GitHub secrets: {str(e)}"

def auto_register_if_needed(session, github_token=None, repo_owner=None, repo_name=None):
    """Tự động đăng ký tài khoản mới nếu thông tin hiện tại không hợp lệ"""
    global USERNAME, PASSWORD
    
    # Kiểm tra trạng thái tài khoản hiện tại
    is_valid, status = check_account_status(session, USERNAME, PASSWORD)
    
    if is_valid:
        logging.info("🎯 Current account is valid, no registration needed")
        return True, USERNAME, PASSWORD
        
    logging.info(f"🔄 Current account status: {status}, starting registration...")
    
    # Đăng ký tài khoản mới
    success, message, new_username, new_password = handleRegister(session)
    
    if not success:
        logging.error(f"❌ Auto registration failed: {message}")
        return False, None, None
        
    # Cập nhật biến global
    USERNAME = new_username
    PASSWORD = new_password
    
    logging.info(f"✅ New account registered successfully: {new_username}")
    
    # Cập nhật GitHub secrets nếu có thông tin
    if github_token and repo_owner and repo_name:
        logging.info("🔄 Updating GitHub repository secrets...")
        success, github_result = update_github_secrets(
            new_username, new_password, repo_owner, repo_name, github_token
        )
        if success:
            logging.info("✅ GitHub secrets updated successfully")
        else:
            logging.warning(f"⚠️ Failed to update GitHub secrets: {github_result}")
    else:
        logging.info("ℹ️ GitHub credentials not provided, skipping secrets update")
        
    return True, new_username, new_password

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s.%(msecs)03d [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logging.info("🔄 Initializing Flexiroam automation service v2.0")

    session = requests.session()
    
    # Lấy thông tin GitHub từ environment (tùy chọn)
    github_token = os.environ.get('GIT_TOKEN', '')  # Sử dụng GIT_TOKEN từ env
    repo_owner = os.environ.get('REPO_OWNER', '')
    repo_name = os.environ.get('REPO_NAME', '')
    
    # Tự động đăng ký nếu cần
    logging.info("🔍 Checking account credentials...")
    success, username, password = auto_register_if_needed(
        session, 
        github_token if github_token else None,
        repo_owner if repo_owner else None, 
        repo_name if repo_name else None
    )
    
    if not success:
        logging.error("❌ Failed to establish valid account credentials")
        exit(1)
    
    # Cập nhật biến global
    USERNAME = username
    PASSWORD = password
    
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

    logging.info("📅 Authentication successful - Service ready")

    # Start session update thread
    threading.Thread(target=updateSessionThread, daemon=True, kwargs={ "session": session }).start()

    # Start plan management thread
    threading.Thread(target=autoActivePlansThread, daemon=True, kwargs={ "session": session, "token": token }).start()

    # Block process
    while True:
        time.sleep(1000)

# Phần còn lại của code giữ nguyên như ban đầu
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
    for i in range(len(digits) - 2, -1, -2): # Starting from second last digit, double every other digit
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9 # If doubled result is greater than 9, subtract 9
    return sum(digits) % 10 # Luhn check value

def generate_card_number(bin_prefix, length=16):
    """Generate complete card number based on BIN that follows Luhn rule"""
    while True:
        card_number = bin_prefix + ''.join(str(random.randint(0, 9)) for _ in range(length - len(bin_prefix) - 1))
        check_digit = (10 - luhn_checksum(card_number + "0")) % 10 # Calculate Luhn check digit
        full_card_number = card_number + str(check_digit)
        if luhn_checksum(full_card_number) == 0: # Ensure card number is valid
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

if __name__ == "__main__":
    main()
