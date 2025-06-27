import logging
import requests
import json
import random
import time
import threading
import os
import base64
import re
from datetime import datetime, timedelta
from nacl import encoding, public

# Cấu hình logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

class Utils:
    """Các hàm tiện ích chung"""
    JWT_DEFAULT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGllbnRfaWQiOjQsImZpcnN0X25hbWUiOiJUcmF2ZWwiLCJsYXN0X25hbWUiOiJBcHAiLCJlbWFpbCI6InRyYXZlbGFwcEBmbGV4aXJvYW0uY29tIiwidHlwZSI6IkNsaWVudCIsImFjY2Vzc190eXBlIjoiQXBwIiwidXNlcl9hY2NvdW50X2lkIjo2LCJ1c2VyX3JvbGUiOiJWaWV3ZXIiLCJwZXJtaXNzaW9uIjpbXSwiZXhwaXJlIjoxODc5NjcwMjYwfQ.-RtM_zNG-zBsD_S2oOEyy4uSbqR7wReAI92gp9uh-0Y"
    CARD_BIN = "528911"

    @staticmethod
    def get_random_user_agent():
        """Tạo User-Agent ngẫu nhiên"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
        ]
        return random.choice(user_agents)

    @staticmethod
    def get_common_headers():
        """Trả về header chung cho các yêu cầu API"""
        return {
            "Authorization": f"Bearer {Utils.JWT_DEFAULT}",
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Origin": "https://flexiroam.com/",
            "Referer": "https://flexiroam.com/",
            "User-Agent": Utils.get_random_user_agent(),
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Dest": "empty",
            "lang": "en-us"
        }

    @staticmethod
    def generate_card_number(bin_prefix, length=16):
        """Tạo số thẻ tín dụng hợp lệ theo thuật toán Luhn"""
        while True:
            card_number = bin_prefix + ''.join(str(random.randint(0, 9)) for _ in range(length - len(bin_prefix) - 1))
            check_digit = (10 - Utils.luhn_checksum(card_number + "0")) % 10
            full_card_number = card_number + str(check_digit)
            if Utils.luhn_checksum(full_card_number) == 0:
                return full_card_number

    @staticmethod
    def luhn_checksum(card_number):
        """Tính checksum Luhn cho số thẻ"""
        digits = [int(d) for d in card_number]
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        return sum(digits) % 10

class UserManager:
    """Quản lý đăng ký, xác minh và đăng nhập người dùng"""
    def __init__(self, session):
        self.session = session
        self.user_data = None
        self.auth_token = None

    def generate_random_user_data(self):
        """Tạo dữ liệu người dùng ngẫu nhiên"""
        first_names = ["Jack", "Tristan", "Shane", "Amity", "Krystan", "Brooke", "Vincent", "Vivian", "Lillian", "Alice"]
        last_names = ["Erickson", "Gilbert", "Maddox", "Morton", "Lindsey", "Chandler", "Johnson", "Travis", "Kennedy"]
        country_codes = ["US", "UK", "VN", "CA", "AU", "DE", "FR", "JP", "CN", "IN", "BR", "RU", "IT", "ES", "KR", "MX", "ID", "TH", "SG", "MY"]
        iphone_models = ["iPhone11,2-iPhone XS", "iPhone12,1-iPhone 11", "iPhone13,2-iPhone 12", "iPhone14,2-iPhone 13 Pro", "iPhone15,2-iPhone 14 Pro", "iPhone16,1-iPhone 15 Pro"]
        ios_versions = ["17.0", "17.1", "17.2", "17.3", "17.4", "17.5", "18.0", "18.1"]

        random_num = random.randint(100, 999) + int(str(int(time.time()))[-3:])
        first_name = random.choice(first_names)
        last_name = random.choice(last_names)
        home_country_code = random.choice(country_codes)
        email = f"{first_name.lower()}{last_name.lower()}.{random_num}@simpace.edu.vn"
        iphone_info = random.choice(iphone_models).split('-')
        ios_version = random.choice(ios_versions)

        self.user_data = {
            "first_name": first_name,
            "last_name": last_name,
            "home_country_code": home_country_code,
            "email": email,
            "password": "@Sadb0iz",
            "language_preference": "en-us",
            "device_udid": iphone_info[0],
            "device_model": iphone_info[1],
            "device_platform": "ios",
            "device_version": ios_version,
            "have_esim_supported_device": 1,
            "notification_token": "undefined"
        }
        return self.user_data

    def register(self):
        """Đăng ký người dùng mới"""
        if not self.user_data:
            self.generate_random_user_data()

        response = self.session.post(
            "https://prod-enduserservices.flexiroam.com/api/registration/request/create",
            headers=Utils.get_common_headers(),
            json=self.user_data,
            timeout=30
        ).json()

        if response.get("message") != "An email has been sent with verification link, please check your email inbox to verify your account.":
            return False, response.get("message", "Lỗi không xác định")
        return True, response["data"]

    def get_verification_token(self, email):
        """Lấy mã xác minh từ email"""
        for attempt in range(1, 4):
            logging.info(f"🔍 Tìm email xác minh... (Lần {attempt}/3)")
            time.sleep(15)
            response = self.session.get(f"http://hunght1890.com/{email}").json()
            for group in response:
                if "body" in group:
                    token_match = re.search(r'verify\?token=([a-zA-Z0-9]+)', group["body"])
                    if token_match:
                        return True, token_match.group(1)
        return False, "Không tìm thấy mã xác minh trong email"

    def verify(self, verify_token):
        """Xác minh email"""
        response = self.session.post(
            "https://prod-enduserservices.flexiroam.com/api/registration/token/verify",
            headers=Utils.get_common_headers(),
            json={"token": verify_token},
            timeout=30
        ).json()

        if response.get("message") == "Email verification successfully. Please proceed to login":
            return True, "Đăng ký thành công"
        return False, f"Xác minh email thất bại: {response}"

    def login(self, email, password):
        """Đăng nhập và lấy auth_token"""
        payload = {
            "email": email,
            "password": password,
            "device_udid": "iPhone17,2",
            "device_model": "iPhone17,2",
            "device_platform": "ios",
            "device_version": "18.3.1",
            "have_esim_supported_device": 1,
            "notification_token": "undefined"
        }
        headers = Utils.get_common_headers()
        headers["authorization"] = f"Bearer {Utils.JWT_DEFAULT}"

        response = self.session.post(
            "https://prod-enduserservices.flexiroam.com/api/user/login",
            headers=headers,
            json=payload
        ).json()

        if response.get("message") != "Login Successful":
            return False, response.get("message", "Đăng nhập thất bại")
        self.auth_token = response["data"]["token"]
        return True, response["data"]

class PlanManager:
    """Quản lý các gói dữ liệu"""
    def __init__(self, session, auth_token, user_email):
        self.session = session
        self.auth_token = auth_token
        self.user_email = user_email

    def get_plans(self):
        """Lấy danh sách gói dữ liệu hiện tại"""
        try:
            headers = {
                "referer": "https://www.flexiroam.com/en-us/home",
                "rsc": "1",
                "user-agent": Utils.get_random_user_agent()
            }
            result = self.session.get("https://www.flexiroam.com/en-us/my-plans", headers=headers)
            for line in result.text.splitlines():
                if '{"plans":[' in line:
                    splits = line.split('{"plans":[')
                    result_raw = '{"plans":[' + splits[1][:len(splits[1]) - 1]
                    return True, json.loads(result_raw)
            return False, "Không tìm thấy thông tin gói dữ liệu"
        except Exception as e:
            logging.error(f"Lỗi khi lấy gói dữ liệu: {e}")
            time.sleep(1)
            return self.get_plans()

    def start_plan(self, plan_id):
        """Kích hoạt gói dữ liệu"""
        headers = {
            "authorization": f"Bearer {self.auth_token}",
            "content-type": "application/json",
            "user-agent": Utils.get_random_user_agent()
        }
        payload = {"sim_plan_id": plan_id}
        result = self.session.post("https://prod-planservices.flexiroam.com/api/plan/start", headers=headers, json=payload)
        result_json = result.json()
        if "data" not in result_json:
            return False, result_json.get("message", "Lỗi không xác định")
        return True, "Kích hoạt gói thành công!"

    def eligibility_plan(self, lookup_value):
        """Kiểm tra tính hợp lệ của thẻ để thêm gói"""
        headers = {
            "authorization": f"Bearer {self.auth_token}",
            "content-type": "application/json",
            "user-agent": Utils.get_random_user_agent()
        }
        payload = {"email": self.user_email, "lookup_value": lookup_value}
        result = self.session.post("https://prod-enduserservices.flexiroam.com/api/user/redemption/check/eligibility", headers=headers, json=payload)
        result_json = result.json()
        if "Authorization Failed" in result_json.get("message", ""):
            return False, "Tài khoản bị cấm, dừng thực thi."
        if "Your Mastercard is not eligible for the offer" in result_json.get("message", ""):
            return False, "Số thẻ không đáp ứng yêu cầu."
        if "3GB Global Data Plan" not in result_json.get("message", ""):
            return False, result_json.get("message", "Lỗi không xác định")
        return True, result_json["data"]["redemption_id"]

    def redemption_confirm(self, redemption_id):
        """Xác nhận bổ sung gói dữ liệu"""
        headers = {
            "authorization": f"Bearer {self.auth_token}",
            "content-type": "application/json",
            "user-agent": Utils.get_random_user_agent()
        }
        payload = {"redemption_id": redemption_id}
        result = self.session.post("https://prod-enduserservices.flexiroam.com/api/user/redemption/confirm", headers=headers, json=payload)
        result_json = result.json()
        if result_json.get("message") != "Redemption confirmed":
            return False, result_json.get("message", "Lỗi không xác định")
        return True, "Thêm gói mới thành công!"

class GitHubManager:
    """Quản lý cập nhật GitHub secrets"""
    def __init__(self, session, repo_owner, repo_name, repo_token):
        self.session = session
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        self.repo_token = repo_token
        self.base_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets"

    def update_secrets(self, secrets):
        """Cập nhật GitHub secrets"""
        try:
            headers = {
                "Authorization": f"Bearer {self.repo_token}",
                "Accept": "application/vnd.github+json"
            }
            response = self.session.get(f"{self.base_url}/public-key", headers=headers)
            response.raise_for_status()
            response_json = response.json()
            public_key = response_json["key"]
            key_id = response_json["key_id"]

            def encrypt(public_key, secret_value):
                public_key = nacl.public.PublicKey(public_key.encode("utf-8"), nacl.encoding.Base64Encoder())
                sealed_box = nacl.public.SealedBox(public_key)
                encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
                return base64.b64encode(encrypted).decode("utf-8")

            all_success = True
            failed_secrets = []
            for key, value in secrets.items():
                url_secret = f"{self.base_url}/{key}"
                data = {"encrypted_value": encrypt(public_key, value), "key_id": key_id}
                resp = self.session.put(url_secret, headers=headers, json=data)
                if resp.status_code not in [201, 204]:
                    all_success = False
                    failed_secrets.append((key, resp.status_code, resp.text))

            if all_success:
                return True, "Cập nhật GitHub secrets thành công"
            error_messages = "; ".join([f"{k}({code}): {text}" for k, code, text in failed_secrets])
            return False, f"Không thể cập nhật một số secrets: {error_messages}"
        except Exception as e:
            return False, f"Lỗi khi cập nhật GitHub secrets: {str(e)}"

def get_csrf(session):
    """Lấy CSRF token"""
    headers = {"referer": "https://www.flexiroam.com/en-us/home", "user-agent": Utils.get_random_user_agent()}
    result = session.get("https://www.flexiroam.com/api/auth/csrf", headers=headers)
    result_json = result.json()
    if "csrfToken" not in result_json:
        return False, result.text
    return True, result_json["csrfToken"]

def credentials(session, csrf, token):
    """Thiết lập phiên an toàn với CSRF và auth token"""
    result = session.post(
        url="https://www.flexiroam.com/api/auth/callback/credentials",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "referer": "https://www.flexiroam.com/en-us/login",
            "user-agent": Utils.get_random_user_agent(),
            "x-auth-return-redirect": "1"
        },
        data={
            "token": token,
            "redirect": "false",
            "csrfToken": csrf,
            "callbackUrl": "https://www.flexiroam.com/en-us/login"
        }
    )
    result_json = result.json()
    if "url" not in result_json:
        return False, result.text
    return True, ""

def update_session(session):
    """Cập nhật phiên"""
    headers = {"referer": "https://www.flexiroam.com/en-us/home", "user-agent": Utils.get_random_user_agent()}
    result = session.get("https://www.flexiroam.com/api/auth/session", headers=headers)
    result_json = result.json()
    if "expires" not in result_json:
        return False, result.text
    return True, ""

def update_session_thread(session):
    """Luồng cập nhật phiên định kỳ"""
    while True:
        success, result = update_session(session)
        if not success:
            logging.error("❌ Cập nhật phiên thất bại: %s", result)
        else:
            logging.debug("🔄 Cập nhật phiên thành công")
        time.sleep(3600)

def auto_active_plans_thread(plan_manager):
    """Luồng quản lý và kích hoạt gói dữ liệu tự động"""
    def select_out_plans(plans):
        new_plans = []
        for plan in plans["plans"]:
            if plan["circleChart"]["percentage"] != 0:
                new_plans.append(plan)
        return new_plans

    def get_active_percentage(plans):
        total_rate = 0
        for plan in plans:
            if plan["status"] == 'Active':
                total_rate += plan["circleChart"]["percentage"]
        return total_rate

    def get_inactive_plan(plans):
        count, total_rate, plan_id = 0, 0, 0
        for plan in plans["plans"]:
            if plan["status"] == 'In-active':
                count += 1
                total_rate += plan["circleChart"]["percentage"]
                if plan_id == 0:
                    plan_id = plan["planId"]
        return count, total_rate, plan_id

    day_get = 0
    time_sec = 0
    last_get_plans_time = datetime.now() - timedelta(hours=7)

    while True:
        time.sleep(120)
        time_sec += 120
        if time_sec > 86400:  # Reset sau 1 ngày
            day_get = 0
            time_sec = 0

        success, result_plans = plan_manager.get_plans()
        if not success and "Không tìm thấy thông tin gói dữ liệu" not in result_plans:
            logging.error("❌ Lấy thông tin gói thất bại: %s", result_plans)
            continue
        if not success:
            result_plans = {"plans": []}

        active_plans = select_out_plans(result_plans)
        balance_count, inactive_rate, first_plan_id = get_inactive_plan(result_plans)
        active_rate = get_active_percentage(active_plans)

        logging.info("👤 Trạng thái gói: Hoạt động %.2f GB | Không hoạt động %.2f GB | Có sẵn %d gói",
                     (active_rate / 100) * 3, (inactive_rate / 100) * 3, balance_count)

        current_time = datetime.now()

        if active_rate <= 30 and balance_count != 0:
            success, result = plan_manager.start_plan(first_plan_id)
            if not success:
                logging.error("❌ Kích hoạt gói thất bại: %s", result)
                continue
            if current_time - last_get_plans_time >= timedelta(hours=6):
                last_get_plans_time = datetime.now() - timedelta(hours=5)
            logging.info("✅ Kích hoạt gói thành công [ID: %s]", str(first_plan_id))
            continue

        if balance_count < 2 and day_get < 4 and current_time - last_get_plans_time >= timedelta(hours=6):
            card_number = Utils.generate_card_number(Utils.CARD_BIN)
            success, result = plan_manager.eligibility_plan(card_number)
            if not success:
                if result == "We are currently processing your previous redemption, kindly retry again later":
                    logging.warning("⏳ Giới hạn tốc độ - Đợi lần thử tiếp theo (Thẻ: %s)", card_number[-4:])
                    last_get_plans_time = datetime.now()
                    continue
                if "Account banned" in result or "Số thẻ không đáp ứng yêu cầu" in result:
                    logging.critical("🚫 Dịch vụ bị chấm dứt: %s (Thẻ: %s)", result, card_number[-4:])
                    exit(-1)
                logging.error("❌ Xác thực thẻ thất bại: %s (Thẻ: %s)", result, card_number[-4:])
                continue

            success, result = plan_manager.redemption_confirm(result)
            if not success:
                logging.error("❌ Thêm gói thất bại: %s (Thẻ: %s)", result, card_number[-4:])
                continue

            logging.info("🎉 Thêm gói thành công (Thẻ: %s)", card_number[-4:])
            day_get += 1
            last_get_plans_time = datetime.now()

def main():
    """Hàm chính điều phối toàn bộ quy trình"""
    logging.info("🔄 Khởi tạo dịch vụ tự động Flexiroam v2.0")
    session = requests.session()

    user_manager = UserManager(session)
    plan_manager = None
    github_manager = None

    # Lấy biến môi trường
    repo_owner = os.environ.get('repo_owner', '')
    repo_name = os.environ.get('repo_name', '')
    repo_token = os.environ.get('repo_token', '')
    user_email = os.environ.get('usr_email', '')
    user_password = os.environ.get('usr_pass', '@Sadb0iz')  # Mặc định nếu không cung cấp
    auth_token = os.environ.get('usr_auth_token', '')

    if repo_owner and repo_name and repo_token:
        github_manager = GitHubManager(session, repo_owner, repo_name, repo_token)

    # Đăng ký nếu chưa có email
    if not user_email:
        logging.info("ℹ️ Không có email, đăng ký người dùng mới...")
        success, result = user_manager.register()
        if not success:
            logging.error(result)
            return
        user_email = result["email"]
        success, verification_token = user_manager.get_verification_token(user_email)
        if not success:
            logging.error(verification_token)
            return
        success, message = user_manager.verify(verification_token)
        if not success:
            logging.error(message)
            return
        logging.info(f"✅ Đăng ký thành công: {user_email}")

        if github_manager:
            success, result = github_manager.update_secrets({"usr_email": user_email})
            if success:
                logging.info("✅ Cập nhật GitHub secrets với email")
            else:
                logging.warning(f"⚠️ Không thể cập nhật GitHub secrets: {result}")

    # Đăng nhập
    if not auth_token:
        success, result = user_manager.login(user_email, user_password)
        if not success:
            logging.error(f"❌ Đăng nhập thất bại: {result}")
            return
        auth_token = result["token"]
        logging.info(f"🔑 Lấy auth_token: {auth_token}")

        if github_manager:
            success, result = github_manager.update_secrets({"usr_auth_token": auth_token})
            if success:
                logging.info("✅ Cập nhật GitHub secrets với auth_token")
            else:
                logging.warning(f"⚠️ Không thể cập nhật GitHub secrets: {result}")

    # Lấy CSRF và thiết lập phiên
    logging.info("🔐 Lấy CSRF token...")
    success, csrf_token = get_csrf(session)
    if not success:
        logging.error("❌ Lấy CSRF thất bại: %s", csrf_token)
        return

    logging.info("🛡️ Thiết lập phiên an toàn...")
    success, message = credentials(session, csrf_token, auth_token)
    if not success:
        logging.error("❌ Thiết lập phiên thất bại: %s", message)
        return

    plan_manager = PlanManager(session, auth_token, user_email)

    # Khởi động các luồng
    threading.Thread(target=update_session_thread, daemon=True, args=(session,)).start()
    threading.Thread(target=auto_active_plans_thread, daemon=True, args=(plan_manager,)).start()

    # Giữ chương trình chạy
    while True:
        time.sleep(1000)

if __name__ == "__main__":
    main()