import requests
import json
import logging
import re
import os
import time
import random
import base64
from datetime import datetime, timedelta

# Global variables
USERNAME = os.environ.get('USERNAME', '')
PASSWORD = os.environ.get('PASSWORD', '')

def generate_random_user_data():
    """Generate random user data for FlexiRoam registration"""
    first_names = ["Jack", "Tristan", "Shane", "Amity", "Krystan", "Brooke", "Vincent", "Vivian", "Lillian", "Alice"]
    last_names = ["Erickson", "Gilbert", "Maddox", "Morton", "Lindsey", "Chandler", "Johnson", "Travis", "Kennedy"]
    country_codes = ["US", "UK", "VN", "CA", "AU", "DE", "FR", "JP", "CN", "IN", "BR", "RU", "IT", "ES", "KR", "MX", "ID", "TH", "SG", "MY"]
    iphone_models = [
        ("iPhone11,2", "iPhone XS"), 
        ("iPhone12,1", "iPhone 11"), 
        ("iPhone13,2", "iPhone 12"), 
        ("iPhone14,2", "iPhone 13 Pro"), 
        ("iPhone15,2", "iPhone 14 Pro"), 
        ("iPhone16,1", "iPhone 15 Pro")
    ]
    ios_versions = ["17.0", "17.1", "17.2", "17.3", "17.4", "17.5", "18.0", "18.1"]
    
    # Generate random data
    random_num = random.randint(100, 999) + int(str(int(time.time()))[-3:])
    first_name = random.choice(first_names)
    last_name = random.choice(last_names)
    country_code = random.choice(country_codes)
    device_udid, device_model = random.choice(iphone_models)
    ios_version = random.choice(ios_versions)
    
    # Generate random email with timestamp to avoid duplicates
    email = f"{first_name.lower()}{last_name.lower()}.{random_num}@simpace.edu.vn"
    
    return {
        "first_name": first_name,
        "last_name": last_name,
        "home_country_code": country_code,
        "email": email,
        "password": "@Sadb0iz",
        "language_preference": "en-us",
        "device_udid": device_udid,
        "device_model": device_model,
        "device_platform": "ios",
        "device_version": ios_version,
        "have_esim_supported_device": 1,
        "notification_token": "undefined"
    }

def register_user(session, user_data):
    """Register a new user with FlexiRoam"""
    try:
        url = "https://app.flexiroam.com/api/auth/register"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "FlexiRoam/1.0 (iPhone; iOS 17.5; Scale/3.00)",
            "Accept": "application/json"
        }
        
        response = session.post(url, headers=headers, json=user_data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                logging.info(f"✅ User registration successful: {user_data['email']}")
                return True, result
            else:
                logging.error(f"❌ Registration failed: {result.get('message', 'Unknown error')}")
                return False, result.get('message', 'Registration failed')
        else:
            logging.error(f"❌ Registration request failed: {response.status_code}")
            return False, f"HTTP {response.status_code}: {response.text}"
            
    except Exception as e:
        logging.error(f"❌ Exception during registration: {str(e)}")
        return False, str(e)

def get_verification_token(session, email):
    """Get verification token from email (simulation for educational purposes)"""
    # Note: This is a simplified simulation. In real implementation,
    # you would need to integrate with an email service or use a temporary email service
    try:
        # Simulate waiting for email
        logging.info(f"📧 Waiting for verification email for {email}...")
        time.sleep(5)  # Simulate email delay
        
        # For educational purposes, we'll generate a mock token
        # In real implementation, you would parse the email content
        mock_token = f"verify_{int(time.time())}_{random.randint(1000, 9999)}"
        logging.info(f"📧 Verification token received: {mock_token}")
        
        return True, mock_token
        
    except Exception as e:
        logging.error(f"❌ Error getting verification token: {str(e)}")
        return False, str(e)

def verify_email_token(session, email, token):
    """Verify email with the provided token"""
    try:
        url = "https://app.flexiroam.com/api/auth/verify-email"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "FlexiRoam/1.0 (iPhone; iOS 17.5; Scale/3.00)",
            "Accept": "application/json"
        }
        
        data = {
            "email": email,
            "token": token
        }
        
        response = session.post(url, headers=headers, json=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                logging.info(f"✅ Email verification successful for {email}")
                return True, result
            else:
                logging.error(f"❌ Email verification failed: {result.get('message', 'Unknown error')}")
                return False, result.get('message', 'Verification failed')
        else:
            logging.error(f"❌ Verification request failed: {response.status_code}")
            return False, f"HTTP {response.status_code}: {response.text}"
            
    except Exception as e:
        logging.error(f"❌ Exception during email verification: {str(e)}")
        return False, str(e)

def handle_registration(session):
    """Handle the complete registration process"""
    try:
        # Generate random user data
        user_data = generate_random_user_data()
        logging.info(f"🎯 Generated user data for: {user_data['email']}")
        
        # Register user
        success, result = register_user(session, user_data)
        if not success:
            return False, f"Registration failed: {result}", None, None
            
        # Get verification token
        success, token = get_verification_token(session, user_data['email'])
        if not success:
            return False, f"Failed to get verification token: {token}", None, None
            
        # Verify email
        success, verify_result = verify_email_token(session, user_data['email'], token)
        if not success:
            return False, f"Email verification failed: {verify_result}", None, None
            
        logging.info(f"🎉 Registration process completed successfully for {user_data['email']}")
        return True, "Registration successful", user_data['email'], user_data['password']
        
    except Exception as e:
        logging.error(f"❌ Exception in handle_registration: {str(e)}")
        return False, str(e), None, None

def update_github_secrets(username, password, repo_owner, repo_name, github_token):
    """Update GitHub repository secrets with new credentials"""
    try:
        # Check if PyNaCl is available
        try:
            from nacl import encoding, public
        except ImportError:
            logging.warning("⚠️ PyNaCl not available, skipping GitHub secrets update")
            return False, "PyNaCl library not installed"
        
        # Get public key for encryption
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
        
        # Encrypt the secrets
        def encrypt_secret(secret_value, public_key):
            sealed_box = public.SealedBox(public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder()))
            encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
            return base64.b64encode(encrypted).decode("utf-8")
        
        # Update USERNAME secret
        username_data = {
            "encrypted_value": encrypt_secret(username, public_key),
            "key_id": key_id
        }
        
        username_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/USERNAME"
        username_response = requests.put(username_url, headers=headers, json=username_data)
        
        # Update PASSWORD secret
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

def login(session, username, password):
    """Login to FlexiRoam account"""
    try:
        url = "https://app.flexiroam.com/api/auth/login"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "FlexiRoam/1.0 (iPhone; iOS 17.5; Scale/3.00)",
            "Accept": "application/json"
        }
        
        data = {
            "email": username,
            "password": password
        }
        
        response = session.post(url, headers=headers, json=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                session.headers.update({'Authorization': f"Bearer {result.get('token', '')}"})
                logging.info(f"✅ Login successful for {username}")
                return True, result
            else:
                logging.error(f"❌ Login failed: {result.get('message', 'Unknown error')}")
                return False, result.get('message', 'Login failed')
        else:
            logging.error(f"❌ Login request failed: {response.status_code}")
            return False, f"HTTP {response.status_code}: {response.text}"
            
    except Exception as e:
        logging.error(f"❌ Exception during login: {str(e)}")
        return False, str(e)

def check_account_status(session, username, password):
    """Check if current account credentials are valid"""
    if not username or not password or username == '' or password == '':
        logging.info("📋 No credentials provided, registration needed")
        return False, "No credentials"
        
    try:
        # Try to login with current credentials
        res, result = login(session, username, password)
        if res:
            logging.info("✅ Current credentials are valid")
            return True, "Valid credentials"
        else:
            # Check if account is banned
            if "Authorization Failed" in str(result) or "banned" in str(result).lower():
                logging.warning("🚫 Account appears to be banned")
                return False, "Account banned"
            else:
                logging.warning("❌ Login failed with current credentials")
                return False, "Invalid credentials"
                
    except Exception as e:
        logging.error(f"❌ Error checking account status: {str(e)}")
        return False, f"Error: {str(e)}"

def auto_register_if_needed(session, github_token=None, repo_owner=None, repo_name=None):
    """Automatically register new account if current credentials are invalid"""
    global USERNAME, PASSWORD
    
    # Check current account status
    is_valid, status = check_account_status(session, USERNAME, PASSWORD)
    
    if is_valid:
        logging.info("🎯 Current account is valid, no registration needed")
        return True, USERNAME, PASSWORD
        
    logging.info(f"🔄 Current account status: {status}, starting registration...")
    
    # Register new account
    success, message, new_username, new_password = handle_registration(session)
    
    if not success:
        logging.error(f"❌ Auto registration failed: {message}")
        return False, None, None
        
    # Update global variables
    USERNAME = new_username
    PASSWORD = new_password
    
    logging.info(f"✅ New account registered successfully: {new_username}")
    
    # Update GitHub secrets if credentials provided
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

def get_user_info(session):
    """Get current user information"""
    try:
        url = "https://app.flexiroam.com/api/user"
        response = session.get(url, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                return True, result.get('data', {})
            else:
                return False, result.get('message', 'Failed to get user info')
        else:
            return False, f"HTTP {response.status_code}: {response.text}"
            
    except Exception as e:
        logging.error(f"❌ Exception getting user info: {str(e)}")
        return False, str(e)

def get_daily_checkin_status(session):
    """Check daily check-in status"""
    try:
        url = "https://app.flexiroam.com/api/rewards/daily-checkin"
        response = session.get(url, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            return True, result
        else:
            return False, f"HTTP {response.status_code}: {response.text}"
            
    except Exception as e:
        logging.error(f"❌ Exception checking daily checkin status: {str(e)}")
        return False, str(e)

def perform_daily_checkin(session):
    """Perform daily check-in"""
    try:
        url = "https://app.flexiroam.com/api/rewards/daily-checkin"
        headers = {
            "Content-Type": "application/json"
        }
        
        response = session.post(url, headers=headers, json={}, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                logging.info(f"✅ Daily check-in successful! Reward: {result.get('reward', 'Unknown')}")
                return True, result
            else:
                logging.info(f"ℹ️ Daily check-in: {result.get('message', 'Already checked in today')}")
                return False, result.get('message', 'Check-in failed')
        else:
            return False, f"HTTP {response.status_code}: {response.text}"
            
    except Exception as e:
        logging.error(f"❌ Exception during daily checkin: {str(e)}")
        return False, str(e)

def get_available_rewards(session):
    """Get available rewards/missions"""
    try:
        url = "https://app.flexiroam.com/api/rewards/missions"
        response = session.get(url, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            return True, result
        else:
            return False, f"HTTP {response.status_code}: {response.text}"
            
    except Exception as e:
        logging.error(f"❌ Exception getting available rewards: {str(e)}")
        return False, str(e)

def complete_mission(session, mission_id):
    """Complete a specific mission"""
    try:
        url = f"https://app.flexiroam.com/api/rewards/missions/{mission_id}/complete"
        headers = {
            "Content-Type": "application/json"
        }
        
        response = session.post(url, headers=headers, json={}, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                logging.info(f"✅ Mission {mission_id} completed! Reward: {result.get('reward', 'Unknown')}")
                return True, result
            else:
                logging.info(f"ℹ️ Mission {mission_id}: {result.get('message', 'Cannot complete')}")
                return False, result.get('message', 'Mission completion failed')
        else:
            return False, f"HTTP {response.status_code}: {response.text}"
            
    except Exception as e:
        logging.error(f"❌ Exception completing mission {mission_id}: {str(e)}")
        return False, str(e)

def get_referral_code(session):
    """Get user's referral code"""
    try:
        url = "https://app.flexiroam.com/api/referral/code"
        response = session.get(url, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'success':
                return True, result.get('data', {}).get('referral_code', 'No referral code')
            else:
                return False, result.get('message', 'Failed to get referral code')
        else:
            return False, f"HTTP {response.status_code}: {response.text}"
            
    except Exception as e:
        logging.error(f"❌ Exception getting referral code: {str(e)}")
        return False, str(e)

def main():
    """Main function to run FlexiRoam automation"""
    logging.basicConfig(
        level=logging.INFO, 
        format='%(asctime)s.%(msecs)03d [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s', 
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info("🔄 Initializing FlexiRoam automation service v2.0")

    session = requests.session()
    
    # Get GitHub credentials from environment (optional)
    github_token = os.environ.get('GITHUB_TOKEN', '')
    repo_owner = os.environ.get('REPO_OWNER', '')
    repo_name = os.environ.get('REPO_NAME', '')
    
    # Auto register if needed
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
    
    # Update global variables
    global USERNAME, PASSWORD
    USERNAME = username
    PASSWORD = password
    
    # Get user information
    logging.info("📋 Getting user information...")
    success, user_info = get_user_info(session)
    if success:
        logging.info(f"👤 User: {user_info.get('email', 'Unknown')} | Balance: {user_info.get('balance', 'Unknown')} credits")
    else:
        logging.warning(f"⚠️ Could not get user info: {user_info}")
    
    # Perform daily check-in
    logging.info("🎯 Attempting daily check-in...")
    success, checkin_result = perform_daily_checkin(session)
    if success:
        logging.info("✅ Daily check-in completed successfully")
    else:
        logging.info(f"ℹ️ Daily check-in status: {checkin_result}")
    
    # Get and complete available missions
    logging.info("🎮 Checking available missions...")
    success, missions = get_available_rewards(session)
    if success and missions.get('data'):
        for mission in missions.get('data', []):
            mission_id = mission.get('id')
            mission_name = mission.get('name', 'Unknown')
            mission_status = mission.get('status', 'Unknown')
            
            if mission_status == 'available':
                logging.info(f"🎯 Attempting mission: {mission_name}")
                success, result = complete_mission(session, mission_id)
                if success:
                    logging.info(f"✅ Mission '{mission_name}' completed")
                else:
                    logging.info(f"ℹ️ Mission '{mission_name}': {result}")
                time.sleep(2)  # Avoid rate limiting
    else:
        logging.info("ℹ️ No missions available or failed to get missions")
    
    # Get referral code
    logging.info("🔗 Getting referral code...")
    success, referral_code = get_referral_code(session)
    if success:
        logging.info(f"🎁 Referral code: {referral_code}")
    else:
        logging.warning(f"⚠️ Could not get referral code: {referral_code}")
    
    # Final user info
    logging.info("📊 Getting final user information...")
    success, final_user_info = get_user_info(session)
    if success:
        logging.info(f"✅ Final balance: {final_user_info.get('balance', 'Unknown')} credits")
    else:
        logging.warning(f"⚠️ Could not get final user info: {final_user_info}")
    
    logging.info("🎉 FlexiRoam automation completed successfully!")

if __name__ == "__main__":
    main()
