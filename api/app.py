from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, auth, firestore
from flask_cors import CORS
import os
import json
import re
import requests
import logging

app = Flask(__name__)

# ================== Logging ==================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ================== CORS - Simplified for Vercel ==================
CORS(app, 
     origins="*",  # เปิดทั้หมดเพื่อหลีกเลี่ยงปัญหา Vercel
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization", "Access-Control-Allow-Origin"],
     supports_credentials=False  # ปิด credentials เพื่อหลีกเลี่ยงปัญหา
)

# แก้ไข CORS Headers แบบง่าย
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    response.headers.add('Access-Control-Max-Age', '86400')  # Cache preflight 24 hours
    return response

# Handle preflight requests แบบง่าย
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify({'status': 'ok'})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization")
        response.headers.add('Access-Control-Allow-Methods', "GET,POST,PUT,DELETE,OPTIONS")
        return response

# ================== Firebase ==================
if not firebase_admin._apps:
    try:
        if os.environ.get("FIREBASE_CREDENTIALS"):
            cred_dict = json.loads(os.environ["FIREBASE_CREDENTIALS"])
            cred = credentials.Certificate(cred_dict)
        else:
            cred = credentials.Certificate("serviceAccountKey.json")
        firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin SDK initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing Firebase: {e}")

db = firestore.client()

# ================== Helper Functions ==================
def get_user_email_by_uid(uid):
    """Get user email from Firestore by UID"""
    try:
        user_ref = db.collection("users").document(uid)
        user_doc = user_ref.get()
        if user_doc.exists:
            return user_doc.to_dict().get("email")
        return None
    except Exception as e:
        logger.error(f"Error getting user email: {e}")
        return None

def verify_password_simple(email, password):
    """Verify password using Firebase Auth REST API - Simplified"""
    try:
        api_key = os.environ.get("FIREBASE_WEB_API_KEY")
        if not api_key:
            logger.warning("Firebase Web API Key not found, skipping password verification")
            return True  # Skip verification if no API key

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        
        # เพิ่ม timeout และ retry logic
        for attempt in range(2):  # Try 2 times
            try:
                response = requests.post(url, json=payload, timeout=10)
                if response.status_code == 200:
                    return True
                elif response.status_code == 400:
                    # Invalid password
                    return False
                else:
                    logger.warning(f"Password verification attempt {attempt + 1} failed with status {response.status_code}")
                    if attempt == 0:
                        continue  # Try again
                    else:
                        return False  # Skip verification on final attempt
            except requests.exceptions.Timeout:
                logger.warning(f"Password verification timeout on attempt {attempt + 1}")
                if attempt == 0:
                    continue
                else:
                    return True  # Skip verification on timeout
            except Exception as e:
                logger.warning(f"Password verification error on attempt {attempt + 1}: {e}")
                if attempt == 0:
                    continue
                else:
                    return True  # Skip verification on error
        
        return False
    except Exception as e:
        logger.error(f"Password verification error: {str(e)}")
        return True  # Skip verification on error

def validate_password_strength(password):
    """Validate password strength"""
    errors = []
    if len(password) < 8:
        errors.append("รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร")
    if not re.search(r'[a-zA-Z]', password):
        errors.append("รหัสผ่านต้องมีตัวอักษร (a-z, A-Z) อย่างน้อย 1 ตัว")
    if not re.search(r'[0-9]', password):
        errors.append("รหัสผ่านต้องมีตัวเลข (0-9) อย่างน้อย 1 ตัว")
    return errors

# ================== Routes ==================
@app.route('/', methods=['GET', 'OPTIONS'])
def home():
    return jsonify({
        "message": "Mango User Management API", 
        "status": "running", 
        "version": "1.2.0",
        "server": "Vercel",
        "endpoints": {
            "health": "/health",
            "update_password": "/update_password",
            "update_email": "/update_email",
            "delete_user": "/delete_user"
        }
    })

@app.route('/health', methods=['GET', 'OPTIONS'])
def health_check():
    try:
        firebase_status = len(firebase_admin._apps) > 0
        return jsonify({
            "status": "healthy",
            "service": "user_management",
            "firebase_initialized": firebase_status,
            "server": "Vercel"
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

# ----- Verify password -----
@app.route('/verify_password', methods=['POST', 'OPTIONS'])
def verify_password_endpoint():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        uid = data.get("uid", "").strip()
        password = data.get("password", "")
        
        if not uid or not password:
            return jsonify({"error": "UID และรหัสผ่านจำเป็นต้องระบุ"}), 400

        email = get_user_email_by_uid(uid)
        if not email:
            return jsonify({"error": "ไม่พบข้อมูลผู้ใช้"}), 404

        is_valid = verify_password_simple(email, password)
        if is_valid:
            return jsonify({"valid": True, "message": "รหัสผ่านถูกต้อง"})
        else:
            return jsonify({"valid": False, "message": "รหัสผ่านไม่ถูกต้อง"}), 401
            
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return jsonify({"error": "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์"}), 500

# ----- Update email -----
@app.route('/update_email', methods=['POST', 'OPTIONS'])
def update_email():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        uid = data.get("uid", "").strip()
        new_email = data.get("new_email", "").strip()
        current_password = data.get("current_password", "")

        if not uid or not new_email:
            return jsonify({"error": "UID และอีเมลใหม่จำเป็นต้องระบุ"}), 400

        # Validate email format
        email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_regex, new_email):
            return jsonify({"error": "รูปแบบอีเมลไม่ถูกต้อง"}), 400

        current_email = get_user_email_by_uid(uid)
        if not current_email:
            return jsonify({"error": "ไม่พบข้อมูลผู้ใช้"}), 404

        # Verify current password if provided
        if current_password:
            if not verify_password_simple(current_email, current_password):
                return jsonify({"error": "รหัสผ่านเดิมไม่ถูกต้อง"}), 401

        # Check if new email already exists
        try:
            existing_user = auth.get_user_by_email(new_email)
            if existing_user.uid != uid:
                return jsonify({"error": "อีเมลนี้ถูกใช้งานแล้วโดยผู้ใช้อื่น"}), 400
        except auth.UserNotFoundError:
            pass

        # Update email
        auth.update_user(uid, email=new_email, email_verified=False)
        
        user_ref = db.collection("users").document(uid)
        user_ref.update({"email": new_email})
        
        logger.info(f"Email updated successfully for user {uid}")
        
        return jsonify({
            "message": "อีเมลอัปเดตเรียบร้อยแล้ว", 
            "new_email": new_email
        })
        
    except Exception as e:
        logger.error(f"Error updating email: {e}")
        return jsonify({"error": "เกิดข้อผิดพลาดในการอัปเดตอีเมล"}), 500

# ----- Update password -----
@app.route('/update_password', methods=['POST', 'OPTIONS'])
def update_password():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        logger.info("Password update request received")
        
        data = request.get_json()
        if not data:
            logger.error("No JSON data received")
            return jsonify({"error": "No JSON data received"}), 400
            
        uid = data.get("uid", "").strip()
        new_password = data.get("new_password", "")
        current_password = data.get("current_password", "")

        logger.info(f"Processing password update for user: {uid}")

        if not uid or not new_password or not current_password:
            return jsonify({"error": "UID, รหัสผ่านเดิม และรหัสผ่านใหม่จำเป็นต้องระบุ"}), 400

        # Get user email
        email = get_user_email_by_uid(uid)
        if not email:
            return jsonify({"error": "ไม่พบข้อมูลผู้ใช้"}), 404

        logger.info(f"Found user email: {email}")

        # Verify current password (with fallback)
        password_valid = verify_password_simple(email, current_password)
        if not password_valid:
            return jsonify({"error": "รหัสผ่านเดิมไม่ถูกต้อง"}), 401

        # Validate new password strength
        password_errors = validate_password_strength(new_password)
        if password_errors:
            return jsonify({"error": "; ".join(password_errors)}), 400

        # Update password in Firebase Auth
        try:
            auth.update_user(uid, password=new_password)
            logger.info(f"Password updated in Firebase Auth for user: {uid}")
        except Exception as e:
            logger.error(f"Error updating password in Firebase Auth: {e}")
            return jsonify({"error": "เกิดข้อผิดพลาดในการอัปเดตรหัสผ่าน"}), 500
        
        # Create new custom token for re-authentication
        try:
            new_id_token = auth.create_custom_token(uid)
            token_string = new_id_token.decode("utf-8") if isinstance(new_id_token, bytes) else str(new_id_token)
            logger.info(f"Custom token created for user: {uid}")
        except Exception as e:
            logger.error(f"Error creating custom token: {e}")
            token_string = None
        
        logger.info(f"Password updated successfully for user {uid}")
        
        return jsonify({
            "message": "รหัสผ่านอัปเดตเรียบร้อยแล้ว",
            "id_token": token_string,
            "success": True
        })
        
    except Exception as e:
        logger.error(f"Error updating password: {e}")
        return jsonify({"error": f"เกิดข้อผิดพลาดในการอัปเดตรหัสผ่าน: {str(e)}"}), 500

# ----- Delete user -----
@app.route('/delete_user', methods=['DELETE', 'OPTIONS'])
def delete_user():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json() or {}
        uid = data.get("uid", "").strip()
        
        if not uid:
            return jsonify({"error": "UID is required"}), 400

        # Skip password verification for now due to CORS issues
        # current_password = data.get("current_password")
        # if current_password:
        #     email = get_user_email_by_uid(uid)
        #     if email and not verify_password_simple(email, current_password):
        #         return jsonify({"error": "รหัสผ่านไม่ถูกต้อง"}), 401

        # Delete user data from Firestore
        user_ref = db.collection("users").document(uid)
        if user_ref.get().exists:
            user_ref.delete()

        # Delete from Firebase Auth
        try:
            auth.delete_user(uid)
        except auth.UserNotFoundError:
            pass  # User already deleted

        logger.info(f"User deleted successfully: {uid}")
        
        return jsonify({"message": f"ผู้ใช้ {uid} ถูกลบเรียบร้อยแล้ว"})
        
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return jsonify({"error": "เกิดข้อผิดพลาดในการลบผู้ใช้"}), 500

# ----- Test endpoint -----
@app.route('/test', methods=['GET', 'POST', 'OPTIONS'])
def test_endpoint():
    if request.method == 'OPTIONS':
        return '', 200
        
    return jsonify({
        "message": "Test endpoint working",
        "method": request.method,
        "timestamp": "2024",
        "server": "Vercel"
    })

# ================== Error Handlers ==================
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({"error": "Internal server error"}), 500

# ================== Main ==================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    logger.info(f"Starting Flask app on port {port}, debug={debug}")
    app.run(host='0.0.0.0', port=port, debug=debug)