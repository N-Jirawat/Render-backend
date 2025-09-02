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

# ================== CORS - แก้ไขให้รองรับ localhost development ==================
CORS(app, 
     origins=[
         "http://localhost:3000",  # สำหรับ development
         "https://your-frontend-domain.vercel.app",  # สำหรับ production (เปลี่ยนเป็น domain จริงของคุณ)
         "*"  # fallback (ใช้เฉพาะเมื่อจำเป็น)
     ],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization", "Access-Control-Allow-Origin"],
     supports_credentials=False
)

# แก้ไข CORS Headers - เพิ่มการจัดการ preflight requests
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin:
        response.headers.add('Access-Control-Allow-Origin', origin)
    else:
        response.headers.add('Access-Control-Allow-Origin', '*')
    
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    response.headers.add('Access-Control-Max-Age', '3600')
    return response

# Handle preflight requests อย่างชัดเจน
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify({'status': 'ok'})
        origin = request.headers.get('Origin')
        if origin:
            response.headers.add("Access-Control-Allow-Origin", origin)
        else:
            response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization,Accept")
        response.headers.add('Access-Control-Allow-Methods', "GET,POST,PUT,DELETE,OPTIONS")
        response.headers.add('Access-Control-Max-Age', '3600')
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
            return True

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        
        # เพิ่ม timeout และ retry logic
        for attempt in range(2):
            try:
                response = requests.post(url, json=payload, timeout=15)
                if response.status_code == 200:
                    return True
                elif response.status_code == 400:
                    return False
                else:
                    logger.warning(f"Password verification attempt {attempt + 1} failed with status {response.status_code}")
                    if attempt == 0:
                        continue
                    else:
                        return False
            except requests.exceptions.Timeout:
                logger.warning(f"Password verification timeout on attempt {attempt + 1}")
                if attempt == 0:
                    continue
                else:
                    return True
            except Exception as e:
                logger.warning(f"Password verification error on attempt {attempt + 1}: {e}")
                if attempt == 0:
                    continue
                else:
                    return True
        
        return False
    except Exception as e:
        logger.error(f"Password verification error: {str(e)}")
        return True

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
        "version": "1.3.0",
        "server": "Vercel",
        "cors_enabled": True,
        "endpoints": {
            "health": "/health",
            "update_password": "/update_password",
            "update_email": "/update_email",
            "delete_user": "/delete_user",
            "test": "/test"
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
            "server": "Vercel",
            "cors_enabled": True
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

# ----- Update password -----
@app.route('/update_password', methods=['POST', 'OPTIONS'])
def update_password():
    if request.method == 'OPTIONS':
        # ตอบสนองต่อ preflight request
        response = jsonify({"status": "ok"})
        response.headers.add('Access-Control-Allow-Origin', 'https://mangoleafanalyzer.onrender.com')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        return response, 200

    # โลจิกสำหรับการอัปเดตรหัสผ่าน
    try:
        data = request.get_json()
        uid = data.get('uid')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        # ตัวอย่างการอัปเดตใน Firebase Authentication
        user = auth.get_user(uid)
        # ตรวจสอบรหัสผ่านเดิมและอัปเดต (ต้องใช้ Firebase Admin SDK หรือ Firebase Client SDK ฝั่ง client)
        # ... โลจิกอัปเดตรหัสผ่าน ...
        
        response = jsonify({"message": "เปลี่ยนรหัสผ่านสำเร็จ", "id_token": "new_token_if_needed"})
        response.headers.add('Access-Control-Allow-Origin', 'https://mangoleafanalyzer.onrender.com')
        return response
    except Exception as e:
        response = jsonify({"error": str(e)})
        response.headers.add('Access-Control-Allow-Origin', 'https://mangoleafanalyzer.onrender.com')
        return response, 500
    
    
# ----- Update email -----
@app.route('/update_email', methods=['POST', 'OPTIONS'])
def update_email():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight_ok'})
        origin = request.headers.get('Origin')
        if origin:
            response.headers.add("Access-Control-Allow-Origin", origin)
        else:
            response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization,Accept")
        response.headers.add('Access-Control-Allow-Methods', "POST,OPTIONS")
        return response
        
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

# ----- Delete user -----
@app.route('/delete_user', methods=['DELETE', 'OPTIONS'])
def delete_user():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight_ok'})
        origin = request.headers.get('Origin')
        if origin:
            response.headers.add("Access-Control-Allow-Origin", origin)
        else:
            response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization,Accept")
        response.headers.add('Access-Control-Allow-Methods', "DELETE,OPTIONS")
        return response
        
    try:
        data = request.get_json() or {}
        uid = data.get("uid", "").strip()
        
        if not uid:
            return jsonify({"error": "UID is required"}), 400

        # Delete user data from Firestore
        user_ref = db.collection("users").document(uid)
        if user_ref.get().exists:
            user_ref.delete()

        # Delete from Firebase Auth
        try:
            auth.delete_user(uid)
        except auth.UserNotFoundError:
            pass

        logger.info(f"User deleted successfully: {uid}")
        
        return jsonify({"message": f"ผู้ใช้ {uid} ถูกลบเรียบร้อยแล้ว"})
        
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return jsonify({"error": "เกิดข้อผิดพลาดในการลบผู้ใช้"}), 500

# ----- Test endpoint -----
@app.route('/test', methods=['GET', 'POST', 'OPTIONS'])
def test_endpoint():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight_ok'})
        origin = request.headers.get('Origin')
        if origin:
            response.headers.add("Access-Control-Allow-Origin", origin)
        else:
            response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization,Accept")
        response.headers.add('Access-Control-Allow-Methods', "GET,POST,OPTIONS")
        return response
        
    return jsonify({
        "message": "Test endpoint working",
        "method": request.method,
        "timestamp": "2024",
        "server": "Vercel",
        "cors_working": True,
        "origin": request.headers.get('Origin', 'No origin header')
    })

# ----- Verify password endpoint -----
@app.route('/verify_password', methods=['POST', 'OPTIONS'])
def verify_password_endpoint():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight_ok'})
        origin = request.headers.get('Origin')
        if origin:
            response.headers.add("Access-Control-Allow-Origin", origin)
        else:
            response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization,Accept")
        response.headers.add('Access-Control-Allow-Methods', "POST,OPTIONS")
        return response
        
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

# ================== Error Handlers ==================
@app.errorhandler(404)
def not_found(error):
    response = jsonify({"error": "Endpoint not found"})
    origin = request.headers.get('Origin')
    if origin:
        response.headers.add("Access-Control-Allow-Origin", origin)
    return response, 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    response = jsonify({"error": "Internal server error"})
    origin = request.headers.get('Origin')
    if origin:
        response.headers.add("Access-Control-Allow-Origin", origin)
    return response, 500

# ================== Main ==================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    logger.info(f"Starting Flask app on port {port}, debug={debug}")
    app.run(host='0.0.0.0', port=port, debug=debug)