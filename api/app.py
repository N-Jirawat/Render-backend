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

# ================== CORS ==================
CORS(app, 
     origins=[
         "http://localhost:3000",  # สำหรับ development
         "https://your-frontend-domain.vercel.app",  # แก้เป็น domain จริงของคุณ
         "https://mangoleafanalyzer.onrender.com",  # เพิ่ม domain อื่นถ้ามี
     ],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization", "Access-Control-Allow-Origin"],
     supports_credentials=True
)

@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    allowed_origins = [
        "http://localhost:3000",
        "https://your-frontend-domain.vercel.app",
        "https://mangoleafanalyzer.onrender.com",
    ]
    if origin in allowed_origins:
        response.headers.add('Access-Control-Allow-Origin', origin)
    else:
        response.headers.add('Access-Control-Allow-Origin', '*')
    
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    response.headers.add('Access-Control-Max-Age', '3600')
    return response

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify({'status': 'preflight_ok'})
        origin = request.headers.get('Origin')
        allowed_origins = [
            "http://localhost:3000",
            "https://your-frontend-domain.vercel.app",
            "https://mangoleafanalyzer.onrender.com",
        ]
        if origin in allowed_origins:
            response.headers.add("Access-Control-Allow-Origin", origin)
        else:
            response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization,Accept")
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
        raise

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

def is_admin_user(token):
    """Verify if the user is an admin based on Firebase token"""
    try:
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token.get('uid')
        user_ref = db.collection("users").document(uid)
        user_doc = user_ref.get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            return user_data.get('role') == 'admin'
        return False
    except Exception as e:
        logger.error(f"Error verifying admin user: {e}")
        return False

# ================== Routes ==================
@app.route('/', methods=['GET', 'OPTIONS'])
def home():
    return jsonify({
        "message": "Mango User Management API",
        "status": "running",
        "version": "1.3.1",
        "server": "Vercel",
        "cors_enabled": True,
        "endpoints": {
            "health": "/health",
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

@app.route('/update_email', methods=['POST', 'OPTIONS'])
def update_email():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight_ok'})
        origin = request.headers.get('Origin')
        allowed_origins = [
            "http://localhost:3000",
            "https://your-frontend-domain.vercel.app",
            "https://mangoleafanalyzer.onrender.com",
        ]
        if origin in allowed_origins:
            response.headers.add("Access-Control-Allow-Origin", origin)
        else:
            response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization,Accept")
        response.headers.add('Access-Control-Allow-Methods', "POST,OPTIONS")
        return response

    try:
        # ตรวจสอบว่าเป็นแอดมิน
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "ต้องระบุ Firebase ID Token ใน Authorization header"}), 401
        
        token = auth_header.split('Bearer ')[1]
        if not is_admin_user(token):
            return jsonify({"error": "ต้องเป็นแอดมินเท่านั้นถึงจะอัปเดตอีเมลได้"}), 403

        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400

        uid = data.get("uid", "").strip()
        new_email = data.get("email", "").strip()  # เปลี่ยนชื่อ key เป็น email เพื่อให้สอดคล้องกับ frontend

        if not uid or not new_email:
            return jsonify({"error": "ต้องระบุ UID และอีเมลใหม่"}), 400

        # Validate email format
        email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_regex, new_email):
            return jsonify({"error": "รูปแบบอีเมลไม่ถูกต้อง"}), 400

        # Check if new email already exists
        try:
            existing_user = auth.get_user_by_email(new_email)
            if existing_user.uid != uid:
                return jsonify({"error": "อีเมลนี้ถูกใช้งานแล้วโดยผู้ใช้อื่น"}), 400
        except auth.UserNotFoundError:
            pass

        # Update email in Firebase Authentication
        auth.update_user(uid, email=new_email, email_verified=False)

        # Update email in Firestore
        user_ref = db.collection("users").document(uid)
        user_ref.update({"email": new_email})

        logger.info(f"Email updated successfully for user {uid}")

        return jsonify({
            "message": "อัปเดตอีเมลเรียบร้อยแล้ว",
            "new_email": new_email
        })

    except auth.UserNotFoundError:
        return jsonify({"error": "ไม่พบผู้ใช้ที่มี UID นี้"}), 404
    except Exception as e:
        logger.error(f"Error updating email: {e}")
        return jsonify({"error": f"เกิดข้อผิดพลาดในการอัปเดตอีเมล: {str(e)}"}), 500

@app.route('/delete_user', methods=['DELETE', 'OPTIONS'])
def delete_user():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight_ok'})
        origin = request.headers.get('Origin')
        allowed_origins = [
            "http://localhost:3000",
            "https://your-frontend-domain.vercel.app",
            "https://mangoleafanalyzer.onrender.com",
        ]
        if origin in allowed_origins:
            response.headers.add("Access-Control-Allow-Origin", origin)
        else:
            response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization,Accept")
        response.headers.add('Access-Control-Allow-Methods', "DELETE,OPTIONS")
        return response

    try:
        # ตรวจสอบว่าเป็นแอดมิน
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "ต้องระบุ Firebase ID Token ใน Authorization header"}), 401
        
        token = auth_header.split('Bearer ')[1]
        if not is_admin_user(token):
            return jsonify({"error": "ต้องเป็นแอดมินเท่านั้นถึงจะลบผู้ใช้ได้"}), 403

        data = request.get_json() or {}
        uid = data.get("uid", "").strip()

        if not uid:
            return jsonify({"error": "ต้องระบุ UID"}), 400

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
        return jsonify({"error": f"เกิดข้อผิดพลาดในการลบผู้ใช้: {str(e)}"}), 500

@app.route('/test', methods=['GET', 'POST', 'OPTIONS'])
def test_endpoint():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight_ok'})
        origin = request.headers.get('Origin')
        allowed_origins = [
            "http://localhost:3000",
            "https://your-frontend-domain.vercel.app",
            "https://mangoleafanalyzer.onrender.com",
        ]
        if origin in allowed_origins:
            response.headers.add("Access-Control-Allow-Origin", origin)
        else:
            response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization,Accept")
        response.headers.add('Access-Control-Allow-Methods', "GET,POST,OPTIONS")
        return response

    return jsonify({
        "message": "Test endpoint working",
        "method": request.method,
        "timestamp": "2025",
        "server": "Vercel",
        "cors_working": True,
        "origin": request.headers.get('Origin', 'No origin header')
    })

# ================== Error Handlers ==================
@app.errorhandler(404)
def not_found(error):
    response = jsonify({"error": "Endpoint not found"})
    origin = request.headers.get('Origin')
    allowed_origins = [
        "http://localhost:3000",
        "https://your-frontend-domain.vercel.app",
        "https://mangoleafanalyzer.onrender.com",
    ]
    if origin in allowed_origins:
        response.headers.add("Access-Control-Allow-Origin", origin)
    return response, 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    response = jsonify({"error": "Internal server error"})
    origin = request.headers.get('Origin')
    allowed_origins = [
        "http://localhost:3000",
        "https://your-frontend-domain.vercel.app",
        "https://mangoleafanalyzer.onrender.com",
    ]
    if origin in allowed_origins:
        response.headers.add("Access-Control-Allow-Origin", origin)
    return response, 500

# ================== Main ==================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    logger.info(f"Starting Flask app on port {port}, debug={debug}")
    app.run(host='0.0.0.0', port=port, debug=debug)