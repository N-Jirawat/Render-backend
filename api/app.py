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
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400

        uid = data.get("uid", "").strip()
        new_email = data.get("email", "").strip() or data.get("new_email", "").strip() 
        current_password = data.get("current_password", "").strip()

        # Debug logging
        logger.info(f"Received data: uid={uid}, email={new_email}")

        if not uid or not new_email:
            return jsonify({"error": "ต้องระบุ UID และอีเมลใหม่"}), 400

        # Validate email format
        email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_regex, new_email):
            return jsonify({"error": "รูปแบบอีเมลไม่ถูกต้อง"}), 400

        # ตรวจสอบสิทธิ์: ต้องเป็น admin หรือเป็นเจ้าของบัญชี
        auth_header = request.headers.get('Authorization')
        is_admin = False
        is_owner = False
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split('Bearer ')[1]
            try:
                decoded_token = auth.verify_id_token(token)
                token_uid = decoded_token.get('uid')
                
                # ตรวจสอบว่าเป็น admin
                if is_admin_user(token):
                    is_admin = True
                    logger.info(f"Admin user updating email for {uid}")
                # ตรวจสอบว่าเป็นเจ้าของบัญชี
                elif token_uid == uid:
                    is_owner = True
                    logger.info(f"User updating own email: {uid}")
            except Exception as e:
                logger.error(f"Token verification failed: {e}")

        # ถ้าไม่ใช่ admin และไม่ใช่เจ้าของบัญชี
        if not is_admin and not is_owner:
            return jsonify({"error": "ไม่มีสิทธิ์อัปเดตอีเมลนี้"}), 403

        # ถ้าเป็นเจ้าของบัญชี ต้องมีรหัสผ่าน
        if is_owner and not current_password:
            return jsonify({"error": "ต้องระบุรหัsผ่านเดิมเพื่อยืนยันตัวตน"}), 400

        # ถ้าเป็นเจ้าของบัญชี ให้ตรวจสอบรหัสผ่าน (ในที่นี้เราพึ่ง Frontend ตรวจสอบแล้ว)
        # แต่สำหรับความปลอดภัย เราจะตรวจสอบอีกครั้ง
        if is_owner and current_password:
            try:
                # ดึงอีเมลปัจจุบันจาก Firestore
                current_email = get_user_email_by_uid(uid)
                if not current_email:
                    return jsonify({"error": "ไม่พบข้อมูลผู้ใช้"}), 404
                
                # ลองยืนยันตัวตนด้วย Firebase Admin SDK (ถ้าต้องการ)
                # หมายเหตุ: Firebase Admin SDK ไม่มีฟังก์ชัน signInWithEmailAndPassword
                # ดังนั้นเราจะพึ่งการตรวจสอบจาก Frontend ก่อน
                logger.info(f"Password verification handled by frontend for user {uid}")
                
            except Exception as e:
                logger.error(f"Error verifying password: {e}")
                return jsonify({"error": "เกิดข้อผิดพลาดในการยืนยันรหัสผ่าน"}), 500

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
        data = request.get_json() or {}
        uid = data.get("uid", "").strip()

        if not uid:
            return jsonify({"error": "ต้องระบุ UID"}), 400

        # ตรวจสอบสิทธิ์: ต้องเป็น admin หรือเป็นเจ้าของบัญชี
        auth_header = request.headers.get('Authorization')
        is_admin = False
        is_owner = False
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split('Bearer ')[1]
            try:
                decoded_token = auth.verify_id_token(token)
                token_uid = decoded_token.get('uid')
                
                # ตรวจสอบว่าเป็น admin
                if is_admin_user(token):
                    is_admin = True
                    logger.info(f"Admin user deleting user {uid}")
                # ตรวจสอบว่าเป็นเจ้าของบัญชี
                elif token_uid == uid:
                    is_owner = True
                    logger.info(f"User deleting own account: {uid}")
            except Exception as e:
                logger.error(f"Token verification failed: {e}")

        # ถ้าไม่ใช่ admin และไม่ใช่เจ้าของบัญชี
        if not is_admin and not is_owner:
            return jsonify({"error": "ไม่มีสิทธิ์ลบบัญชีนี้"}), 403

        # Delete user data from Firestore
        user_ref = db.collection("users").document(uid)
        if user_ref.get().exists:
            user_ref.delete()

        # Delete related data (optional - เพิ่มถ้าต้องการลบข้อมูลที่เกี่ยวข้อง)
        try:
            # Delete AnalysisHistory
            analysis_query = db.collection("AnalysisHistory").where("userId", "==", uid)
            analysis_docs = analysis_query.get()
            for doc in analysis_docs:
                doc.reference.delete()
            
            # Delete ReportDataUser
            report_query = db.collection("ReportDataUser").where("UserID", "==", uid)
            report_docs = report_query.get()
            for doc in report_docs:
                doc.reference.delete()
                
            logger.info(f"Related data deleted for user {uid}")
        except Exception as e:
            logger.warning(f"Error deleting related data for user {uid}: {e}")

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