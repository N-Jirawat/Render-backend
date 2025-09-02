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
         "https://mangoleafanalyzer.onrender.com", 
         "http://localhost:3000", 
         "https://localhost:3000"
     ],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"],
     supports_credentials=True
)

@app.before_request
def handle_options_preflight():
    if request.method == "OPTIONS":
        response = jsonify({"status": "preflight ok"})
        origin = request.headers.get("Origin")
        allowed_origins = [
            "https://mangoleafanalyzer.onrender.com",
            "http://localhost:3000",
            "https://localhost:3000"
        ]
        if origin in allowed_origins:
            response.headers.add("Access-Control-Allow-Origin", origin)
        else:
            response.headers.add("Access-Control-Allow-Origin", "https://mangoleafanalyzer.onrender.com")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response, 200

@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    allowed_origins = [
        "https://mangoleafanalyzer.onrender.com",
        "http://localhost:3000",
        "https://localhost:3000"
    ]
    if origin in allowed_origins:
        response.headers.add('Access-Control-Allow-Origin', origin)
    else:
        response.headers.add('Access-Control-Allow-Origin', 'https://mangoleafanalyzer.onrender.com')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
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

def verify_password(email, password):
    """Verify password using Firebase Auth REST API"""
    try:
        api_key = os.environ.get("FIREBASE_WEB_API_KEY")
        if not api_key:
            logger.error("Firebase Web API Key not found")
            return False

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        response = requests.post(url, json=payload, timeout=15)

        if response.status_code == 200:
            return True
        else:
            error_data = response.json()
            error_message = error_data.get("error", {}).get("message", "Unknown error")
            logger.warning(f"Password verification failed: {error_message}")
            return False
    except requests.exceptions.Timeout:
        logger.error("Password verification timeout")
        return False
    except Exception as e:
        logger.error(f"Password verification error: {str(e)}")
        return False

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
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "message": "Mango User Management API", 
        "status": "running", 
        "version": "1.1.0",
        "endpoints": {
            "health": "/health",
            "check_username": "/check_username",
            "check_email": "/check_email", 
            "verify_password": "/verify_password",
            "update_email": "/update_email",
            "update_password": "/update_password",
            "delete_user": "/delete_user"
        }
    })

@app.route('/health', methods=['GET'])
def health_check():
    try:
        # Test Firebase connection
        firebase_status = len(firebase_admin._apps) > 0
        
        # Test Firestore connection
        test_query = db.collection("users").limit(1).get()
        firestore_status = True
        
        return jsonify({
            "status": "healthy",
            "service": "user_management",
            "firebase_initialized": firebase_status,
            "firestore_connected": firestore_status,
            "timestamp": firestore.SERVER_TIMESTAMP
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy", 
            "error": str(e)
        }), 500

# ----- Check username -----
@app.route('/check_username', methods=['POST'])
def check_username():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        username = data.get("username", "").strip()
        if not username:
            return jsonify({"error": "Username is required"}), 400

        users_ref = db.collection("users")
        docs = users_ref.where("username", "==", username).limit(1).get()
        exists = len(list(docs)) > 0
        
        return jsonify({"exists": exists})
    except Exception as e:
        logger.error(f"Error checking username: {e}")
        return jsonify({"error": "Internal server error"}), 500

# ----- Check email -----
@app.route('/check_email', methods=['POST'])
def check_email():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        email = data.get("email", "").strip()
        if not email:
            return jsonify({"error": "Email is required"}), 400

        users_ref = db.collection("users")
        docs = users_ref.where("email", "==", email).limit(1).get()
        exists = len(list(docs)) > 0
        
        return jsonify({"exists": exists})
    except Exception as e:
        logger.error(f"Error checking email: {e}")
        return jsonify({"error": "Internal server error"}), 500

# ----- Verify password -----
@app.route('/verify_password', methods=['POST'])
def verify_password_endpoint():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        uid = data.get("uid", "").strip()
        password = data.get("password", "")
        
        if not uid or not password:
            return jsonify({"error": "UID และรหัสผ่านจำเป็นต้องระบุ"}), 400

        # Get user email from Firestore
        email = get_user_email_by_uid(uid)
        if not email:
            return jsonify({"error": "ไม่พบข้อมูลผู้ใช้"}), 404

        # Verify password
        is_valid = verify_password(email, password)
        if is_valid:
            return jsonify({"valid": True, "message": "รหัสผ่านถูกต้อง"})
        else:
            return jsonify({"valid": False, "message": "รหัสผ่านไม่ถูกต้อง"}), 401
            
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return jsonify({"error": "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์"}), 500

# ----- Update email -----
@app.route('/update_email', methods=['POST'])
def update_email():
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

        # Get current user data
        current_email = get_user_email_by_uid(uid)
        if not current_email:
            return jsonify({"error": "ไม่พบข้อมูลผู้ใช้"}), 404

        # Verify current password if provided
        if current_password:
            if not verify_password(current_email, current_password):
                return jsonify({"error": "รหัสผ่านเดิมไม่ถูกต้อง"}), 401

        # Check if new email already exists
        try:
            existing_user = auth.get_user_by_email(new_email)
            if existing_user.uid != uid:
                return jsonify({"error": "อีเมลนี้ถูกใช้งานแล้วโดยผู้ใช้อื่น"}), 400
        except auth.UserNotFoundError:
            # Email doesn't exist, which is good
            pass

        # Update email in Firebase Auth and Firestore
        auth.update_user(uid, email=new_email, email_verified=False)
        
        user_ref = db.collection("users").document(uid)
        user_ref.update({"email": new_email})
        
        logger.info(f"Email updated successfully for user {uid}: {current_email} -> {new_email}")
        
        return jsonify({
            "message": "อีเมลอัปเดตเรียบร้อยแล้ว", 
            "new_email": new_email
        })
        
    except Exception as e:
        logger.error(f"Error updating email: {e}")
        return jsonify({"error": "เกิดข้อผิดพลาดในการอัปเดตอีเมล"}), 500

# ----- Update password -----
@app.route('/update_password', methods=['POST'])
def update_password():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        uid = data.get("uid", "").strip()
        new_password = data.get("new_password", "")
        current_password = data.get("current_password", "")

        if not uid or not new_password or not current_password:
            return jsonify({"error": "UID, รหัสผ่านเดิม และรหัสผ่านใหม่จำเป็นต้องระบุ"}), 400

        # Get user email
        email = get_user_email_by_uid(uid)
        if not email:
            return jsonify({"error": "ไม่พบข้อมูลผู้ใช้"}), 404

        # Verify current password
        if not verify_password(email, current_password):
            return jsonify({"error": "รหัสผ่านเดิมไม่ถูกต้อง"}), 401

        # Validate new password strength
        password_errors = validate_password_strength(new_password)
        if password_errors:
            return jsonify({"error": "; ".join(password_errors)}), 400

        # Update password in Firebase Auth
        auth.update_user(uid, password=new_password)
        
        # Create new custom token for re-authentication
        new_id_token = auth.create_custom_token(uid)
        token_string = new_id_token.decode("utf-8") if isinstance(new_id_token, bytes) else str(new_id_token)
        
        logger.info(f"Password updated successfully for user {uid}")
        
        return jsonify({
            "message": "รหัสผ่านอัปเดตเรียบร้อยแล้ว",
            "id_token": token_string
        })
        
    except Exception as e:
        logger.error(f"Error updating password: {e}")
        return jsonify({"error": "เกิดข้อผิดพลาดในการอัปเดตรหัสผ่าน"}), 500

# ----- Find email by username -----
@app.route('/find_email_by_username', methods=['POST'])
def find_email_by_username():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        username = data.get("username", "").strip()
        if not username:
            return jsonify({"error": "Username is required"}), 400

        users_ref = db.collection("users")
        docs = list(users_ref.where("username", "==", username).limit(1).get())
        
        if not docs:
            return jsonify({"error": "ไม่พบผู้ใช้"}), 404
            
        email = docs[0].to_dict().get("email")
        if not email:
            return jsonify({"error": "ไม่พบอีเมลของผู้ใช้"}), 404
            
        return jsonify({"email": email})
        
    except Exception as e:
        logger.error(f"Error finding email by username: {e}")
        return jsonify({"error": "Internal server error"}), 500

# ----- Delete user -----
@app.route('/delete_user', methods=['DELETE'])
def delete_user():
    try:
        data = request.get_json() or {}
        uid = data.get("uid", "").strip()
        
        if not uid:
            return jsonify({"error": "UID is required"}), 400

        # Verify current password if provided (for security)
        current_password = data.get("current_password")
        if current_password:
            email = get_user_email_by_uid(uid)
            if email and not verify_password(email, current_password):
                return jsonify({"error": "รหัสผ่านไม่ถูกต้อง"}), 401

        # Delete user data from Firestore first
        user_ref = db.collection("users").document(uid)
        if user_ref.get().exists:
            user_ref.delete()
            logger.info(f"User document deleted from Firestore: {uid}")

        # Delete related collections (optional - implement based on your data structure)
        # Delete AnalysisHistory
        try:
            analysis_docs = db.collection("AnalysisHistory").where("userId", "==", uid).get()
            for doc in analysis_docs:
                doc.reference.delete()
            logger.info(f"Deleted {len(list(analysis_docs))} AnalysisHistory documents for user {uid}")
        except Exception as e:
            logger.warning(f"Error deleting AnalysisHistory for user {uid}: {e}")

        # Delete ReportDataUser
        try:
            report_docs = db.collection("ReportDataUser").where("UserID", "==", uid).get()
            for doc in report_docs:
                doc.reference.delete()
            logger.info(f"Deleted {len(list(report_docs))} ReportDataUser documents for user {uid}")
        except Exception as e:
            logger.warning(f"Error deleting ReportDataUser for user {uid}: {e}")

        # Delete user from Firebase Auth
        try:
            auth.delete_user(uid)
            logger.info(f"User deleted from Firebase Auth: {uid}")
        except auth.UserNotFoundError:
            logger.warning(f"User {uid} not found in Firebase Auth, but continuing deletion")
        except Exception as e:
            logger.error(f"Error deleting user from Auth: {e}")
            # Continue even if auth deletion fails

        return jsonify({"message": f"ผู้ใช้ {uid} ถูกลบเรียบร้อยแล้ว"})
        
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return jsonify({"error": "เกิดข้อผิดพลาดในการลบผู้ใช้"}), 500

# ----- Test Firebase connection -----
@app.route('/test_firebase', methods=['GET'])
def test_firebase():
    try:
        # Test Firestore
        users_count = len(list(db.collection("users").limit(1).stream()))
        
        # Test Firebase Auth
        auth_users = auth.list_users(max_results=1)
        auth_count = len(auth_users.users)
        
        return jsonify({
            "firestore_connection": "success",
            "auth_connection": "success",
            "sample_user_count": users_count,
            "sample_auth_count": auth_count,
            "firebase_app_count": len(firebase_admin._apps)
        })
    except Exception as e:
        logger.error(f"Firebase test failed: {e}")
        return jsonify({
            "firestore_connection": "failed",
            "auth_connection": "failed", 
            "error": str(e)
        }), 500

# ================== Error Handlers ==================
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({"error": "Internal server error"}), 500

# ================== Run Flask ==================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    logger.info(f"Starting Flask app on port {port}, debug={debug}")
    app.run(host='0.0.0.0', port=port, debug=debug)