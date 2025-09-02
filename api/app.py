from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, auth, firestore
from flask_cors import CORS
import os
import json
import re
import requests

app = Flask(__name__)

# ✅ Configure CORS properly
CORS(app, 
     origins=["https://mangoleafanalyzer.onrender.com", "http://localhost:3000", "https://localhost:3000"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"],
     supports_credentials=True
)

# ✅ เปิด CORS ครอบคลุมทุกเส้นทาง และรองรับ OPTIONS preflight
def _build_cors_preflight_response():
    response = jsonify({"status": "preflight ok"})
    
    # รองรับหลาย origin
    origin = request.headers.get('Origin')
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
    return response

# Initialize Firebase Admin SDK
if not firebase_admin._apps:
    try:
        if os.environ.get("FIREBASE_CREDENTIALS"):
            cred_dict = json.loads(os.environ["FIREBASE_CREDENTIALS"])
            cred = credentials.Certificate(cred_dict)
        else:
            cred = credentials.Certificate("serviceAccountKey.json")
        firebase_admin.initialize_app(cred)
        print("Firebase Admin SDK initialized successfully")
    except Exception as e:
        print(f"Error initializing Firebase: {e}")

db = firestore.client()

# ✅ Additional CORS handler for all responses
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

# ================= Helper Function: Verify Password =================
def verify_password(email, password):
    """
    Verify user password by attempting to sign in with Firebase Auth REST API
    Returns True if password is correct, False otherwise
    """
    try:
        # Get Firebase Web API Key (you need to set this in environment variables)
        api_key = os.environ.get("FIREBASE_WEB_API_KEY")
        if not api_key:
            print("Warning: FIREBASE_WEB_API_KEY not set. Password verification will be skipped.")
            return True  # Skip verification if API key not available
        
        # Firebase Auth REST API endpoint
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        
        response = requests.post(url, json=payload, timeout=10)
        
        if response.status_code == 200:
            return True
        else:
            error_data = response.json()
            error_message = error_data.get("error", {}).get("message", "Unknown error")
            print(f"Password verification failed: {error_message}")
            return False
            
    except requests.exceptions.Timeout:
        print("Password verification timeout")
        return False
    except requests.exceptions.RequestException as e:
        print(f"Password verification request error: {str(e)}")
        return False
    except Exception as e:
        print(f"Password verification error: {str(e)}")
        return False

# ================= ตรวจสอบ username =================
@app.route('/check_username', methods=['POST'])
def check_username():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    try:
        data = request.get_json()
        username = data.get("username")
        if not username:
            return jsonify({"error": "Missing username"}), 400

        users_ref = db.collection("users")
        query = users_ref.where("username", "==", username).limit(1)
        docs = query.get()

        if docs:
            return jsonify({"exists": True})
        return jsonify({"exists": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ================= ตรวจสอบ email =================
@app.route('/check_email', methods=['POST'])
def check_email():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    try:
        data = request.get_json()
        email = data.get("email")
        if not email:
            return jsonify({"error": "Missing email"}), 400

        users_ref = db.collection("users")
        query = users_ref.where("email", "==", email).limit(1)
        docs = query.get()

        if docs:
            return jsonify({"exists": True})
        return jsonify({"exists": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ================= ตรวจสอบรหัสผ่าน =================
@app.route('/verify_password', methods=['POST', 'OPTIONS'])
def verify_password_endpoint():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    try:
        data = request.get_json()
        uid = data.get("uid")
        password = data.get("password")
        
        if not uid or not password:
            return jsonify({"error": "Missing uid or password"}), 400

        # Get user email from Firestore
        try:
            user_ref = db.collection("users").document(uid)
            user_doc = user_ref.get()
            if not user_doc.exists:
                return jsonify({"error": "User not found in database"}), 404
            
            user_data = user_doc.to_dict()
            email = user_data.get("email")
            if not email:
                return jsonify({"error": "User email not found"}), 404
                
        except Exception as e:
            return jsonify({"error": f"Failed to get user data: {str(e)}"}), 500

        # Verify password
        is_valid = verify_password(email, password)
        
        if is_valid:
            return jsonify({"valid": True, "message": "Password is correct"}), 200
        else:
            return jsonify({"valid": False, "message": "Invalid password"}), 401

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# ================= อัปเดตอีเมล =================
@app.route('/update_email', methods=['POST'])
def update_email():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    try:
        data = request.get_json()
        uid = data.get("uid")
        new_email = data.get("new_email")
        current_password = data.get("current_password")
        
        if not uid or not new_email:
            return jsonify({"error": "Missing uid or new_email"}), 400

        # Get current user data
        try:
            user_ref = db.collection("users").document(uid)
            user_doc = user_ref.get()
            if not user_doc.exists:
                return jsonify({"error": "User not found"}), 404
            
            user_data = user_doc.to_dict()
            current_email = user_data.get("email")
            
        except Exception as e:
            return jsonify({"error": f"Failed to get user data: {str(e)}"}), 500

        # Verify current password if provided
        if current_password:
            is_valid = verify_password(current_email, current_password)
            if not is_valid:
                return jsonify({"error": "Current password is incorrect"}), 401

        # ตรวจสอบว่าอีเมลใหม่ไม่ซ้ำกับคนอื่น
        try:
            existing_user = auth.get_user_by_email(new_email)
            if existing_user.uid != uid:
                return jsonify({"error": "Email already exists for another user"}), 400
        except auth.UserNotFoundError:
            pass

        # อัปเดตใน Firebase Authentication
        try:
            auth.update_user(
                uid,
                email=new_email,
                email_verified=False
            )
            print(f"Updated Firebase Auth email for user {uid}: {new_email}")
        except Exception as e:
            return jsonify({"error": f"Failed to update Firebase Auth email: {str(e)}"}), 500

        # อัปเดตใน Firestore
        try:
            user_ref.update({"email": new_email})
            print(f"Updated Firestore email for user {uid}: {new_email}")
        except Exception as e:
            return jsonify({"error": f"Failed to update Firestore email: {str(e)}"}), 500

        return jsonify({
            "message": "Email updated successfully",
            "updated_in": ["firebase_auth", "firestore"],
            "new_email": new_email
        }), 200

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# ================= อัปเดตรหัสผ่าน =================
@app.route('/update_password', methods=['POST'])
def update_password():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    try:
        data = request.get_json()
        uid = data.get("uid")
        new_password = data.get("new_password")
        current_password = data.get("current_password")

        if not uid or not new_password:
            return jsonify({"error": "Missing uid or new_password"}), 400

        if not current_password:
            return jsonify({"error": "Current password is required for verification"}), 400

        # Get user data from Firestore
        try:
            user_ref = db.collection("users").document(uid)
            user_doc = user_ref.get()
            if not user_doc.exists:
                return jsonify({"error": "User not found"}), 404
            
            user_data = user_doc.to_dict()
            email = user_data.get("email")
            
        except Exception as e:
            return jsonify({"error": f"Failed to get user data: {str(e)}"}), 500

        # Verify current password
        is_valid = verify_password(email, current_password)
        if not is_valid:
            return jsonify({"error": "Current password is incorrect"}), 401

        # ตรวจสอบความแข็งแรงของรหัสผ่าน
        if len(new_password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        
        if not re.search(r'[a-zA-Z]', new_password):
            return jsonify({"error": "Password must contain at least one letter"}), 400
            
        if not re.search(r'[0-9]', new_password):
            return jsonify({"error": "Password must contain at least one number"}), 400

        # อัปเดตใน Firebase Authentication
        try:
            user = auth.update_user(
                uid,
                password=new_password
            )
            print(f"Updated Firebase Auth password for user {uid}")
        except Exception as e:
            return jsonify({"error": f"Failed to update Firebase Auth password: {str(e)}"}), 500

        # สร้าง Custom Token ใหม่
        try:
            new_id_token = auth.create_custom_token(uid)
            return jsonify({
                "message": "Password updated successfully",
                "updated_in": ["firebase_auth"],
                "id_token": new_id_token.decode("utf-8") if isinstance(new_id_token, bytes) else str(new_id_token)
            }), 200
        except Exception as e:
            return jsonify({
                "message": "Password updated successfully but failed to generate new ID token",
                "updated_in": ["firebase_auth"],
                "error": str(e)
            }), 200

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500
    


# ================= Home =================
@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Mango User Management API", "status": "running", "version": "1.0.0"})


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "user_management",
        "firebase_initialized": len(firebase_admin._apps) > 0
    })


# ================= Login ด้วย username =================
@app.route('/find_email_by_username', methods=['POST'])
def find_email_by_username():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    try:
        data = request.get_json()
        username = data.get("username")
        if not username:
            return jsonify({"error": "Missing username"}), 400

        users_ref = db.collection("users")
        query = users_ref.where("username", "==", username).limit(1)
        docs = query.get()

        if not docs:
            return jsonify({"error": "User not found"}), 404

        user_doc = docs[0].to_dict()
        return jsonify({"email": user_doc.get("email")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ================= ลบผู้ใช้ =================
@app.route('/delete_user', methods=['DELETE'])
def delete_user():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    try:
        data = request.get_json()
        uid = data.get("uid") if data else None
        current_password = data.get("current_password") if data else None
        
        if not uid:
            return jsonify({"error": "Missing uid parameter"}), 400

        # Verify password before deletion
        if current_password:
            try:
                user_ref = db.collection("users").document(uid)
                user_doc = user_ref.get()
                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    email = user_data.get("email")
                    if email:
                        is_valid = verify_password(email, current_password)
                        if not is_valid:
                            return jsonify({"error": "Current password is incorrect"}), 401
            except Exception as e:
                return jsonify({"error": f"Password verification failed: {str(e)}"}), 500

        # ลบจาก Firestore
        try:
            user_ref = db.collection("users").document(uid)
            if user_ref.get().exists:
                user_ref.delete()
                print(f"Deleted Firestore document: {uid}")
        except Exception as e:
            return jsonify({"error": f"Failed to delete Firestore doc: {str(e)}"}), 500

        # ลบจาก Firebase Auth
        try:
            auth.delete_user(uid)
            print(f"Deleted Firebase Auth user: {uid}")
        except Exception as e:
            return jsonify({"error": f"Failed to delete Firebase Auth user: {str(e)}"}), 500

        return jsonify({"message": f"User {uid} deleted successfully",
                        "deleted_from": ["firestore", "firebase_auth"]}), 200

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# ================= ทดสอบการเชื่อมต่อ Firebase =================
@app.route('/test_firebase', methods=['GET'])
def test_firebase():
    try:
        users_count = sum(1 for _ in db.collection("users").limit(1).stream())
        auth_count = len(auth.list_users(max_results=1).users)
        return jsonify({
            "firestore_connection": "success",
            "auth_connection": "success",
            "sample_user_count": users_count,
            "sample_auth_count": auth_count
        })
    except Exception as e:
        return jsonify({"error": f"Firebase connection failed: {str(e)}"}), 500


# ================= Helper: Preflight response (ลบฟังก์ชันซ้ำ) =================


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)