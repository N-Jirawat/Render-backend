from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, auth, firestore
from flask_cors import CORS
import os
import json
import re
import requests

app = Flask(__name__)

# ================== CORS ==================
# รองรับทุก route, ทุก preflight OPTIONS
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
        print("Firebase Admin SDK initialized successfully")
    except Exception as e:
        print(f"Error initializing Firebase: {e}")

db = firestore.client()

# ================== Helper: Verify Password ==================
def verify_password(email, password):
    try:
        api_key = os.environ.get("FIREBASE_WEB_API_KEY")
        if not api_key:
            return False

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        response = requests.post(url, json=payload, timeout=10)

        if response.status_code == 200:
            return True
        else:
            error_data = response.json()
            error_message = error_data.get("error", {}).get("message", "Unknown error")
            print(f"Password verification failed: {error_message}")
            return False
    except Exception as e:
        print(f"Password verification error: {str(e)}")
        return False

# ================== Routes ==================
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

# ----- Check username -----
@app.route('/check_username', methods=['POST'])
def check_username():
    data = request.get_json()
    username = data.get("username")
    if not username:
        return jsonify({"error": "Missing username"}), 400

    users_ref = db.collection("users")
    docs = users_ref.where("username", "==", username).limit(1).get()
    return jsonify({"exists": bool(docs)})

# ----- Check email -----
@app.route('/check_email', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data.get("email")
    if not email:
        return jsonify({"error": "Missing email"}), 400

    users_ref = db.collection("users")
    docs = users_ref.where("email", "==", email).limit(1).get()
    return jsonify({"exists": bool(docs)})

# ----- Verify password -----
@app.route('/verify_password', methods=['POST'])
def verify_password_endpoint():
    data = request.get_json()
    uid = data.get("uid")
    password = data.get("password")
    if not uid or not password:
        return jsonify({"error": "Missing uid or password"}), 400

    user_ref = db.collection("users").document(uid)
    user_doc = user_ref.get()
    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404
    email = user_doc.to_dict().get("email")
    if not email:
        return jsonify({"error": "User email not found"}), 404

    is_valid = verify_password(email, password)
    if is_valid:
        return jsonify({"valid": True, "message": "Password is correct"})
    return jsonify({"valid": False, "message": "Invalid password"}), 401

# ----- Update email -----
@app.route('/update_email', methods=['POST'])
def update_email():
    data = request.get_json()
    uid = data.get("uid")
    new_email = data.get("new_email")
    current_password = data.get("current_password")

    if not uid or not new_email:
        return jsonify({"error": "Missing uid or new_email"}), 400

    user_ref = db.collection("users").document(uid)
    user_doc = user_ref.get()
    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404
    current_email = user_doc.to_dict().get("email")

    if current_password:
        if not verify_password(current_email, current_password):
            return jsonify({"error": "Current password is incorrect"}), 401

    try:
        existing_user = auth.get_user_by_email(new_email)
        if existing_user.uid != uid:
            return jsonify({"error": "Email already exists for another user"}), 400
    except auth.UserNotFoundError:
        pass

    auth.update_user(uid, email=new_email, email_verified=False)
    user_ref.update({"email": new_email})
    return jsonify({"message": "Email updated successfully", "new_email": new_email})

# ----- Update password -----
@app.route('/update_password', methods=['POST'])
def update_password():
    data = request.get_json()
    uid = data.get("uid")
    new_password = data.get("new_password")
    current_password = data.get("current_password")

    if not uid or not new_password:
        return jsonify({"error": "Missing uid or new_password"}), 400
    if not current_password:
        return jsonify({"error": "Current password is required"}), 400

    user_ref = db.collection("users").document(uid)
    user_doc = user_ref.get()
    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404
    email = user_doc.to_dict().get("email")

    if not verify_password(email, current_password):
        return jsonify({"error": "Current password is incorrect"}), 401

    # Password strength check
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if not re.search(r'[a-zA-Z]', new_password):
        return jsonify({"error": "Password must contain at least one letter"}), 400
    if not re.search(r'[0-9]', new_password):
        return jsonify({"error": "Password must contain at least one number"}), 400

    auth.update_user(uid, password=new_password)
    new_id_token = auth.create_custom_token(uid)
    return jsonify({
        "message": "Password updated successfully",
        "id_token": new_id_token.decode("utf-8") if isinstance(new_id_token, bytes) else str(new_id_token)
    })

# ----- Find email by username -----
@app.route('/find_email_by_username', methods=['POST'])
def find_email_by_username():
    data = request.get_json()
    username = data.get("username")
    if not username:
        return jsonify({"error": "Missing username"}), 400

    users_ref = db.collection("users")
    docs = users_ref.where("username", "==", username).limit(1).get()
    if not docs:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"email": docs[0].to_dict().get("email")})

# ----- Delete user -----
@app.route('/delete_user', methods=['DELETE'])
def delete_user():
    data = request.get_json()
    uid = data.get("uid") if data else None
    current_password = data.get("current_password") if data else None
    if not uid:
        return jsonify({"error": "Missing uid parameter"}), 400

    if current_password:
        user_ref = db.collection("users").document(uid)
        user_doc = user_ref.get()
        if user_doc.exists:
            email = user_doc.to_dict().get("email")
            if email and not verify_password(email, current_password):
                return jsonify({"error": "Current password is incorrect"}), 401

    user_ref = db.collection("users").document(uid)
    if user_ref.get().exists:
        user_ref.delete()
    auth.delete_user(uid)
    return jsonify({"message": f"User {uid} deleted successfully"})

# ----- Test Firebase connection -----
@app.route('/test_firebase', methods=['GET'])
def test_firebase():
    users_count = sum(1 for _ in db.collection("users").limit(1).stream())
    auth_count = len(auth.list_users(max_results=1).users)
    return jsonify({
        "firestore_connection": "success",
        "auth_connection": "success",
        "sample_user_count": users_count,
        "sample_auth_count": auth_count
    })

# ================== Run Flask ==================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
