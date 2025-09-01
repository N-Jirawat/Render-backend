from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, auth, firestore
from flask_cors import CORS
import os
import json

app = Flask(__name__)

# ✅ เปิด CORS ครอบคลุมทุกเส้นทาง และรองรับ OPTIONS preflight
CORS(app, resources={r"/*": {"origins": [
    "https://mangoleafanalyzer.onrender.com",
    "http://localhost:3000"
]}}, supports_credentials=True)

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


# ================= อัปเดตอีเมล =================
@app.route('/update_email', methods=['POST'])
def update_email():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    try:
        data = request.get_json()
        uid = data.get("uid")
        new_email = data.get("new_email")
        
        if not uid or not new_email:
            return jsonify({"error": "Missing uid or new_email"}), 400

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
            user_ref = db.collection("users").document(uid)
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
        if not uid:
            return jsonify({"error": "Missing uid parameter"}), 400

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


# ================= Helper: Preflight response =================
def _build_cors_preflight_response():
    response = jsonify({"status": "preflight ok"})
    response.headers.add("Access-Control-Allow-Origin", "https://mangoleafanalyzer.onrender.com")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
