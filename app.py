from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, auth, firestore
from flask_cors import CORS
import os
import json

app = Flask(__name__)

# CORS config - อนุญาตเฉพาะ frontend ของคุณ
CORS(app, resources={r"/*": {"origins": ["https://mangoleafanalyzer.onrender.com", "http://localhost:3000"]}})

# Initialize Firebase Admin SDK
if not firebase_admin._apps:
    try:
        if os.environ.get("FIREBASE_CREDENTIALS"):
            # สำหรับ Production (Render)
            cred_dict = json.loads(os.environ["FIREBASE_CREDENTIALS"])
            cred = credentials.Certificate(cred_dict)
        else:
            # สำหรับ Local Development
            cred = credentials.Certificate("serviceAccountKey.json")
        
        firebase_admin.initialize_app(cred)
        print("Firebase Admin SDK initialized successfully")
    except Exception as e:
        print(f"Error initializing Firebase: {e}")

db = firestore.client()

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "message": "Mango User Management API",
        "status": "running",
        "version": "1.0.0"
    })

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "user_management",
        "firebase_initialized": len(firebase_admin._apps) > 0
    })

@app.route('/delete_user', methods=['DELETE'])
def delete_user():
    try:
        # รับข้อมูลจาก request
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        uid = data.get("uid")
        if not uid:
            return jsonify({"error": "Missing uid parameter"}), 400

        print(f"Attempting to delete user: {uid}")

        # 1. ลบข้อมูลจาก Firestore
        try:
            user_ref = db.collection("users").document(uid)
            user_doc = user_ref.get()
            
            if user_doc.exists:
                user_ref.delete()
                print(f"Deleted Firestore document for user: {uid}")
            else:
                print(f"Firestore document not found for user: {uid}")
                
        except Exception as firestore_error:
            print(f"Firestore deletion error: {firestore_error}")
            return jsonify({"error": f"Failed to delete from Firestore: {str(firestore_error)}"}), 500

        # 2. ลบจาก Firebase Authentication
        try:
            auth.delete_user(uid)
            print(f"Deleted Firebase Auth user: {uid}")
        except Exception as auth_error:
            print(f"Firebase Auth deletion error: {auth_error}")
            return jsonify({"error": f"Failed to delete from Firebase Auth: {str(auth_error)}"}), 500

        return jsonify({
            "message": f"User {uid} deleted successfully",
            "deleted_from": ["firestore", "firebase_auth"]
        }), 200

    except Exception as e:
        print(f"Unexpected error in delete_user: {str(e)}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route('/test_firebase', methods=['GET'])
def test_firebase():
    """ทดสอบการเชื่อมต่อ Firebase"""
    try:
        # ทดสอบ Firestore
        users_ref = db.collection("users")
        docs = users_ref.limit(1).stream()
        user_count = sum(1 for _ in docs)
        
        # ทดสอบ Auth
        page = auth.list_users(max_results=1)
        auth_count = len(page.users)
        
        return jsonify({
            "firestore_connection": "success",
            "auth_connection": "success",
            "sample_user_count": user_count,
            "sample_auth_count": auth_count
        })
    except Exception as e:
        return jsonify({
            "error": f"Firebase connection failed: {str(e)}"
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)