from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random
import redis
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config
from model import db, User, Excuse, Quest, Session, Rating
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from sqlalchemy import func
import jwt

app = Flask(__name__)
CORS(app)
app.config["JWT_SECRET_KEY"] = "super-secret-key"
jwt = JWTManager(app)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = User.query.get(data["user_id"])
        except:
            return jsonify({"message": "Token is invalid or expired"}), 401

        return f(current_user, *args, **kwargs)

    return decorated

app.config.from_object(Config)
db.init_app(app)
limiter = Limiter(get_remote_address, app=app)


@app.route("/signup", methods=["POST"])
def signup():
    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists!"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully!"}), 201

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = create_access_token(identity=user.id)  
    return jsonify({"access_token": access_token}), 200


@app.route("/api/leaderboard", methods=["GET"])
@token_required
def leaderboard():
    

    
    results = db.session.query(
        User.username,
        func.count(Rating.id).label("total_ratings")
    ).join(Excuse, Excuse.user_id == User.id
    ).join(Rating, Rating.excuse_id == Excuse.id
    ).group_by(User.id
    ).order_by(func.count(Rating.id).desc()
    ).limit(5).all()

    leaderboard = [{"username": username, "total_ratings": total} for username, total in results]

    return jsonify({"leaderboard": leaderboard}), 200

@app.route("/profile", methods=["GET"])
@token_required
@jwt_required()
def profile():
    user_id = get_jwt_identity()  
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({"username": user.username}), 200

@app.route("/api/excuse", methods=["GET"])
@jwt_required()
def get_excuse():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user or not user.excuses:
        return jsonify({"message": "No excuses found!"}), 404

    excuse = random.choice(user.excuses)
    return jsonify({"excuse": excuse.text}), 200

@app.route("/api/excuse", methods=["POST"])
@jwt_required()
def add_excuse():
    user_id = get_jwt_identity()
    data = request.get_json()
    excuse_text = data.get("excuse")

    if not excuse_text:
        return jsonify({"message": "Excuse text required"}), 400

    new_excuse = Excuse(text=excuse_text, user_id=user_id)
    db.session.add(new_excuse)
    db.session.commit()

    return jsonify({"message": "Excuse added!"}), 201

@app.route("/api/excuse/<int:excuse_id>", methods=["DELETE"])
@jwt_required()
def delete_excuse(excuse_id):
    user_id = get_jwt_identity()
    excuse = Excuse.query.filter_by(id=excuse_id, user_id=user_id).first()

    if not excuse:
        return jsonify({"message": "Excuse not found or unauthorized"}), 404

    db.session.delete(excuse)
    db.session.commit()
    return jsonify({"message": "Excuse deleted successfully"}), 200

@app.route("/api/excuse/<int:excuse_id>", methods=["PUT"])
@jwt_required()
def edit_excuse(excuse_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    new_text = data.get("excuse")

    if not new_text:
        return jsonify({"message": "New excuse text required"}), 400

    excuse = Excuse.query.filter_by(id=excuse_id, user_id=user_id).first()

    if not excuse:
        return jsonify({"message": "Excuse not found or unauthorized"}), 404

    excuse.text = new_text
    db.session.commit()
    return jsonify({"message": "Excuse updated successfully"}), 200

@app.route("/api/my-excuses", methods=["GET"])
@jwt_required()
def get_my_excuses():
    user_id = get_jwt_identity()
    excuses = Excuse.query.filter_by(user_id=user_id).all()

    if not excuses:
        return jsonify({"message": "You haven't submitted any excuses yet!"}), 404

    return jsonify({"my_excuses": [e.text for e in excuses]}), 200

@app.route("/api/excuse/<int:excuse_id>/rate", methods=["POST"])
@jwt_required()  
def rate_excuse(excuse_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    score = data.get("score")

    if score is None or not (1 <= score <= 5):
        return jsonify({"message": "Score must be between 1 and 5"}), 400

    existing_rating = Rating.query.filter_by(user_id=user_id, excuse_id=excuse_id).first()
    if existing_rating:
        existing_rating.score = score
    else:
        new_rating = Rating(user_id=user_id, excuse_id=excuse_id, score=score)
        db.session.add(new_rating)

    db.session.commit()
    return jsonify({"message": "Rating added!"}), 200

@app.route("/api/quest", methods=["GET"])
@jwt_required()
def get_quest():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    quests = Quest.query.all()
    if not quests:
        return jsonify({"message": "No quests available!"}), 404

    quest = random.choice(quests)
    return jsonify({"quest": quest.text}), 200

@app.route("/api/session", methods=["POST"])
@jwt_required()
def log_session():
    user_id = get_jwt_identity()
    data = request.get_json()
    duration = data.get("duration")

    if not duration:
        return jsonify({"message": "Duration required"}), 400

    session = Session(user_id=user_id, duration=duration)
    db.session.add(session)
    db.session.commit()

    return jsonify({"message": "Session logged successfully"}), 201

@app.route("/api/session/history", methods=["GET"])
@jwt_required()
def get_session_history():
    user_id = get_jwt_identity()
    sessions = Session.query.filter_by(user_id=user_id).order_by(Session.timestamp.desc()).all()

    return jsonify({
        "history": [{"duration": s.duration, "timestamp": s.timestamp.isoformat()} for s in sessions]
    }), 200

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
