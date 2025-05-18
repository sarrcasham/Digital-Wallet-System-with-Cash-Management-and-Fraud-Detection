import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flasgger import Swagger
from groq import Groq

# --- App Initialization ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wallet.db'
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this in production!
app.config['SWAGGER'] = {'title': 'Digital Wallet API', 'uiversion': 3}
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
swagger = Swagger(app)

# --- Groq LLM Client ---
groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    is_admin = db.Column(db.Boolean, default=False)
    deleted = db.Column(db.Boolean, default=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    type = db.Column(db.String(20))  # deposit, withdraw, transfer
    amount = db.Column(db.Float)
    target_user = db.Column(db.String(80), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    flagged = db.Column(db.Boolean, default=False)
    deleted = db.Column(db.Boolean, default=False)

# --- Helper Functions ---
def detect_fraud(user_id, type, amount, recent_transactions):
    """Basic fraud detection using LLM via Groq API"""
    # Prepare prompt for LLM
    prompt = (
        f"Analyze the following transactions for user {user_id}: {recent_transactions}. "
        f"Current transaction: type={type}, amount={amount}. "
        "Flag if there are multiple transfers in a short period or a sudden large withdrawal."
    )
    response = groq_client.chat.completions.create(
        messages=[
            {"role": "system", "content": "You are a fraud detection expert."},
            {"role": "user", "content": prompt}
        ],
        model="llama3-8b-8192"
    )
    output = response.choices[0].message.content.lower()
    return "flag" in output or "suspicious" in output

def get_recent_transactions(user_id, minutes=10):
    since = datetime.utcnow() - timedelta(minutes=minutes)
    txs = Transaction.query.filter_by(user_id=user_id).filter(Transaction.timestamp > since).all()
    return [{"type": t.type, "amount": t.amount, "timestamp": t.timestamp.isoformat()} for t in txs]

# --- API Endpoints ---

@app.route('/register', methods=['POST'])
def register():
    """User registration"""
    data = request.json
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"msg": "Username already exists"}), 400
    hashed = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], password=hashed)
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "User registered successfully"})

@app.route('/login', methods=['POST'])
def login():
    """User login and JWT token issuance"""
    data = request.json
    user = User.query.filter_by(username=data['username'], deleted=False).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)
    return jsonify({"msg": "Invalid credentials"}), 401

@app.route('/wallet/deposit', methods=['POST'])
@jwt_required()
def deposit():
    """Deposit virtual cash"""
    user = User.query.get(get_jwt_identity())
    if user.deleted:
        return jsonify({"msg": "Account deleted"}), 403
    amount = float(request.json.get('amount', 0))
    if amount <= 0:
        return jsonify({"msg": "Invalid deposit amount"}), 400
    user.balance += amount
    tx = Transaction(user_id=user.id, type='deposit', amount=amount)
    db.session.add(tx)
    db.session.commit()
    return jsonify({"msg": "Deposit successful", "balance": user.balance})

@app.route('/wallet/withdraw', methods=['POST'])
@jwt_required()
def withdraw():
    """Withdraw virtual cash"""
    user = User.query.get(get_jwt_identity())
    if user.deleted:
        return jsonify({"msg": "Account deleted"}), 403
    amount = float(request.json.get('amount', 0))
    if amount <= 0 or amount > user.balance:
        return jsonify({"msg": "Invalid or insufficient funds"}), 400
    # Fraud detection: Sudden large withdrawal
    recent = get_recent_transactions(user.id)
    flagged = detect_fraud(user.id, 'withdraw', amount, recent)
    user.balance -= amount
    tx = Transaction(user_id=user.id, type='withdraw', amount=amount, flagged=flagged)
    db.session.add(tx)
    db.session.commit()
    return jsonify({"msg": "Withdrawal successful", "flagged": flagged, "balance": user.balance})

@app.route('/wallet/transfer', methods=['POST'])
@jwt_required()
def transfer():
    """Transfer funds to another user"""
    user = User.query.get(get_jwt_identity())
    if user.deleted:
        return jsonify({"msg": "Account deleted"}), 403
    data = request.json
    target = User.query.filter_by(username=data['to'], deleted=False).first()
    amount = float(data.get('amount', 0))
    if not target or target.id == user.id:
        return jsonify({"msg": "Invalid target user"}), 400
    if amount <= 0 or amount > user.balance:
        return jsonify({"msg": "Invalid or insufficient funds"}), 400
    # Fraud detection: Multiple transfers in short period
    recent = get_recent_transactions(user.id)
    flagged = detect_fraud(user.id, 'transfer', amount, recent)
    user.balance -= amount
    target.balance += amount
    tx = Transaction(user_id=user.id, type='transfer', amount=amount, target_user=target.username, flagged=flagged)
    db.session.add(tx)
    db.session.commit()
    return jsonify({"msg": "Transfer successful", "flagged": flagged, "balance": user.balance})

@app.route('/wallet/history', methods=['GET'])
@jwt_required()
def history():
    """Transaction history per user"""
    user = User.query.get(get_jwt_identity())
    txs = Transaction.query.filter_by(user_id=user.id, deleted=False).order_by(Transaction.timestamp.desc()).all()
    return jsonify([{
        "id": t.id, "type": t.type, "amount": t.amount, "target_user": t.target_user,
        "timestamp": t.timestamp.isoformat(), "flagged": t.flagged
    } for t in txs])

# --- Admin APIs ---
@app.route('/admin/flagged', methods=['GET'])
@jwt_required()
def flagged_transactions():
    """View flagged transactions (admin only)"""
    user = User.query.get(get_jwt_identity())
    if not user.is_admin:
        return jsonify({"msg": "Admin only"}), 403
    txs = Transaction.query.filter_by(flagged=True, deleted=False).all()
    return jsonify([{
        "id": t.id, "user_id": t.user_id, "type": t.type, "amount": t.amount,
        "timestamp": t.timestamp.isoformat(), "target_user": t.target_user
    } for t in txs])

@app.route('/admin/balances', methods=['GET'])
@jwt_required()
def total_balances():
    """Aggregate total user balances (admin only)"""
    user = User.query.get(get_jwt_identity())
    if not user.is_admin:
        return jsonify({"msg": "Admin only"}), 403
    total = db.session.query(db.func.sum(User.balance)).filter_by(deleted=False).scalar()
    return jsonify({"total_balance": total})

@app.route('/admin/top-users', methods=['GET'])
@jwt_required()
def top_users():
    """Top users by balance or transaction volume (admin only)"""
    user = User.query.get(get_jwt_identity())
    if not user.is_admin:
        return jsonify({"msg": "Admin only"}), 403
    by = request.args.get('by', 'balance')
    if by == 'balance':
        users = User.query.filter_by(deleted=False).order_by(User.balance.desc()).limit(5).all()
        return jsonify([{"username": u.username, "balance": u.balance} for u in users])
    elif by == 'volume':
        tx_counts = db.session.query(Transaction.user_id, db.func.count(Transaction.id).label('count'))\
            .filter_by(deleted=False).group_by(Transaction.user_id).order_by(db.desc('count')).limit(5).all()
        result = []
        for uid, count in tx_counts:
            uname = User.query.get(uid).username
            result.append({"username": uname, "transaction_count": count})
        return jsonify(result)
    else:
        return jsonify({"msg": "Invalid query"}), 400

# --- Soft Delete Endpoints (Bonus) ---
@app.route('/account/delete', methods=['POST'])
@jwt_required()
def soft_delete_account():
    user = User.query.get(get_jwt_identity())
    user.deleted = True
    db.session.commit()
    return jsonify({"msg": "Account soft-deleted"})

@app.route('/transaction/delete/<int:tx_id>', methods=['POST'])
@jwt_required()
def soft_delete_transaction(tx_id):
    tx = Transaction.query.get(tx_id)
    if tx and tx.user_id == get_jwt_identity():
        tx.deleted = True
        db.session.commit()
        return jsonify({"msg": "Transaction soft-deleted"})
    return jsonify({"msg": "Not found or unauthorized"}), 404

# --- Run App and Initialize DB ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default admin if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password=bcrypt.generate_password_hash('admin').decode('utf-8'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
