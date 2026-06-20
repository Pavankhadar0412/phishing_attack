"""
Flask Application for Phishing Website Detection System
Main application with routes, database, and API endpoints
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import joblib
import os
import datetime
import json
import re
import requests
from functools import wraps
import pandas as pd
from io import BytesIO
from feature_extraction import extract_url_features
from train_model import PhishingModelTrainer
import secrets

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Rate limiting storage
rate_limits = {}

# Database Models
class User(UserMixin, db.Model):
    """User model for authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    scans = db.relationship('ScanHistory', backref='user', lazy=True)

class ScanHistory(db.Model):
    """Model to store scan history"""
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    is_phishing = db.Column(db.Boolean, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    probability_phishing = db.Column(db.Float, nullable=False)
    probability_legitimate = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    virustotal_score = db.Column(db.Integer, nullable=True)
    features = db.Column(db.Text, nullable=True)

# Load ML Model
model_trainer = PhishingModelTrainer()
model_data = None

def load_ml_model():
    """Load the trained ML model"""
    global model_data
    try:
        if os.path.exists('phishing_model.pkl'):
            model_data = joblib.load('phishing_model.pkl')
            model_trainer.model = model_data['model']
            model_trainer.scaler = model_data['scaler']
            model_trainer.feature_names = model_data['feature_names']
            model_trainer.best_model_name = model_data['best_model_name']
            model_trainer.best_accuracy = model_data['best_accuracy']
            print("ML Model loaded successfully")
            return True
        else:
            print("Model file not found. Please train the model first.")
            return False
    except Exception as e:
        print(f"Error loading model: {e}")
        return False

# Rate limiting decorator
def rate_limit(max_requests=10, window=60):
    """
    Rate limiting decorator to prevent abuse.
    
    Args:
        max_requests (int): Maximum number of requests allowed
        window (int): Time window in seconds
    """
    def decorator(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            # Get client IP
            client_ip = request.remote_addr
            
            # Get current time
            now = datetime.datetime.now()
            
            # Initialize or get existing rate limit data
            if client_ip not in rate_limits:
                rate_limits[client_ip] = {'count': 0, 'window_start': now}
            
            # Reset if window has passed
            if (now - rate_limits[client_ip]['window_start']).total_seconds() > window:
                rate_limits[client_ip] = {'count': 0, 'window_start': now}
            
            # Check if limit exceeded
            if rate_limits[client_ip]['count'] >= max_requests:
                return jsonify({
                    'error': 'Rate limit exceeded. Please try again later.',
                    'status': 'error'
                }), 429
            
            # Increment counter
            rate_limits[client_ip]['count'] += 1
            
            return f(*args, **kwargs)
        return wrapped_function
    return decorator

# Input validation
def validate_url(url):
    """
    Validate the URL format.
    
    Args:
        url (str): URL to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not url:
        return False, "URL cannot be empty"
    
    if len(url) > 2000:
        return False, "URL is too long (max 2000 characters)"
    
    # Basic URL pattern validation
    url_pattern = re.compile(
        r'^(http|https)://'  # http or https
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(url):
        return False, "Invalid URL format"
    
    return True, None

# VirusTotal API integration
def check_virustotal(url, api_key=None):
    """
    Check URL against VirusTotal database.
    
    Args:
        url (str): URL to check
        api_key (str): VirusTotal API key (optional)
        
    Returns:
        dict: VirusTotal scan results
    """
    if not api_key:
        return {'score': None, 'error': 'No API key provided'}
    
    try:
        # First, submit the URL for analysis
        submit_url = "https://www.virustotal.com/api/v3/urls"
        headers = {
            "x-apikey": api_key,
            "accept": "application/json"
        }
        data = {"url": url}
        
        response = requests.post(submit_url, headers=headers, data=data, timeout=10)
        
        if response.status_code == 200:
            analysis_id = response.json().get('data', {}).get('id')
            
            # Get the analysis results
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers, timeout=10)
            
            if analysis_response.status_code == 200:
                result = analysis_response.json()
                stats = result.get('data', {}).get('attributes', {}).get('stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                
                score = int((malicious / total) * 100) if total > 0 else 0
                
                return {
                    'score': score,
                    'malicious': malicious,
                    'total': total,
                    'stats': stats
                }
        
        return {'score': None, 'error': 'VirusTotal check failed'}
    
    except Exception as e:
        return {'score': None, 'error': str(e)}

# Login manager user loader
@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    """Home page route - redirect to login if not authenticated"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/about')
def about():
    """About page route"""
    return render_template('about.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page with statistics"""
    # Get statistics
    total_scans = ScanHistory.query.count()
    phishing_count = ScanHistory.query.filter_by(is_phishing=True).count()
    safe_count = ScanHistory.query.filter_by(is_phishing=False).count()
    
    # Get recent scans
    recent_scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(10).all()
    
    # Calculate statistics for charts
    stats = {
        'total_scans': total_scans,
        'phishing_count': phishing_count,
        'safe_count': safe_count,
        'phishing_percentage': round((phishing_count / total_scans * 100) if total_scans > 0 else 0, 2),
        'safe_percentage': round((safe_count / total_scans * 100) if total_scans > 0 else 0, 2)
    }
    
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans)

@app.route('/history')
@login_required
def history():
    """Scan history page"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '')
    
    query = ScanHistory.query
    
    if search:
        query = query.filter(ScanHistory.url.contains(search))
    
    scans = query.order_by(ScanHistory.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('history.html', scans=scans, search=search)

@app.route('/predict', methods=['POST'])
@rate_limit(max_requests=30, window=60)
def predict():
    """
    Predict if a URL is phishing or legitimate.
    API endpoint for prediction.
    """
    try:
        # Get URL from request
        data = request.get_json()
        url = data.get('url', '').strip()
        
        # Validate URL
        is_valid, error_msg = validate_url(url)
        if not is_valid:
            return jsonify({
                'error': error_msg,
                'status': 'error'
            }), 400
        
        # Check if model is loaded
        if model_trainer.model is None:
            return jsonify({
                'error': 'Model not loaded. Please train the model first.',
                'status': 'error'
            }), 500
        
        # Make prediction
        result = model_trainer.predict_url(url)
        
        if result is None:
            return jsonify({
                'error': 'Prediction failed',
                'status': 'error'
            }), 500
        
        # Check VirusTotal if API key is provided
        vt_api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        virustotal_result = None
        if vt_api_key:
            virustotal_result = check_virustotal(url, vt_api_key)
        
        # Store in database if user is logged in
        if current_user.is_authenticated:
            scan = ScanHistory(
                url=url,
                is_phishing=result['is_phishing'],
                confidence=result['confidence'],
                risk_level=result['risk_level'],
                probability_phishing=result['probability_phishing'],
                probability_legitimate=result['probability_legitimate'],
                user_id=current_user.id,
                virustotal_score=virustotal_result['score'] if virustotal_result else None,
                features=json.dumps(extract_url_features(url))
            )
            db.session.add(scan)
            db.session.commit()
        
        # Prepare response
        response = {
            'url': url,
            'is_phishing': result['is_phishing'],
            'confidence': round(result['confidence'], 2),
            'risk_level': result['risk_level'],
            'probability_phishing': round(result['probability_phishing'], 2),
            'probability_legitimate': round(result['probability_legitimate'], 2),
            'status': 'success'
        }
        
        if virustotal_result:
            response['virustotal'] = virustotal_result
        
        return jsonify(response)
    
    except Exception as e:
        return jsonify({
            'error': f'Prediction error: {str(e)}',
            'status': 'error'
        }), 500

@app.route('/api/predict', methods=['POST'])
@rate_limit(max_requests=50, window=60)
def api_predict():
    """
    REST API endpoint for external use.
    Returns JSON response with prediction results.
    """
    return predict()

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """
    API endpoint to get overall statistics.
    """
    total_scans = ScanHistory.query.count()
    phishing_count = ScanHistory.query.filter_by(is_phishing=True).count()
    safe_count = ScanHistory.query.filter_by(is_phishing=False).count()
    
    return jsonify({
        'total_scans': total_scans,
        'phishing_count': phishing_count,
        'safe_count': safe_count,
        'status': 'success'
    })

@app.route('/export/csv')
@login_required
def export_csv():
    """
    Export scan history to CSV file.
    """
    try:
        scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).all()
        
        # Create DataFrame
        data = []
        for scan in scans:
            data.append({
                'URL': scan.url,
                'Is Phishing': 'Yes' if scan.is_phishing else 'No',
                'Confidence': scan.confidence,
                'Risk Level': scan.risk_level,
                'Probability Phishing': scan.probability_phishing,
                'Probability Legitimate': scan.probability_legitimate,
                'Timestamp': scan.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'VirusTotal Score': scan.virustotal_score
            })
        
        df = pd.DataFrame(data)
        
        # Create CSV in memory
        output = BytesIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'scan_history_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')
        
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error='Email already exists')
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        
        db.session.add(user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """User logout route"""
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    """Admin dashboard route"""
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    total_scans = ScanHistory.query.count()
    
    return render_template('admin.html', users=users, total_scans=total_scans)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('index.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    return render_template('index.html', error='Internal server error'), 500

# Initialize database
def init_db():
    """Initialize the database with tables and default admin user"""
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@phishingdetector.com',
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created: username=admin, password=admin123")

# Main execution
if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Load ML model
    load_ml_model()
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
