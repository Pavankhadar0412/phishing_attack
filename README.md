# Phishing Website Detection System

An AI-powered full-stack web application for detecting phishing websites using machine learning algorithms. The system analyzes URLs in real-time and provides detailed risk assessments with confidence scores.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.0.0-green)
![Machine Learning](https://img.shields.io/badge/ML-Scikit--learn-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 🚀 Features

### Core Features
- **AI-Powered Detection**: Machine learning models (Random Forest, Decision Tree, XGBoost) trained on phishing datasets
- **Real-Time Analysis**: Instant URL scanning with comprehensive feature extraction
- **20+ Feature Extraction**: Analyzes URL length, domain characteristics, suspicious keywords, IP addresses, and more
- **Detailed Reports**: Confidence scores, risk levels, and probability breakdowns
- **Scan History**: Track all scans with search and export capabilities
- **Dashboard**: Interactive charts and statistics using Chart.js
- **User Authentication**: Secure login and registration system
- **Dark Mode**: Modern UI with dark/light theme toggle
- **Responsive Design**: Mobile-friendly interface using Bootstrap 5

### Security Features
- **VirusTotal Integration**: Optional API integration for enhanced detection
- **Rate Limiting**: Protection against API abuse
- **Input Validation**: Comprehensive URL validation
- **SQL Injection Protection**: SQLAlchemy ORM with parameterized queries
- **Password Hashing**: Secure password storage using Werkzeug

### Bonus Features
- **REST API Endpoint**: External API for programmatic access
- **CSV Export**: Download scan history for analysis
- **Admin Dashboard**: Administrative controls for user management
- **Real-time URL Reputation**: Enhanced threat assessment
- **Threat Level Meter**: Visual risk indicator

## 📋 Requirements

- Python 3.8 or higher
- pip (Python package manager)
- 2GB RAM minimum
- 500MB disk space

## 🛠️ Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/phishing-website-detector.git
cd phishing-website-detector
```

### Step 2: Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Train the ML Model

```bash
python train_model.py
```

This will:
- Generate a synthetic phishing dataset (or use your own)
- Extract features from URLs
- Train multiple ML models
- Select the best performing model
- Save the model as `phishing_model.pkl`

### Step 5: Run the Application

```bash
python app.py
```

The application will start on `http://localhost:5000`

## 📁 Project Structure

```
PhishingWebsiteDetector/
│
├── app.py                      # Flask application with routes and API
├── train_model.py              # ML model training script
├── feature_extraction.py       # URL feature extraction module
├── phishing_model.pkl          # Trained ML model (generated)
├── database.db                 # SQLite database (generated)
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
├── static/
│   ├── css/
│   │   └── style.css          # Custom CSS with dark mode
│   ├── js/
│   │   └── script.js          # Frontend JavaScript
│   └── images/                # Static images
│
├── templates/
│   ├── index.html             # Home page
│   ├── dashboard.html         # Dashboard with charts
│   ├── history.html           # Scan history page
│   └── about.html             # About page
│
└── dataset/
    └── phishing.csv           # Phishing dataset (optional)
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
SECRET_KEY=your-secret-key-here
VIRUSTOTAL_API_KEY=your-virustotal-api-key  # Optional
```

### Default Admin Credentials

- **Username**: admin
- **Password**: admin123

⚠️ **Important**: Change the default admin password after first login!

## 📊 Features Analyzed

The system extracts and analyzes 20+ features from URLs:

1. **URL Characteristics**: Length, domain length, path length, query length
2. **Character Counts**: Dots, hyphens, underscores, slashes, digits, letters
3. **Protocol**: HTTP vs HTTPS detection
4. **Special Symbols**: @ symbol, IP addresses, port numbers
5. **Domain Features**: Subdomain count, TLD analysis, domain age estimation
6. **Suspicious Keywords**: login, verify, account, secure, update, etc.
7. **URL Shortening**: Detection of shortened URLs (bit.ly, tinyurl, etc.)
8. **Security Indicators**: SSL indicators, redirect detection
9. **Entropy Calculation**: Shannon entropy for randomness detection
10. **Brand Detection**: Brand name and homograph character detection
11. **Path Analysis**: Depth, executable files, sensitive parameters
12. **Ratio Features**: Digit ratio, special character ratio

## 🎯 Usage

### Web Interface

1. Open `http://localhost:5000` in your browser
2. Enter a URL in the scan box
3. Click "Scan" to analyze the URL
4. View detailed results with confidence scores
5. Login to access history and dashboard

### API Endpoint

Make POST requests to `/api/predict`:

```bash
curl -X POST http://localhost:5000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Response:
```json
{
  "url": "https://example.com",
  "is_phishing": false,
  "confidence": 95.5,
  "risk_level": "Low",
  "probability_phishing": 4.5,
  "probability_legitimate": 95.5,
  "status": "success"
}
```

## 🚢 Deployment

### Deploy to Render

1. Create a `render.yaml` file:
```yaml
services:
  - type: web
    name: phishing-detector
    env: python
    buildCommand: pip install -r requirements.txt
    startCommand: python app.py
    envVars:
      - key: SECRET_KEY
        generateValue: true
      - key: VIRUSTOTAL_API_KEY
        sync: false
```

2. Push your code to GitHub
3. Connect your GitHub repository to Render
4. Deploy automatically

### Deploy to Heroku

```bash
# Install Heroku CLI
heroku create phishing-detector
heroku buildpacks:set heroku/python
git push heroku main
```

### Deploy to VPS (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt update
sudo apt install python3 python3-pip python3-venv nginx

# Clone and setup
git clone https://github.com/yourusername/phishing-website-detector.git
cd phishing-website-detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Setup systemd service
sudo nano /etc/systemd/system/phishing-detector.service
```

Service file content:
```ini
[Unit]
Description=Phishing Detector
After=network.target

[Service]
User=www-data
WorkingDirectory=/path/to/phishing-website-detector
ExecStart=/path/to/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl start phishing-detector
sudo systemctl enable phishing-detector
```

## 📈 Model Performance

The system achieves the following performance metrics on test data:

- **Random Forest**: 95%+ accuracy
- **Decision Tree**: 90%+ accuracy
- **XGBoost**: 96%+ accuracy (if available)

## 🔒 Security Considerations

- Never share your SECRET_KEY
- Change default admin credentials
- Use HTTPS in production
- Implement rate limiting (included)
- Keep dependencies updated
- Regular security audits
- Monitor scan logs for suspicious activity

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Scikit-learn for ML algorithms
- Flask for web framework
- Bootstrap for UI components
- Chart.js for data visualization
- VirusTotal for API integration

## 📧 Contact

For questions or support:
- Email: support@phishingdetector.com
- GitHub Issues: [Create an issue](https://github.com/yourusername/phishing-website-detector/issues)

## 📸 Screenshots

### Home Page
![Home Page](screenshots/home.png)

### Scan Results
![Scan Results](screenshots/results.png)

### Dashboard
![Dashboard](screenshots/dashboard.png)

### Scan History
![History](screenshots/history.png)

## 🔮 Future Enhancements

- [ ] Mobile app (React Native)
- [ ] Browser extension
- [ ] Email phishing detection
- [ ] Advanced ML models (Deep Learning)
- [ ] Real-time threat intelligence feed
- [ ] Multi-language support
- [ ] API rate limiting per user
- [ ] OAuth authentication
- [ ] Docker containerization
- [ ] Kubernetes deployment

## 🐛 Known Issues

- VirusTotal API has rate limits (free tier: 4 requests/minute)
- Model accuracy depends on training data quality
- Some legitimate URLs may be flagged as suspicious (false positives)

## 📚 Documentation

For detailed documentation, visit: [Documentation Link](https://your-docs-site.com)

## ⚠️ Disclaimer

This tool is for educational and defensive purposes only. No phishing detection system can guarantee 100% accuracy. Always exercise caution when clicking on links from unknown sources. Verify the authenticity of websites through official channels before entering sensitive information.

---

**Made with ❤️ for cybersecurity**
"# phishing_attack" 
