from app import app, db, User, ScanHistory

with app.app_context():
    print("=" * 60)
    print("DATABASE DETAILS")
    print("=" * 60)
    
    print("\nDatabase Configuration:")
    print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"Track Modifications: {app.config['SQLALCHEMY_TRACK_MODIFICATIONS']}")
    
    print("\n" + "=" * 60)
    print("USERS TABLE")
    print("=" * 60)
    users = User.query.all()
    print(f"Total Users: {len(users)}")
    for u in users:
        print(f"\nID: {u.id}")
        print(f"Username: {u.username}")
        print(f"Email: {u.email}")
        print(f"Is Admin: {u.is_admin}")
        print(f"Created At: {u.created_at}")
        print(f"Total Scans: {len(u.scans)}")
    
    print("\n" + "=" * 60)
    print("SCAN HISTORY TABLE")
    print("=" * 60)
    scans = ScanHistory.query.all()
    print(f"Total Scans: {len(scans)}")
    
    if scans:
        phishing_count = ScanHistory.query.filter_by(is_phishing=True).count()
        safe_count = ScanHistory.query.filter_by(is_phishing=False).count()
        print(f"Phishing URLs: {phishing_count}")
        print(f"Safe URLs: {safe_count}")
        
        print("\nRecent Scans:")
        for scan in scans[-5:]:
            print(f"\nID: {scan.id}")
            print(f"URL: {scan.url}")
            print(f"Is Phishing: {scan.is_phishing}")
            print(f"Confidence: {scan.confidence}%")
            print(f"Risk Level: {scan.risk_level}")
            print(f"Timestamp: {scan.timestamp}")
            print(f"User ID: {scan.user_id}")
    else:
        print("No scans recorded yet.")
    
    print("\n" + "=" * 60)
    print("DATABASE TABLES")
    print("=" * 60)
    print(db.metadata.tables.keys())
