from app import app, db, User

with app.app_context():
    users = User.query.all()
    print(f'Database connected. Users found: {len(users)}')
    for u in users:
        print(f'Username: {u.username}, Email: {u.email}, Admin: {u.is_admin}')
