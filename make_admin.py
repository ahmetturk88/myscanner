# make_admin.py
from app import app, db
from models import User

with app.app_context():
    user = User.query.filter_by(username='ahmedsayrafi').first()
    if user:
        user.is_admin = True
        db.session.commit()
        print("✅ Admin access granted!")
        print(f"Username: {user.username}")
        print(f"Is Admin: {user.is_admin}")
    else:
        print("❌ User not found!")
        print("Please register first using the web interface.")