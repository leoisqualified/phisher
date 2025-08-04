# clear_db.py
from app import app
from models import db, URLLog, Blacklist, Company, AdminUser

def clear_database():
    print("Clearing database...")

    # Delete records from each table
    URLLog.query.delete()
    Blacklist.query.delete()
    AdminUser.query.delete()
    Company.query.delete()

    db.session.commit()
    print("Database cleared successfully.")

if __name__ == "__main__":
    with app.app_context():
        clear_database()
