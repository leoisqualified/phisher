from models import Company
from flask import request, session, redirect, url_for
from functools import wraps 

def get_company_from_apikey():
    api_key = request.headers.get("X-API-KEY")
    if not api_key:
        return None

    company = Company.query.filter_by(api_key=api_key).first()
    return company

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function
