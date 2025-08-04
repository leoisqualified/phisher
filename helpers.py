from .models import Company
from flask import request

def get_company_from_apikey():
    api_key = request.headers.get("X-API-KEY")
    if not api_key:
        return None

    company = Company.query.filter_by(api_key=api_key).first()
    return company
