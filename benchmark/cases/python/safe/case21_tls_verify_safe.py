import requests

def fetch_partner_data_safe(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    # Safe: Default TLS verification enabled on static partner endpoint
    response = requests.get("https://api.partner.com/v1/data", headers=headers)
    return response.json()
