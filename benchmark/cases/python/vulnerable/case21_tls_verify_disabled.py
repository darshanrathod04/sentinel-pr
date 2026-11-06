import requests

def fetch_partner_data(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    # Dangerous: TLS verification explicitly disabled on static partner endpoint
    response = requests.get("https://api.partner.com/v1/data", headers=headers, verify=False)
    return response.json()
