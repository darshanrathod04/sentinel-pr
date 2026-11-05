import requests

def dispatch_notification_webhook(webhook_url):
    response = requests.get(webhook_url)
    return response.status_code
