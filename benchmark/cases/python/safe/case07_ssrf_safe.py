import requests

ALLOWED_HOSTS = ["https://api.github.com", "https://hooks.slack.com"]

def dispatch_notification_webhook_safe(webhook_url):
    if webhook_url in ALLOWED_HOSTS:
        response = requests.get(webhook_url)
        return response.status_code
    return 403
