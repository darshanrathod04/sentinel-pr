import requests

def notify_webhook(request):
    callback_url = request.args.get("callback")
    requests.post(callback_url, json={"event": "ping"})
