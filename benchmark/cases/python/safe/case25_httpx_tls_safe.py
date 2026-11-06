import httpx

def dispatch_event_safe(event_payload):
    # Safe: Default TLS verification enabled
    client = httpx.Client()
    response = client.post("https://events.internal.corp/stream", json=event_payload)
    return response.status_code
