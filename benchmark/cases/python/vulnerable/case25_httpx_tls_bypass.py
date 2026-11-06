import httpx

def dispatch_event(event_payload):
    client = httpx.Client(verify=False)
    # Dangerous: TLS verification disabled on client POST
    response = client.post("https://events.internal.corp/stream", json=event_payload, verify=False)
    return response.status_code
