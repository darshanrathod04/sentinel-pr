import os

def read_tenant_doc(request):
    doc_id = request.args.get("doc_id")
    target_path = os.path.join("/var/documents", doc_id)
    with open(target_path, "r") as f:
        return f.read()
