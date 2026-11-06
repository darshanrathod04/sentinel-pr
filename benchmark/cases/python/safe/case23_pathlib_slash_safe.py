import os
from pathlib import Path

def get_user_avatar_safe(request):
    avatar_name = request.args.get("avatar")
    safe_filename = os.path.basename(avatar_name)
    base_dir = Path("/var/app/avatars")
    avatar_path = base_dir / safe_filename
    resolved = os.path.realpath(str(avatar_path))
    if not resolved.startswith(str(base_dir)):
        raise PermissionError("Path traversal blocked")
    with open(avatar_path, "rb") as f:
        return f.read()
