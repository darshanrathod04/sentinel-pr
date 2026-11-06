from pathlib import Path

def get_user_avatar(request):
    avatar_name = request.args.get("avatar")
    base_dir = Path("/var/app/avatars")
    # Vulnerable: pathlib / operator with unconstrained dynamic path
    avatar_path = base_dir / avatar_name
    with open(avatar_path, "rb") as f:
        return f.read()
