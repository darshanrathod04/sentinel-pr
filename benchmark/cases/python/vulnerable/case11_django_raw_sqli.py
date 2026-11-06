from django.contrib.auth.models import User

def find_user_by_name(request):
    name = request.GET.get("name")
    query = f"SELECT * FROM auth_user WHERE username = '{name}'"
    return User.objects.raw(query)
