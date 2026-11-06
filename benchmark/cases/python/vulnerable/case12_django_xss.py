from django.utils.safestring import mark_safe

def render_user_comment(request):
    comment = request.POST.get("comment")
    html = f"<div class='user-comment'>{comment}</div>"
    return mark_safe(html)
