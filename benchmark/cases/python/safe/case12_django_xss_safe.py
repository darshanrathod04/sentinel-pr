from django.utils.safestring import mark_safe

def render_static_banner():
    return mark_safe("<div class='banner'>Welcome to SentinelPR</div>")
