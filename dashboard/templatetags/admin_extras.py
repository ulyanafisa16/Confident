from django import template
 
register = template.Library()
 
@register.filter
def get_attr(obj, attr_name):
    """
    Template filter untuk akses attribute objek secara dinamis.
    Penggunaan: {{ config|get_attr:rule_name }}
    """
    return getattr(obj, attr_name, False)