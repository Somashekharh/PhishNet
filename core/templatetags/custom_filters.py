from django import template
import math
import pprint

register = template.Library()

@register.filter
def replace(value, arg):
    """
    Replace all instances of arg in the string with a space and capitalize words.
    """
    # Replace underscores with spaces and capitalize each word
    words = value.replace(arg, " ").split()
    return " ".join(word.capitalize() for word in words)

@register.filter
def abs_value(value):
    """Return the absolute value of a number."""
    try:
        return abs(float(value))
    except (ValueError, TypeError):
        return value

@register.filter
def pprint(value):
    """Pretty print a value for debugging."""
    try:
        return pprint.pformat(value, width=80, depth=3)
    except:
        return str(value) 