
# This is overly simplistic helper function, that returns true if the string starts with http:// or https://
def is_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")