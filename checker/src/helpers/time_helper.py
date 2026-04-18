from datetime import datetime, timezone
from checker.src.helpers.const import MS_IN_SECOND

def convert_to_utc(timestamp : int | None) -> str:
    if timestamp is None:
        return "None"

    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime('%d-%m-%Y %H:%M:%S UTC')
    except (OverflowError, OSError, ValueError):
        try:
            dt = datetime.fromtimestamp(timestamp/MS_IN_SECOND, tz=timezone.utc)
            return dt.strftime('%d-%m-%Y %H:%M:%S UTC')
        except (OverflowError, OSError, ValueError):
            return f"Invalid timestamp: {timestamp}"