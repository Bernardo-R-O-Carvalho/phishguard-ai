from datetime import datetime
import re

# Horário comercial: 7h-21h, seg-sex
# Fora disso é suspeito
SUSPICIOUS_HOURS = list(range(0, 6)) + list(range(22, 24))  # 22h-05h59

DATE_FORMATS = [
    "%a, %d %b %Y %H:%M:%S %z",   # RFC 2822: Mon, 01 Jan 2024 10:00:00 +0000
    "%d %b %Y %H:%M:%S %z",        # sem dia da semana
    "%Y-%m-%dT%H:%M:%S%z",         # ISO 8601
    "%Y-%m-%d %H:%M:%S",           # simples sem tz
    "%d/%m/%Y %H:%M",              # BR style
    "%m/%d/%Y %H:%M",              # US style
]

def parse_date(date_str: str) -> datetime | None:
    """Tenta parsear a string de data em vários formatos."""
    if not date_str:
        return None

    # Remove timezone textual como "(UTC)" ou "(BRT)" que quebram o parse
    cleaned = re.sub(r'\s*\([A-Z]+\)\s*$', '', date_str.strip())

    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    return None

def analyze_time(date_str: str) -> dict:
    """
    Analisa o horário de envio do email.
    Retorna flags e score (0-20).
    """
    if not date_str or not date_str.strip():
        return {"flags": [], "score": 0, "parsed": None}

    dt = parse_date(date_str)
    if dt is None:
        return {"flags": ["could not parse date"], "score": 0, "parsed": None}

    flags = []
    score = 0

    # Horário suspeito
    if dt.hour in SUSPICIOUS_HOURS:
        flags.append(f"sent at unusual hour ({dt.hour:02d}:{dt.minute:02d})")
        score += 15

    # Final de semana (5=sábado, 6=domingo)
    if dt.weekday() >= 5:
        day_name = "Saturday" if dt.weekday() == 5 else "Sunday"
        flags.append(f"sent on {day_name}")
        score += 5

    return {
        "flags": flags,
        "score": min(score, 20),
        "parsed": dt.strftime("%Y-%m-%d %H:%M") if dt else None
    }
