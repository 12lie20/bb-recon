import logging
from datetime import datetime
logger = logging.getLogger("bb-recon")
STEP_TOTAL = 12
RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
RED   = "\033[38;5;196m"; GRN  = "\033[38;5;82m";  YLW = "\033[38;5;220m"
BLU   = "\033[38;5;39m";  MGN  = "\033[38;5;201m"; CYN = "\033[38;5;45m"
WHT   = "\033[38;5;255m"; GRY  = "\033[38;5;244m"; BLK = "\033[30m"
ORG   = "\033[38;5;208m"; DGRN = "\033[38;5;48m"
BG_RED = "\033[48;5;196m"; BG_BLK = "\033[48;5;236m"

__all__ = ["STEP_TOTAL", "RESET", "BOLD", "DIM", "RED", "GRN", "YLW", "BLU", "MGN", "CYN", "WHT", "GRY", "BLK", "ORG", "DGRN", "BG_RED", "BG_BLK", "banner", "section", "_end", "ok", "info", "warn", "found", "vuln", "sbadge", "sevbadge"]

def banner():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    art = [
        "  ██████╗ ██████╗       ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗",
        "  ██╔══██╗██╔══██╗      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║",
        "  ██████╔╝██████╔╝█████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║",
        "  ██╔══██╗██╔══██╗╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║",
        "  ██████╔╝██████╔╝      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║",
        "  ╚═════╝ ╚═════╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚══╝",
    ]
    print()
    print(GRY + "╔" + "═" * 70 + "╗" + RESET)
    for line in art:
        print(GRY + "║" + RESET + CYN + BOLD + line + " " * (70 - len(line)) + RESET + GRY + "║" + RESET)
    for text in ("v8.0  ·  Bug Bounty Reconnaissance Framework", now):
        p = (70 - len(text)) // 2
        print(GRY + "║" + RESET + GRY + DIM + " " * p + text + " " * (70 - p - len(text)) + RESET + GRY + "║" + RESET)
    print(GRY + "╚" + "═" * 70 + "╝" + RESET)
    print()
def section(num, title):
    filled="█"*num+"░"*(STEP_TOTAL-num)
    print()
    print(GRY+"┌─ "+RESET+WHT+BOLD+f"STEP {num}/{STEP_TOTAL}"+RESET+GRY+" ─── "+RESET+CYN+BOLD+title+RESET)
    print(GRY+f"│  [{filled}]"+RESET)
    print(GRY+"│"+RESET)
def _end():   print(GRY+"└"+"─"*70+RESET)
def ok(m):    print(GRY+"│  "+RESET+DGRN+"✔  "+RESET+WHT+m+RESET)
def info(m):  print(GRY+"│  "+RESET+GRY+"·  "+RESET+GRY+m+RESET)
def warn(m):  print(GRY+"│  "+RESET+YLW+"▲  "+RESET+YLW+m+RESET)
def found(m): print(GRY+"│  "+RESET+MGN+"★  "+RESET+WHT+BOLD+m+RESET)
def vuln(m):  print(GRY+"│  "+RESET+RED+"!! "+RESET+RED+BOLD+m+RESET)
def sbadge(code):
    c=int(code) if str(code).isdigit() else 0
    if c==200:          return "\033[48;5;28m"+WHT+f" {c} "+RESET
    if c in(301,302):   return "\033[48;5;39m"+BLK+f" {c} "+RESET
    if c==401:          return "\033[48;5;202m"+WHT+f" {c} "+RESET
    if c==403:          return "\033[48;5;130m"+WHT+f" {c} "+RESET
    if c==500:          return BG_RED+WHT+f" {c} "+RESET
    if c>0:             return BG_BLK+GRY+f" {c} "+RESET
    return BG_BLK+GRY+" ERR "+RESET
def sevbadge(s):
    s=s.upper()
    if s=="CRITICAL": return BG_RED+WHT+BOLD+" CRIT "+RESET
    if s=="HIGH":     return "\033[48;5;196m"+WHT+BOLD+" HIGH "+RESET
    if s=="MEDIUM":   return "\033[48;5;220m"+BLK+"  MED "+RESET
    return BG_BLK+GRY+f" {s[:4]:4} "+RESET
