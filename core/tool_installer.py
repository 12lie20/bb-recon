import subprocess
import sys
import os
import shutil
import platform
import logging
logger = logging.getLogger("bb-recon")
from core.ui import RESET, BOLD, DIM, GRN, YLW, RED, CYN, GRY, WHT, MGN

GO_TOOLS = {
    "subfinder":    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx":        "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "dnsx":         "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "naabu":        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "nuclei":       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "katana":       "github.com/projectdiscovery/katana/cmd/katana@latest",
    "waybackurls":  "github.com/tomnomnom/waybackurls@latest",
    "gau":          "github.com/lc/gau/v2/cmd/gau@latest",
}

PIP_TOOLS = {
    "uro":          "uro",
    "aiohttp":      "aiohttp>=3.9.0",
    "dnspython":    "dnspython>=2.4.0",
    "jinja2":       "Jinja2",
    "pyyaml":       "PyYAML",
    "cryptography": "cryptography",
    "pyjwt":        "PyJWT",
}

def _has_go():
    return shutil.which("go") is not None

def _has_pip():
    return shutil.which("pip") is not None or shutil.which("pip3") is not None

def _pip_cmd():
    if shutil.which("pip3"):
        return "pip3"
    return "pip"

def _check_tool(name):
    return shutil.which(name) is not None

def _check_pip_package(pkg_name):
    try:
        __import__(pkg_name)
        return True
    except ImportError:
        return False

def _install_go_tool(name, path):
    print(GRY+"│  "+RESET+CYN+f"Installing {name}"+RESET+GRY+DIM+f"  ({path})"+RESET)
    try:
        env = os.environ.copy()
        gopath = env.get("GOPATH", os.path.expanduser("~/go"))
        env["GOPATH"] = gopath
        gobin = os.path.join(gopath, "bin")
        env["GOBIN"] = gobin
        if gobin not in env.get("PATH", ""):
            env["PATH"] = gobin + os.pathsep + env.get("PATH", "")
        r = subprocess.run(
            ["go", "install", path],
            capture_output=True, text=True, timeout=120, env=env
        )
        if r.returncode == 0:
            print(GRY+"│  "+RESET+GRN+"✔  "+RESET+WHT+f"{name} installed successfully"+RESET)
            return True
        else:
            err = (r.stderr or r.stdout or "").strip().splitlines()
            err_msg = err[0][:80] if err else "unknown error"
            print(GRY+"│  "+RESET+RED+f"✗  {name} install failed: {err_msg}"+RESET)
            return False
    except subprocess.TimeoutExpired:
        print(GRY+"│  "+RESET+RED+f"✗  {name} install timed out (120s)"+RESET)
        return False
    except Exception as e:
        print(GRY+"│  "+RESET+RED+f"✗  {name} install error: {e}"+RESET)
        return False

def _install_pip_package(pkg_name, pkg_spec):
    print(GRY+"│  "+RESET+CYN+f"Installing {pkg_name}"+RESET+GRY+DIM+f"  ({pkg_spec})"+RESET)
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg_spec],
            capture_output=True, text=True, timeout=60
        )
        if r.returncode == 0:
            print(GRY+"│  "+RESET+GRN+"✔  "+RESET+WHT+f"{pkg_name} installed"+RESET)
            return True
        else:
            err = (r.stderr or "").strip().splitlines()
            err_msg = err[-1][:80] if err else "unknown error"
            print(GRY+"│  "+RESET+RED+f"✗  {pkg_name} failed: {err_msg}"+RESET)
            return False
    except Exception as e:
        print(GRY+"│  "+RESET+RED+f"✗  {pkg_name} error: {e}"+RESET)
        return False

def ensure_tools(auto_install=True):
    print()
    print(GRY+"┌─ "+RESET+WHT+BOLD+"PRE-FLIGHT"+RESET+GRY+" ─── "+RESET+CYN+BOLD+"TOOL DEPENDENCY CHECK"+RESET)
    print(GRY+"│"+RESET)

    has_go = _has_go()
    has_pip = _has_pip()

    if has_go:
        go_ver = ""
        try:
            r = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=5)
            go_ver = r.stdout.strip().split()[-2] if r.stdout else ""
        except Exception:
            pass
        print(GRY+"│  "+RESET+GRN+"✔  "+RESET+WHT+f"Go runtime found"+RESET+GRY+DIM+f"  ({go_ver})"+RESET)
    else:
        print(GRY+"│  "+RESET+YLW+"▲  "+RESET+YLW+"Go not found — Go tools will be skipped"+RESET)
        print(GRY+"│     "+RESET+GRY+DIM+"Install from https://go.dev/dl/"+RESET)

    print(GRY+"│  "+RESET+GRN+"✔  "+RESET+WHT+f"Python {sys.version.split()[0]}"+RESET)
    print(GRY+"│"+RESET)

    go_ok, go_missing, go_failed = [], [], []
    pip_ok, pip_missing, pip_failed = [], [], []

    print(GRY+"│  "+RESET+WHT+BOLD+"Go Tools:"+RESET)
    for name, path in GO_TOOLS.items():
        if _check_tool(name):
            go_ok.append(name)
            print(GRY+"│    "+RESET+GRN+"✔ "+RESET+GRY+f"{name}"+RESET)
        else:
            go_missing.append((name, path))
            print(GRY+"│    "+RESET+RED+"✗ "+RESET+YLW+f"{name}"+RESET+GRY+DIM+"  (missing)"+RESET)

    print(GRY+"│"+RESET)
    print(GRY+"│  "+RESET+WHT+BOLD+"Python Packages:"+RESET)
    for pkg_name, pkg_spec in PIP_TOOLS.items():
        import_name = pkg_name.replace("-", "_").lower()
        if import_name == "pyyaml":
            import_name = "yaml"
        if import_name == "pyjwt":
            import_name = "jwt"
        if _check_pip_package(import_name) or _check_tool(pkg_name):
            pip_ok.append(pkg_name)
            print(GRY+"│    "+RESET+GRN+"✔ "+RESET+GRY+f"{pkg_name}"+RESET)
        else:
            pip_missing.append((pkg_name, pkg_spec))
            print(GRY+"│    "+RESET+RED+"✗ "+RESET+YLW+f"{pkg_name}"+RESET+GRY+DIM+"  (missing)"+RESET)

    total_missing = len(go_missing) + len(pip_missing)

    if total_missing == 0:
        print(GRY+"│"+RESET)
        print(GRY+"│  "+RESET+GRN+BOLD+"All tools ready — proceeding with scan"+RESET)
        print(GRY+"└"+"─"*70+RESET)
        print()
        return True

    if not auto_install:
        print(GRY+"│"+RESET)
        print(GRY+"│  "+RESET+YLW+f"▲  {total_missing} tools missing — scan will skip unavailable modules"+RESET)
        print(GRY+"└"+"─"*70+RESET)
        print()
        return False

    print(GRY+"│"+RESET)
    print(GRY+"│  "+RESET+MGN+BOLD+f"Auto-installing {total_missing} missing tool(s) ..."+RESET)
    print(GRY+"│"+RESET)

    if pip_missing:
        for pkg_name, pkg_spec in pip_missing:
            ok = _install_pip_package(pkg_name, pkg_spec)
            if ok:
                pip_ok.append(pkg_name)
            else:
                pip_failed.append(pkg_name)

    if go_missing and has_go:
        for name, path in go_missing:
            ok = _install_go_tool(name, path)
            if ok:
                go_ok.append(name)
            else:
                go_failed.append(name)
    elif go_missing and not has_go:
        go_failed = [n for n, _ in go_missing]
        print(GRY+"│  "+RESET+YLW+"▲  Skipping Go tools (Go runtime not installed)"+RESET)

    all_failed = go_failed + pip_failed

    print(GRY+"│"+RESET)
    if not all_failed:
        print(GRY+"│  "+RESET+GRN+BOLD+"All tools installed successfully!"+RESET)
    else:
        print(GRY+"│  "+RESET+GRN+f"Installed: {total_missing - len(all_failed)}/{total_missing}"+RESET)
        if all_failed:
            print(GRY+"│  "+RESET+YLW+f"▲  Could not install: {', '.join(all_failed)}"+RESET)
            print(GRY+"│  "+RESET+GRY+DIM+"  Scan will continue — modules using these tools will be skipped"+RESET)

    print(GRY+"└"+"─"*70+RESET)
    print()
    return len(all_failed) == 0
