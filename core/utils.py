import subprocess, os, json, re, time, shutil, shlex, asyncio, functools
import urllib.parse
import logging
logger = logging.getLogger("bb-recon")
from core.config import CONFIG
from core.ui import *
def save_checkpoint(out, step, data):
    cp = {"step": step, "timestamp": time.time()}
    cp.update(data)
    save_json(f"{out}/.checkpoint.json", cp)
def load_checkpoint(out_dir):
    cp_file = f"{out_dir}/.checkpoint.json"
    if os.path.exists(cp_file):
        try:
            with open(cp_file, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]
KNOWN_TECH_KEYS = {
    "wordpress","drupal","joomla","laravel","django","flask","rails","spring",
    "nginx","apache","iis","tomcat","node.js","next.js","nuxt","php","asp.net",
    "jquery","react","angular","vue","svelte","bootstrap","tailwind","grafana",
    "jenkins","kibana","elasticsearch","redis","mongodb","mysql","postgres",
    "couchdb","kubernetes","docker","aws","azure","cloudflare","firebase",
    "jira","confluence","gitlab","github","magento","shopify","woocommerce",
    "strapi","ghost","varnish","prettyPhoto","slider revolution",
    "pdf.js","modernizr","moment.js","owl carousel","isotope","masonry",
    "express","fastify","koa","nest.js","deno","bun","supabase","hasura",
    "graphql","prisma","typeorm","sequelize","mongoose","symfony","codeigniter",
    "cakephp","yii","zend","slim","lumen","fastapi","starlette","tornado",
    "gunicorn","uvicorn","caddy","traefik","envoy","haproxy","litespeed",
    "openresty","kong","apisix","minio","consul","vault","terraform",
    "ansible","puppet","chef","saltstack","prometheus","alertmanager",
    "datadog","new relic","sentry","bugsnag","rollbar","logstash","fluentd",
    "rabbitmq","kafka","nats","celery","sidekiq","bull","temporal",
}
def random_ua():
    import random
    return random.choice(UA_LIST)
def is_likely_tech(label):
    l = (label or "").strip().lower()
    if not l:
        return False
    if l in KNOWN_TECH_KEYS:
        return True
    if re.search(r"\b(v?\d+(?:\.\d+){1,3})\b", l):
        return True
    return any(k in l or l in k for k in KNOWN_TECH_KEYS)
def t_ok(name): return bool(shutil.which(name))
def pool_workers(default_workers):
    try:
        return max(1, min(int(default_workers), int(CONFIG.max_threads)))
    except Exception:
        return max(1, int(default_workers))
def in_target_domain(url_or_host, domain):
    host = url_or_host.strip().lower()
    if not host:
        return False
    if "://" in host:
        try:
            host = urllib.parse.urlparse(host).netloc.lower()
        except Exception:
            return False
    host = host.split(":")[0].strip(".")
    domain = domain.lower().strip(".")
    return host == domain or host.endswith("." + domain)
def shell_cat_cmd(path):
    quoted = f'"{path}"'
    return f"type {quoted}" if os.name == "nt" else f"cat {quoted}"
def _normalize_cmd(cmd):
    if isinstance(cmd, (list, tuple)):
        return [str(x) for x in cmd]
    if isinstance(cmd, str):
        return shlex.split(cmd, posix=(os.name != "nt"))
    raise TypeError("cmd must be str/list/tuple")
def run_cmd(cmd, timeout=120, input_data=None):
    if CONFIG.dry_run:
        info(f"[dry-run] {' '.join(_normalize_cmd(cmd))}")
        return ""
    try:
        r=subprocess.run(_normalize_cmd(cmd),capture_output=True,text=True,
                         input=input_data,
                         timeout=timeout,env=os.environ.copy())
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        warn(f"Timeout ({timeout}s)")
        return ""
    except Exception as e:
        warn(f"cmd error: {e}")
        return ""
def pipe_cmd(cmd, timeout=300, retries=2, input_data=None):
    if CONFIG.dry_run:
        info(f"[dry-run] {' '.join(_normalize_cmd(cmd))}")
        return []
    for attempt in range(1, retries+1):
        try:
            proc=subprocess.Popen(_normalize_cmd(cmd),stdout=subprocess.PIPE,
                                  stdin=subprocess.PIPE if input_data is not None else None,
                                  stderr=subprocess.DEVNULL,text=True,
                                  env=os.environ.copy())
            try:
                stdout,_=proc.communicate(input=input_data, timeout=timeout)
                lines=[l.strip() for l in stdout.splitlines() if l.strip()]
                if lines: return lines
                if attempt<retries:
                    warn(f"Pipeline empty — retry {attempt}/{retries} ...")
                    time.sleep(2); continue
                return []
            except subprocess.TimeoutExpired:
                proc.kill()
                warn(f"Pipeline timeout ({timeout}s) — partial results")
                stdout,_=proc.communicate()
                return [l.strip() for l in stdout.splitlines() if l.strip()]
        except Exception as e:
            warn(f"Pipeline error (attempt {attempt}): {e}")
            if attempt<retries: time.sleep(2)
    return []
def save_json(p,d):
    with open(p,"w",encoding="utf-8") as f:
        f.write(json.dumps(d,indent=2,ensure_ascii=False))
def save_txt(p,d):
    with open(p,"w",encoding="utf-8") as f:
        f.write("\n".join(str(x) for x in d))
def generate_oob_id():
    import random, string
    return "bb" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

def ensure_async(async_fn):
    @functools.wraps(async_fn)
    def wrapper(*args, **kwargs):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            return loop.create_task(async_fn(*args, **kwargs))
        else:
            return asyncio.run(async_fn(*args, **kwargs))
    return wrapper
