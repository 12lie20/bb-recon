import re, socket
import asyncio
import aiohttp
import logging
from collections import defaultdict
logger = logging.getLogger("bb-recon")

from core.ui import *
from core.utils import *
from core.utils import ensure_async
from core.http import http_probe

PORT_PROFILES={
    80:("http","web"),443:("https","web"),8080:("http","web"),
    8443:("https","web"),8000:("http","web"),8001:("http","web"),
    8008:("http","web"),8081:("http","web"),8082:("http","web"),
    8083:("http","web"),8085:("http","web"),8086:("http","web"),
    8090:("http","web"),8444:("https","web"),8888:("http","web"),
    9000:("http","web"),9001:("http","web"),9080:("http","web"),
    9090:("http","web"),3000:("http","web"),4000:("http","web"),
    5000:("http","web"),9200:("http","elasticsearch"),
    9300:("tcp","elasticsearch-transport"),
    6379:("tcp","redis"),27017:("tcp","mongodb"),
    5432:("tcp","postgres"),3306:("tcp","mysql"),
    5984:("http","couchdb"),2375:("http","docker"),
    2376:("https","docker-tls"),
    22:("tcp","ssh"),21:("tcp","ftp"),
}

def probe_tcp_port(host, port, svc):
    probes={"redis":b"PING\r\n","ftp":None,"ssh":None,"mongodb":None}
    pd=probes.get(svc)
    try:
        with socket.create_connection((host,port),timeout=6) as sock:
            if pd: sock.sendall(pd)
            banner=sock.recv(512).decode("utf-8",errors="ignore").strip()
            return {"method":"TCP banner","banner":banner[:200]}
    except Exception as e:
        return {"method":"TCP banner","error":str(e)[:60]}

async def probe_port(session, host, port):
    scheme,svc=PORT_PROFILES[port]
    result={"host":host,"port":port,"service":svc,"findings":[]}
    if scheme in ("http","https"):
        base=f"{scheme}://{host}:{port}"
        code,body,hdrs,ms=await http_probe(session, base+"/",timeout=8)
        server=hdrs.get("Server",""); powered=hdrs.get("X-Powered-By","")
        result["findings"].append({"method":"GET /","code":code,
                                   "server":server,"powered_by":powered,"ms":ms})
        if code==405:
            c2,b2,_,ms2=await http_probe(session, base+"/",method="POST",
                                    data=b"{}",timeout=6,
                                    extra_headers={"Content-Type":"application/json"})
            result["findings"].append({"method":"POST /","code":c2,"ms":ms2})
    elif scheme=="tcp":
        loop = asyncio.get_running_loop()
        finding = await loop.run_in_executor(None, probe_tcp_port, host, port, svc)
        result["findings"].append(finding)
    return result

FALLBACK_PORTS = [
    21, 22, 80, 443, 2375, 2376, 3000, 3306, 4000, 5000, 5432, 5984,
    6379, 8000, 8001, 8008, 8080, 8081, 8082, 8083, 8085, 8086, 8090,
    8443, 8444, 8888, 9000, 9001, 9080, 9090, 9200, 9300, 27017,
]

async def _scan_port_socket(host, port, timeout=3):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None

async def _fallback_port_scan(hosts):
    port_map = defaultdict(list)
    sem = asyncio.Semaphore(100)
    async def check(host, port):
        async with sem:
            result = await _scan_port_socket(host, port)
            if result:
                port_map[host].append(port)
                badge = MGN+"[!]"+RESET if port in PORT_PROFILES else GRY+"[ ]"+RESET
                svc = PORT_PROFILES.get(port, ("", ""))[1]
                svc_s = GRY+DIM+f"  [{svc}]"+RESET if svc else ""
                print(GRY+"│  "+RESET+badge+"  "+WHT+f"{host}:{port}"+RESET+svc_s)
    tasks = [check(h, p) for h in hosts for p in FALLBACK_PORTS]
    await asyncio.gather(*tasks)
    return port_map

@ensure_async
async def run_ports(live_lines, out):
    section(3,"STRATEGIC PORT SCAN  +  SERVICE INTERACTION")
    use_naabu = t_ok("naabu")
    if not use_naabu:
        warn("naabu not found — using Python socket fallback (top 33 ports)")
    hosts=set()
    for line in live_lines:
        m=re.match(r"https?://([^/\s\[]+)",line)
        if m: hosts.add(m.group(1))
    if not hosts:
        warn("No live hosts for port scan"); _end(); return {}
    hosts_file=f"{out}/_hosts_for_ports.txt"
    save_txt(hosts_file,sorted(hosts))
    print(GRY+"│"+RESET)
    loop = asyncio.get_running_loop()
    port_map=defaultdict(list)
    if use_naabu:
        info(f"naabu scanning {len(hosts)} hosts · top-1000 ports ...")
        lines = await loop.run_in_executor(None, lambda: pipe_cmd(["naabu", "-l", hosts_file, "-top-ports", "1000", "-c", "50", "-silent", "-no-color"], 180))
        for line in lines:
            m=re.match(r"([^:]+):(\d+)",line.strip())
            if m:
                host,port=m.group(1),int(m.group(2))
                port_map[host].append(port)
                badge=MGN+"[!]"+RESET if port in PORT_PROFILES else GRY+"[ ]"+RESET
                svc=PORT_PROFILES.get(port,("",""))[1]
                svc_s=GRY+DIM+f"  [{svc}]"+RESET if svc else ""
                print(GRY+"│  "+RESET+badge+"  "+WHT+f"{host}:{port}"+RESET+svc_s)
    else:
        info(f"Python fallback scanning {len(hosts)} hosts × {len(FALLBACK_PORTS)} ports ...")
        port_map = await _fallback_port_scan(sorted(hosts))
    hosts_with_443={h for h,ports in port_map.items() if 443 in ports}
    tasks_args=[(h,p) for h,ports in port_map.items()
           for p in ports
           if p in PORT_PROFILES
           and not (p==80 and h in hosts_with_443)]
    print(GRY+"│"+RESET)
    info(f"Probing {len(tasks_args)} interesting services ...")
    print(GRY+"│"+RESET)
    port_findings=[]
    
    sem = asyncio.Semaphore(15)
    async with aiohttp.ClientSession() as session:
        async def bound_probe(h, p):
            async with sem:
                try:
                    return await probe_port(session, h, p)
                except Exception as e:
                    logger.debug(f"Port probe failed for {(h, p)}: {e}")
                    return None
                    
        tasks = [bound_probe(h, p) for h, p in tasks_args]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if not res: continue
            h, p = res["host"], res["port"]
            svc = res["service"]
            fds=[fi for fi in res["findings"] if fi.get("code") or "banner" in fi]
            if not fds: continue
            print(GRY+"│  "+RESET+CYN+BOLD+f"{h}:{p}"+RESET+GRY+f"  [{svc}]"+RESET)
            for fi in fds:
                if "banner" in fi:
                    b=fi["banner"]
                    if b:
                        color=RED+BOLD if any(x in b.lower() for x in
                              ("no auth","unauthorized required: 0","version")) else GRY
                        print(GRY+"│    "+RESET+YLW+"[BANNER] "+RESET+color+b[:100]+RESET)
                        if "no auth" in b.lower():
                            found(f"UNAUTHENTICATED {svc.upper()} → {h}:{p}")
                else:
                    fc=fi.get("code",0); method=fi.get("method","")
                    snippet=fi.get("snippet","")[:80]
                    validated=fi.get("validated",True)
                    line_str=(GRY+"│    "+RESET+sbadge(fc)+"  "+
                              GRY+f"{method:<22}"+RESET)
                    if snippet and validated:
                        line_str+=GRY+DIM+"  "+snippet+RESET
                    print(line_str)
                    if fc==200 and validated and method!="GET /":
                        found(f"Exposed: {h}:{p}{method.split()[-1]}")
            port_findings.append(res)
            print(GRY+"│"+RESET)
            
    save_json(f"{out}/port_scan.json",{h:sorted(p) for h,p in port_map.items()})
    save_json(f"{out}/port_findings.json",port_findings)
    ok(f"Open ports   : {BOLD}{sum(len(v) for v in port_map.values())}{RESET}")
    ok(f"Services probed: {BOLD}{len(tasks_args)}{RESET}")
    _end()
    return dict(port_map)

port_scan = run_ports

