#!/usr/bin/env python3
"""conn-map.py - łączy wyniki conn-audit.sh z wielu serwerów w mapę połączeń.

Oczekiwany układ (jeden katalog wynikowy conn-audit.sh na serwer, nazwy dowolne):
    audyty/web01/{info.txt,summary.tsv,conntrack.tsv}
    audyty/app01/{info.txt,summary.tsv}
    ...
Użycie:
    python3 conn-map.py audyty [-o wyjscie] [--hosts hosts.txt] [--skip-ports 22,53,123]
                               [--unknown subnet|show|hide] [--min 1]
Wynik: map.html (interaktywna, dla dużych środowisk), map.md (do GitLaba: README/wiki), map.mmd (sam Mermaid), map.dot (Graphviz), edges.csv (lista połączeń)
"""
import argparse, csv, ipaddress, json, os, sys
from collections import defaultdict
from datetime import date

PORTS = {22: "ssh", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos", 123: "ntp", 389: "ldap",
         443: "https", 445: "smb", 514: "syslog", 636: "ldaps", 1433: "mssql", 1521: "oracle",
         2049: "nfs", 3128: "squid", 3268: "ad-gc", 3269: "ad-gcs", 3306: "mysql", 5432: "postgres",
         5671: "amqps", 5672: "amqp", 6379: "redis", 6443: "kube-api", 8080: "http-alt",
         8443: "https-alt", 9090: "prometheus", 9092: "kafka", 9100: "node-exporter",
         9200: "elasticsearch", 10250: "kubelet", 11211: "memcached", 27017: "mongodb"}


def useful(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_link_local or a.is_unspecified)


def read_info(path):
    host, ips = None, []
    for line in open(path, encoding="utf-8-sig", errors="replace"):
        if line.startswith("host:"):
            host = line.split(":", 1)[1].strip().split(".")[0].lower()
        elif line.startswith("lokalne_ip:"):
            ips = [i for i in line.split(":", 1)[1].strip().split(",") if i]
    return host, ips


def rows(path):
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
            yield from csv.DictReader(f, delimiter="\t")


def load_inventory(root):
    servers, ipmap, dup = defaultdict(list), {}, set()
    for d, _, files in os.walk(root):
        if "info.txt" not in files:
            continue
        host, ips = read_info(os.path.join(d, "info.txt"))
        if not host:
            continue
        servers[host].append(d)
        for ip in filter(useful, ips):
            if ip in ipmap and ipmap[ip] != host:
                dup.add(ip)          # np. 10.88.0.1 z podmana na wielu hostach - nie da się przypisać
            ipmap[ip] = host
    for ip in dup:
        ipmap.pop(ip, None)
    return servers, ipmap, dup


def load_names(path):
    """Plik jak /etc/hosts: 'ip nazwa' albo 'podsieć/CIDR nazwa'. Zwraca (pojedyncze IP, podsieci)."""
    names, nets = {}, []
    if path:
        for line in open(path, encoding="utf-8-sig"):
            p = line.split("#")[0].split()
            if len(p) < 2:
                continue
            try:
                if "/" in p[0]:
                    nets.append((ipaddress.ip_network(p[0], strict=False), p[1]))
                else:
                    names[str(ipaddress.ip_address(p[0]))] = p[1]
            except ValueError:
                print(f"Pomijam błędny wpis w {path}: {line.strip()}", file=sys.stderr)
    nets.sort(key=lambda x: x[0].prefixlen, reverse=True)   # najpierw najbardziej szczegółowa podsieć
    return names, nets


def node_for(ip, ipmap, names, nets, unknown):
    if ip in ipmap:
        return ipmap[ip]
    if ip in names:
        return names[ip]
    a = ipaddress.ip_address(ip)
    for net, name in nets:
        if a in net:
            return name
    if unknown == "hide":
        return None
    if unknown == "subnet":
        return f"{ipaddress.ip_network(f'{ip}/{24 if a.version == 4 else 64}', strict=False)} (nieznane)"
    return ip


def build_edges(servers, ipmap, names, nets, args):
    edges = {}
    for host, dirs in servers.items():
        for d in dirs:
            for fname in ("summary.tsv", "conntrack.tsv"):
                for r in rows(os.path.join(d, fname)):
                    kind, ip = r["kierunek"], r["adres_zdalny"]
                    if kind not in ("OUT", "IN") or not useful(ip):
                        continue
                    n = int(r.get("probek") or r.get("nowych") or 0)
                    if n < args.min:
                        continue
                    peer = node_for(ip, ipmap, names, nets, args.unknown)
                    if kind == "OUT":
                        src, dst, port = host, peer, r["port_zdalny"]
                    else:
                        src, dst, port = peer, host, r["port_lokalny"]
                    if src is None or dst is None or src == dst or port in args.skip:
                        continue
                    pnum = int(port) if port.isdigit() else 0      # ICMP: brak portu
                    e = edges.setdefault((src, dst, r["proto"], pnum),
                                         {"sides": set(), "n": 0, "client": set(), "server": set()})
                    e["sides"].add(kind)
                    e["n"] = max(e["n"], n)
                    unit = r.get("jednostka") or "-"
                    if unit != "-":
                        e["client" if kind == "OUT" else "server"].add(unit)
    return edges


def svc(proto, port):
    if not port:
        return proto
    return f"{port}/{proto} {PORTS.get(port, '')}".strip()


def split_groups(edges):
    """(src,dst) -> (potwierdzone, niepotwierdzone) listy etykiet portów.
    Potwierdzone = widoczne po obu stronach (OUT u klienta i IN u serwera)."""
    g = defaultdict(lambda: ([], []))
    for (s, d, proto, port), e in sorted(edges.items()):
        g[(s, d)][0 if e["sides"] == {"OUT", "IN"} else 1].append(svc(proto, port))
    return g


def write_mermaid(path, groups, audited):
    ids = {}
    nid = lambda n: ids.setdefault(n, f"n{len(ids)}")
    q = lambda s: s.replace('"', "'")
    lines = ["flowchart LR"]
    for (s, d), (ok, maybe) in groups.items():
        for items, arrow in ((ok, "-->"), (maybe, "-.->")):
            if items:
                lines.append(f'  {nid(s)} {arrow}|"{q("<br/>".join(items))}"| {nid(d)}')
    for n, i in ids.items():
        lines.insert(1, f'  {i}["{q(n)}"]' if n in audited else f'  {i}(["{q(n)}"])')
    lines.append("  classDef ext stroke-dasharray: 4 3,fill:#f5f5f5,color:#555")
    unk = [i for n, i in ids.items() if n not in audited]
    if unk:
        lines.append("  class " + ",".join(unk) + " ext")
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")


def write_markdown(path, mmd_path):
    """map.md: gotowy do wrzucenia do repozytorium / wiki GitLaba (blok ```mermaid renderuje się sam)."""
    diagram = open(mmd_path, encoding="utf-8-sig").read()
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Mapa połączeń między serwerami\n\nWygenerowano: {date.today()}. "
                "Linia ciągła = połączenie widoczne po obu stronach, przerywana = tylko z jednej strony "
                "(brak audytu celu, load balancer lub NAT po drodze).\n\n```mermaid\n" + diagram + "```\n")



def node_meta(servers, ipmap, names, nets, edges):
    """Węzły dla viewera: nazwa -> (rodzaj, adres IP do grupowania po podsieci)."""
    ips = {}
    for ip, h in sorted(ipmap.items(), key=lambda kv: (ipaddress.ip_address(kv[0]).version, int(ipaddress.ip_address(kv[0])))):
        ips.setdefault(h, ip)
    for ip, n in names.items():
        ips.setdefault(n, ip)
    for net, n in nets:
        ips.setdefault(n, str(net.network_address))
    named = set(names.values()) | {n for _, n in nets}
    ids = set(servers) | named | {x for k in edges for x in k[:2]}
    kind = lambda n: "host" if n in servers else ("named" if n in named else "unknown")
    return [{"id": n, "kind": kind(n), "ip": ips.get(n, "")} for n in sorted(ids)]


def write_html(path, edges, meta):
    """map.html: jeden samodzielny plik (bez internetu): układ sił, filtry portów, tryb 'wybrany host + sąsiedzi'."""
    data = {"generated": str(date.today()), "nodes": meta, "edges": [
        {"s": s, "d": d, "p": proto, "port": port, "svc": PORTS.get(port, ""), "ok": e["sides"] == {"OUT", "IN"},
         "n": e["n"], "c": sorted(e["client"]), "u": sorted(e["server"])}
        for (s, d, proto, port), e in sorted(edges.items())]}
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    with open(path, "w", encoding="utf-8") as f:
        f.write(VIEWER_HTML.replace("__DATA__", blob))


def write_dot(path, groups, audited):
    out = ["digraph conn {", "  rankdir=LR; node [shape=box, fontname=Helvetica]; edge [fontname=Helvetica, fontsize=10];"]
    nodes = {n for k in groups for n in k}
    for n in sorted(nodes):
        out.append(f'  "{n}"' + ('' if n in audited else ' [style="dashed,filled", fillcolor="#f5f5f5"]') + ";")
    for (s, d), (ok, maybe) in groups.items():
        for items, style in ((ok, "solid"), (maybe, "dashed")):
            if items:
                label = "\\n".join(items)
                out.append(f'  "{s}" -> "{d}" [label="{label}", style={style}];')
    out.append("}")
    open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")


def write_csv(path, edges):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["zrodlo", "cel", "proto", "port", "usluga", "potwierdzone", "wystapien",
                    "jednostki_klienta", "jednostki_serwera"])
        for (s, d, proto, port), e in sorted(edges.items()):
            w.writerow([s, d, proto, port or "", PORTS.get(port, ""), "tak" if e["sides"] == {"OUT", "IN"} else "nie",
                        e["n"], ";".join(sorted(e["client"])), ";".join(sorted(e["server"]))])


VIEWER_HTML = r'''<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mapa połączeń</title>
<style>
:root{--bg:#ffffff;--fg:#1f2328;--muted:#656d76;--line:#8c959f;--panel:#f6f8fa;--border:#d0d7de;--accent:#0969da;--ok:#1a7f37;--unk:#9aa4af}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--line:#6e7681;--panel:#161b22;--border:#30363d;--accent:#58a6ff;--ok:#3fb950;--unk:#6e7681}}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--fg);font:13px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;display:flex;flex-direction:column}
header{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;padding:8px 12px;border-bottom:1px solid var(--border);background:var(--panel)}
header strong{font-size:14px}
header label{display:inline-flex;gap:5px;align-items:center;white-space:nowrap}
input[type=search],select,button{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:4px 8px}
button{cursor:pointer}button:hover{border-color:var(--accent)}
#stats{color:var(--muted)}
#ports{display:flex;flex-wrap:wrap;gap:4px;padding:6px 12px;border-bottom:1px solid var(--border);max-height:76px;overflow:auto}
#ports .lbl0{color:var(--muted);align-self:center;margin-right:4px}
.chip{border:1px solid var(--border);border-radius:99px;padding:1px 9px;cursor:pointer;user-select:none;background:var(--bg)}
.chip small{color:var(--muted);margin-left:4px}
.chip.off{opacity:.45;text-decoration:line-through}
main{flex:1;display:flex;min-height:0}
#svg{flex:1;min-width:0;height:100%;cursor:grab;touch-action:none;background:var(--bg)}
#svg.pan{cursor:grabbing}
aside{width:340px;max-width:45vw;border-left:1px solid var(--border);background:var(--panel);overflow:auto;padding:10px 12px}
aside h3{margin:.2em 0 .4em;font-size:15px;word-break:break-all}
aside h4{margin:14px 0 4px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
aside table{width:100%;border-collapse:collapse}
aside td{padding:3px 4px;border-top:1px solid var(--border);vertical-align:top}
aside td.n{text-align:right;color:var(--muted);white-space:nowrap}
.peer{color:var(--accent);cursor:pointer;word-break:break-all}
.members .peer{word-break:normal;white-space:nowrap}.peer:hover{text-decoration:underline}
.muted{color:var(--muted)}.okmark{color:var(--ok);font-weight:600}
.sw{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:-1px}
.edge{fill:none;stroke:var(--line);stroke-opacity:.45;marker-end:url(#arr)}
.edge.dash{stroke-dasharray:5 4}
.node circle{stroke:var(--bg);stroke-width:1.5}
.node.unknown circle{fill:var(--bg)!important;stroke:var(--unk);stroke-width:1.6;stroke-dasharray:3 2}
.node.named circle{stroke:var(--fg);stroke-width:1.4}
.node{cursor:pointer}
.node text{font-size:10px;fill:var(--fg);paint-order:stroke;stroke:var(--bg);stroke-width:3px;pointer-events:none}
.arrow{fill:var(--line)}.arrow-hi{fill:var(--accent)}
.nolabels .node:not(.on):not(.sel) text{display:none}
.zlow .node.minor:not(.on):not(.sel) text{display:none}
.edges-hidden .edge:not(.on){display:none}
.node.group circle{stroke:var(--fg);stroke-width:1.2;fill-opacity:.85}
.node.group text{font-size:12px;font-weight:600}
.hl .edge:not(.on){opacity:.07}
.hl .node:not(.on){opacity:.22}
.edge.on{stroke:var(--accent);stroke-opacity:1;marker-end:url(#arrHi);stroke-width:2}
.node.sel circle{stroke:var(--accent);stroke-width:3}
.empty{color:var(--muted);padding:20px}
@media (max-width:800px){main{flex-direction:column}aside{width:100%;max-width:none;height:40%;border-left:0;border-top:1px solid var(--border)}}
</style>
</head>
<body>
<header>
  <strong>Mapa połączeń</strong><span id="stats"></span>
  <input id="q" type="search" list="names" placeholder="Szukaj hosta…" size="18" autocomplete="off">
  <datalist id="names"></datalist>
  <label>Widok
    <select id="view"><option value="hosts">hosty</option><option value="groups">grupy (zwinięte)</option></select></label>
  <label>Zakres
    <select id="scope"><option value="0">cały graf</option><option value="1">wybrany + sąsiedzi</option><option value="2">wybrany + 2 poziomy</option></select></label>
  <label>Kolory
    <select id="colorby"><option value="subnet">podsieć /24</option><option value="prefix">prefiks nazwy</option><option value="kind">audyt / nazwany / nieznany</option></select></label>
  <label><input type="checkbox" id="onlyok"> tylko potwierdzone</label>
  <label><input type="checkbox" id="hideunk"> ukryj nieznane</label>
  <label><input type="checkbox" id="hideiso" checked> ukryj bez połączeń</label>
  <label><input type="checkbox" id="hideedges"> krawędzie tylko po najechaniu</label>
  <button id="relayout" title="Przelicz układ od nowa">Przelicz układ</button>
  <button id="fit">Dopasuj widok</button>
</header>
<div id="ports"></div>
<main>
  <svg id="svg" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="userSpaceOnUse" markerWidth="9" markerHeight="9" orient="auto"><path d="M0 0L10 5L0 10z" class="arrow"/></marker>
      <marker id="arrHi" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="userSpaceOnUse" markerWidth="11" markerHeight="11" orient="auto"><path d="M0 0L10 5L0 10z" class="arrow-hi"/></marker>
    </defs>
    <g id="vp"><g id="eg"></g><g id="ng"></g></g>
  </svg>
  <aside id="panel"></aside>
</main>
<script>
(function(){
"use strict";
var DATA = __DATA__;
var NS = "http://www.w3.org/2000/svg";
var $ = function(id){ return document.getElementById(id); };
var svg = $("svg"), vp = $("vp"), eg = $("eg"), ng = $("ng"), panel = $("panel");
function el(name, attrs){ var e = document.createElementNS(NS, name); for (var k in attrs) e.setAttribute(k, attrs[k]); return e; }
function esc(s){ return String(s).replace(/[&<>"']/g, function(c){ return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]; }); }

var nodesById = new Map(DATA.nodes.map(function(n){ return [n.id, n]; }));
var state = { sel: null, hover: null, hidden: new Set() };
var pos = new Map();          // id -> {x,y,vx,vy,fx,fy}
var view = { k: 1, x: 0, y: 0 };
var cur = { nodes: [], pairs: [], adj: new Map(), nEl: new Map(), eEl: [], groups: new Map(), gc: new Map() };
var sim = { alpha: 0, raf: 0, autofit: false };

function kindOf(id){ var n = nodesById.get(id); return n ? n.kind : "unknown"; }
function ipOf(n){ if (n.ip) return n.ip; var m = n.id.match(/^(\d+\.\d+\.\d+\.\d+)/); return m ? m[1] : ""; }
function groupOf(n){
  var mode = $("colorby").value;
  if (mode === "kind") return n.kind === "host" ? "audyt" : (n.kind === "named" ? "nazwany" : "nieznany");
  if (mode === "prefix") return n.id.replace(/[-_.]?\d+$/, "") || n.id;
  var ip = ipOf(n);
  if (!ip) return "(brak IP)";
  if (ip.indexOf(":") >= 0) return ip.split(":").slice(0, 4).join(":") + "::/64";
  return ip.split(".").slice(0, 3).join(".") + ".0/24";
}
function hue(s){ var h = 5381; for (var i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0; return Math.abs(h) % 360; }
function colorOf(g){
  if (g === "nieznany") return "var(--unk)";
  if (g === "(brak IP)") return "hsl(0 0% 55%)";
  return "hsl(" + hue(g) + " 62% 50%)";
}
function svcLabel(e){ return e.port ? (e.port + "/" + e.p + (e.svc ? " " + e.svc : "")) : e.p; }

/* ---------- widok zwinięty do grup ---------- */
function isGrouped(){ return $("view").value === "groups"; }
function gid(id){ var n = nodesById.get(id); return n ? groupOf(n) : "?"; }
function viewEdges(){
  var es = visibleEdges();
  if (!isGrouped()) return es;
  var m = new Map();
  es.forEach(function(e){
    var s = gid(e.s), d = gid(e.d);
    if (s === d) return;
    var k = s + "\u0001" + d + "\u0001" + e.p + "\u0001" + e.port, a = m.get(k);
    if (!a){ a = { s: s, d: d, p: e.p, port: e.port, svc: e.svc, ok: false, n: 0, c: [], u: [] }; m.set(k, a); }
    a.n += e.n; a.ok = a.ok || e.ok;
    e.c.forEach(function(x){ if (a.c.indexOf(x) < 0) a.c.push(x); });
    e.u.forEach(function(x){ if (a.u.indexOf(x) < 0) a.u.push(x); });
  });
  return Array.from(m.values());
}
function groupNodes(){
  var m = new Map(), hideUnk = $("hideunk").checked;
  DATA.nodes.forEach(function(n){
    if (hideUnk && n.kind === "unknown") return;
    var g = groupOf(n), o = m.get(g);
    if (!o){ o = { id: g, kind: "group", ip: "", members: [] }; m.set(g, o); }
    o.members.push(n.id);
  });
  return m;
}

/* ---------- filtry ---------- */
function visibleEdges(){
  var onlyOk = $("onlyok").checked, hideUnk = $("hideunk").checked;
  return DATA.edges.filter(function(e){
    if (state.hidden.has(e.port + "/" + e.p)) return false;
    if (onlyOk && !e.ok) return false;
    if (hideUnk && (kindOf(e.s) === "unknown" || kindOf(e.d) === "unknown")) return false;
    return true;
  });
}

/* ---------- budowa grafu ---------- */
function rebuild(reheat){
  var hideUnk = $("hideunk").checked, hideIso = $("hideiso").checked;
  var grouped = isGrouped();
  var es = viewEdges();
  var nmap = grouped ? groupNodes() : nodesById;
  var ids = new Set();
  es.forEach(function(e){ ids.add(e.s); ids.add(e.d); });
  if (!hideIso) nmap.forEach(function(n, id){ if (!(hideUnk && n.kind === "unknown")) ids.add(id); });
  var depth = +$("scope").value;
  if (depth > 0 && state.sel && ids.has(state.sel)){
    var nb = new Map();
    es.forEach(function(e){
      if (!nb.has(e.s)) nb.set(e.s, new Set()); if (!nb.has(e.d)) nb.set(e.d, new Set());
      nb.get(e.s).add(e.d); nb.get(e.d).add(e.s);
    });
    var keep = new Set([state.sel]), front = [state.sel];
    for (var k = 0; k < depth; k++){
      var nx = [];
      front.forEach(function(x){ (nb.get(x) || []).forEach(function(y){ if (!keep.has(y)){ keep.add(y); nx.push(y); } }); });
      front = nx;
    }
    ids = keep;
  }
  var pairs = new Map();
  es.forEach(function(e){
    if (!ids.has(e.s) || !ids.has(e.d)) return;
    var key = e.s + "\u0001" + e.d, p = pairs.get(key);
    if (!p){ p = { s: e.s, d: e.d, items: [], n: 0, ok: false }; pairs.set(key, p); }
    p.items.push(e); p.n += e.n; p.ok = p.ok || e.ok;
  });
  var plist = Array.from(pairs.values());
  plist.forEach(function(p){ p.rev = pairs.has(p.d + "\u0001" + p.s); });

  var adj = new Map(), deg = new Map();
  ids.forEach(function(id){ adj.set(id, new Set()); deg.set(id, 0); });
  plist.forEach(function(p){
    adj.get(p.s).add(p.d); adj.get(p.d).add(p.s);
    deg.set(p.s, deg.get(p.s) + 1); deg.set(p.d, deg.get(p.d) + 1);
  });

  var nodes = Array.from(ids).map(function(id){ return nmap.get(id) || { id: id, kind: "unknown", ip: "" }; });
  var groups = new Map();
  nodes.forEach(function(n){ var g = grouped ? n.id : groupOf(n); n._g = g; n._deg = deg.get(n.id); groups.set(g, (groups.get(g) || 0) + 1); });
  var minDeg = 0;
  if (!grouped && nodes.length > 60){ var ds2 = nodes.map(function(n){ return n._deg; }).sort(function(a, b){ return a - b; }); minDeg = ds2[Math.floor(ds2.length * 0.75)]; }
  nodes.forEach(function(n){ n._minor = n._deg < minDeg; });
  plist.forEach(function(p){
    var ds = deg.get(p.s), dt = deg.get(p.d);
    p._same = nmap.get(p.s)._g === nmap.get(p.d)._g;
    p._str = 1 / Math.min(ds, dt); p._bs = dt / (ds + dt); p._bt = ds / (ds + dt);
  });
  var gnames = Array.from(groups.keys()).sort(function(a, b){ return groups.get(b) - groups.get(a) || (a < b ? -1 : 1); });
  var gc = new Map();
  var spread = 40 * Math.sqrt(nodes.length / Math.max(1, gnames.length)) + 70;
  gnames.forEach(function(g, i){
    var a = i * 2.399963, r = spread * Math.sqrt(i + 0.5);
    gc.set(g, { x: Math.cos(a) * r, y: Math.sin(a) * r });
  });
  nodes.forEach(function(n){
    if (!pos.has(n.id)){
      var c = gc.get(n._g);
      var j = 40 + 9 * Math.sqrt(cur.groups ? 1 : 1) * Math.sqrt(groups.get(n._g));
      pos.set(n.id, { x: c.x + (Math.random() - .5) * j, y: c.y + (Math.random() - .5) * j, vx: 0, vy: 0, fx: null, fy: null });
    }
  });

  cur = { nodes: nodes, pairs: plist, adj: adj, nEl: new Map(), eEl: [], groups: groups, gc: gc, gnames: gnames, nmap: nmap, grouped: grouped };

  while (eg.firstChild) eg.removeChild(eg.firstChild);
  while (ng.firstChild) ng.removeChild(ng.firstChild);
  plist.forEach(function(p){
    var path = el("path", { "class": "edge" + (p.ok ? "" : " dash"), "stroke-width": Math.min(2.6, 0.7 + 0.45 * Math.log10(p.n + 1)).toFixed(2) });
    var t = el("title", {});
    t.textContent = p.s + " \u2192 " + p.d + "\n" + p.items.map(function(e){ return svcLabel(e) + (e.ok ? " \u2713" : "") + "  (" + e.n + ")"; }).join("\n");
    path.appendChild(t); eg.appendChild(path); cur.eEl.push(path); p._el = path;
  });
  nodes.forEach(function(n){
    var r = grouped ? 9 + 2.4 * Math.sqrt(n.members.length) : 5 + Math.min(10, 1.6 * Math.sqrt(n._deg));
    n._r = r;
    var g = el("g", { "class": "node " + n.kind + (n._minor ? " minor" : "") });
    var c = el("circle", { r: r, fill: colorOf(n._g) });
    var tx = el("text", { x: r + 3, y: 3 }); tx.textContent = grouped ? n.id + " (" + n.members.length + ")" : n.id;
    var tt = el("title", {}); tt.textContent = grouped ? n.id + "\n" + n.members.length + " hostów" : n.id + (n.ip ? "\n" + n.ip : "") + "\n" + n._g;
    g.appendChild(c); g.appendChild(tx); g.appendChild(tt); ng.appendChild(g);
    cur.nEl.set(n.id, g);
    attachNode(g, n);
  });

  svg.classList.toggle("edges-hidden", $("hideedges").checked);
  $("stats").textContent = nodes.length + (grouped ? " grup" : " hostów") + " \u00b7 " + plist.length + " par \u00b7 " + plist.reduce(function(s, p){ return s + p.items.length; }, 0) + " portów";
  applyClasses();
  renderPanel();
  if (reheat !== false) startSim(typeof reheat === "number" ? reheat : 0.5);
  else draw();
}

/* ---------- symulacja sił ---------- */
function startSim(alpha){
  sim.alpha = Math.max(sim.alpha, alpha);
  if (!sim.raf) sim.raf = requestAnimationFrame(frame);
}
function frame(){
  sim.raf = 0;
  for (var i = 0; i < 3 && sim.alpha > 0.004; i++) tick();
  draw();
  if (sim.alpha > 0.004) sim.raf = requestAnimationFrame(frame);
  else if (sim.autofit){ sim.autofit = false; fit(); }
}
function tick(){
  var ns = cur.nodes, a = sim.alpha, n = ns.length, i, j;
  var P = ns.map(function(x){ return pos.get(x.id); });
  for (i = 0; i < n; i++){
    var p = P[i];
    for (j = i + 1; j < n; j++){
      var q = P[j], dx = p.x - q.x, dy = p.y - q.y, d2 = dx * dx + dy * dy;
      if (d2 < 1){ dx = Math.random() - .5; dy = Math.random() - .5; d2 = 1; }
      if (d2 > (cur.grouped ? 640000 : 250000)) continue;
      var w = (cur.grouped ? 1500 : 140) * a / Math.max(d2, 100);
      p.vx += dx * w; p.vy += dy * w; q.vx -= dx * w; q.vy -= dy * w;
    }
  }
  cur.pairs.forEach(function(l){
    var s = pos.get(l.s), t = pos.get(l.d);
    var dx = t.x - s.x, dy = t.y - s.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
    var target = cur.grouped ? 260 : (l._same ? 55 : 120);
    var f = (d - target) / d * a * l._str;
    dx *= f; dy *= f;
    s.vx += dx * l._bs; s.vy += dy * l._bs; t.vx -= dx * l._bt; t.vy -= dy * l._bt;
  });
  ns.forEach(function(nd, k){
    var p = P[k], c = cur.gc.get(nd._g);
    var gw = cur.grouped ? 0.012 : 0.09;
    p.vx += (c.x - p.x) * gw * a; p.vy += (c.y - p.y) * gw * a;
    p.vx -= p.x * 0.004 * a; p.vy -= p.y * 0.004 * a;
  });
  P.forEach(function(p){
    if (p.fx !== null){ p.x = p.fx; p.y = p.fy; p.vx = p.vy = 0; return; }
    p.vx *= 0.6; p.vy *= 0.6;
    var sp = Math.sqrt(p.vx * p.vx + p.vy * p.vy);
    if (sp > 60){ p.vx *= 60 / sp; p.vy *= 60 / sp; }
    p.x += p.vx; p.y += p.vy;
  });
  sim.alpha += (0 - sim.alpha) * 0.0228;
}

/* ---------- rysowanie ---------- */
function draw(){
  cur.nodes.forEach(function(n){
    var p = pos.get(n.id);
    cur.nEl.get(n.id).setAttribute("transform", "translate(" + p.x.toFixed(1) + "," + p.y.toFixed(1) + ")");
  });
  cur.pairs.forEach(function(p){
    var a = pos.get(p.s), b = pos.get(p.d);
    var dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1, ux = dx / d, uy = dy / d;
    var ra = cur.nmap.get(p.s) ? cur.nmap.get(p.s)._r : 6, rb = (cur.nmap.get(p.d) ? cur.nmap.get(p.d)._r : 6) + 3;
    var x1 = a.x + ux * ra, y1 = a.y + uy * ra, x2 = b.x - ux * rb, y2 = b.y - uy * rb;
    var off = p.rev ? 14 : 0, mx = (x1 + x2) / 2 - uy * off, my = (y1 + y2) / 2 + ux * off;
    p._el.setAttribute("d", "M" + x1.toFixed(1) + "," + y1.toFixed(1) + " Q" + mx.toFixed(1) + "," + my.toFixed(1) + " " + x2.toFixed(1) + "," + y2.toFixed(1));
  });
}
function applyView(){
  vp.setAttribute("transform", "translate(" + view.x.toFixed(1) + "," + view.y.toFixed(1) + ") scale(" + view.k.toFixed(3) + ")");
  svg.classList.toggle("nolabels", view.k < 0.4);
  svg.classList.toggle("zlow", view.k < 1.15);
}
function fit(){
  if (!cur.nodes.length) return;
  var x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9;
  cur.nodes.forEach(function(n){ var p = pos.get(n.id); x0 = Math.min(x0, p.x); y0 = Math.min(y0, p.y); x1 = Math.max(x1, p.x); y1 = Math.max(y1, p.y); });
  var w = svg.clientWidth || 800, h = svg.clientHeight || 600, bw = Math.max(1, x1 - x0) + (cur.grouped ? 300 : 140), bh = Math.max(1, y1 - y0) + 80;
  view.k = Math.min(w / bw, h / bh, 2);
  view.x = w / 2 - (x0 + x1) / 2 * view.k; view.y = h / 2 - (y0 + y1) / 2 * view.k;
  applyView();
}

/* ---------- wyróżnianie ---------- */
function applyClasses(){
  var f = state.hover || state.sel;
  svg.classList.toggle("hl", !!(f && cur.adj.has(f)));
  cur.nEl.forEach(function(g, id){
    var on = !!f && cur.adj.has(f) && (id === f || cur.adj.get(f).has(id));
    g.classList.toggle("on", on); g.classList.toggle("sel", id === state.sel);
  });
  cur.pairs.forEach(function(p){ p._el.classList.toggle("on", !!f && (p.s === f || p.d === f)); });
}

/* ---------- interakcje ---------- */
function attachNode(g, n){
  var drag = null;
  g.addEventListener("pointerenter", function(){ state.hover = n.id; applyClasses(); });
  g.addEventListener("pointerleave", function(){ state.hover = null; applyClasses(); });
  g.addEventListener("pointerdown", function(ev){
    ev.stopPropagation(); g.setPointerCapture(ev.pointerId);
    drag = { x: ev.clientX, y: ev.clientY, moved: false };
  });
  g.addEventListener("pointermove", function(ev){
    if (!drag) return;
    if (Math.abs(ev.clientX - drag.x) + Math.abs(ev.clientY - drag.y) > 3) drag.moved = true;
    if (!drag.moved) return;
    var r = svg.getBoundingClientRect(), p = pos.get(n.id);
    p.fx = (ev.clientX - r.left - view.x) / view.k; p.fy = (ev.clientY - r.top - view.y) / view.k;
    p.x = p.fx; p.y = p.fy; startSim(0.25); draw();
  });
  g.addEventListener("pointerup", function(){
    var p = pos.get(n.id);
    if (drag && !drag.moved) select(n.id); else { p.fx = p.fy = null; }
    drag = null;
  });
}
var panning = null;
svg.addEventListener("pointerdown", function(ev){
  panning = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y, moved: false };
  svg.setPointerCapture(ev.pointerId); svg.classList.add("pan");
});
svg.addEventListener("pointermove", function(ev){
  if (!panning) return;
  var dx = ev.clientX - panning.x, dy = ev.clientY - panning.y;
  if (Math.abs(dx) + Math.abs(dy) > 3) panning.moved = true;
  view.x = panning.vx + dx; view.y = panning.vy + dy; applyView();
});
svg.addEventListener("pointerup", function(){
  if (panning && !panning.moved && state.sel) select(null);
  panning = null; svg.classList.remove("pan");
});
svg.addEventListener("wheel", function(ev){
  ev.preventDefault();
  var r = svg.getBoundingClientRect(), mx = ev.clientX - r.left, my = ev.clientY - r.top;
  var k2 = Math.max(0.1, Math.min(6, view.k * Math.exp(-ev.deltaY * 0.0015)));
  view.x = mx - (mx - view.x) * (k2 / view.k); view.y = my - (my - view.y) * (k2 / view.k); view.k = k2; applyView();
}, { passive: false });

function select(id){
  state.sel = id;
  $("q").value = id || "";
  if (+$("scope").value > 0) rebuild(0.6); else { applyClasses(); renderPanel(); }
}
function drill(hostId){          // przejście z widoku grup do konkretnego hosta
  $("view").value = "hosts"; $("scope").value = "1"; state.sel = hostId; $("q").value = hostId;
  pos.clear(); sim.autofit = true; rebuild(1);
}
function goTo(id){               // wyszukiwarka: host w widoku grup otwiera widok hostów
  if (!nodesById.has(id)) return;
  if (isGrouped()){ drill(id); return; }
  select(id); if (cur.nEl.has(id)) centerOn(id);
}
function centerOn(id){
  var p = pos.get(id); if (!p) return;
  var w = svg.clientWidth, h = svg.clientHeight;
  if (view.k < 0.8) view.k = 1;
  view.x = w / 2 - p.x * view.k; view.y = h / 2 - p.y * view.k; applyView();
}

/* ---------- panel boczny ---------- */
function group(list, key){
  var m = new Map();
  list.forEach(function(e){ var k = e[key]; if (!m.has(k)) m.set(k, []); m.get(k).push(e); });
  return m;
}
function peerRows(items, peerKey, unitKey){
  var rows = Array.from(group(items, peerKey).entries()).map(function(kv){
    var es = kv[1].slice().sort(function(a, b){ return b.n - a.n; });
    var units = new Set(); es.forEach(function(e){ (e[unitKey] || []).forEach(function(u){ units.add(u); }); });
    return { peer: kv[0], es: es, n: es.reduce(function(s, e){ return s + e.n; }, 0), units: Array.from(units) };
  }).sort(function(a, b){ return b.n - a.n; });
  if (!rows.length) return '<p class="muted">brak</p>';
  return "<table>" + rows.map(function(r){
    var ports = r.es.map(function(e){ return esc(svcLabel(e)) + (e.ok ? ' <span class="okmark" title="widoczne po obu stronach">\u2713</span>' : ""); }).join("<br>");
    return '<tr><td><span class="peer" data-id="' + esc(r.peer) + '">' + esc(r.peer) + "</span>" +
      (r.units.length ? '<br><span class="muted">' + esc(r.units.join(", ")) + "</span>" : "") +
      "</td><td>" + ports + '</td><td class="n">' + r.n + "</td></tr>";
  }).join("") + "</table>";
}
function renderPanel(){
  var id = state.sel, html = "";
  if (id && cur.nmap.has(id)){
    var n = cur.nmap.get(id), es = viewEdges();
    var out = es.filter(function(e){ return e.s === id; }), inc = es.filter(function(e){ return e.d === id; });
    html += "<h3>" + esc(id) + "</h3><div class='muted'>" + (n.kind === "group" ? n.members.length + " hostów w grupie" : esc(n.ip || "") + " \u00b7 " +
      (n.kind === "host" ? "serwer z audytem" : n.kind === "named" ? "nazwany w pliku --hosts" : "nieznany")) + "</div>";
    if (n.kind === "group"){
      html += "<h4>Hosty w grupie (klik = pokaż jego połączenia)</h4><p class='members'>" + n.members.slice(0, 120).map(function(m){
        return '<span class="peer" data-host="' + esc(m) + '">' + esc(m) + "</span>"; }).join(", ") + (n.members.length > 120 ? " \u2026" : "") + "</p>";
    }
    html += "<h4>Wychodzące (" + new Set(out.map(function(e){ return e.d; })).size + ")</h4>" + peerRows(out, "d", "c");
    html += "<h4>Przychodzące (" + new Set(inc.map(function(e){ return e.s; })).size + ")</h4>" + peerRows(inc, "s", "u");
    html += "<p class='muted'>Jednostki pod hostem to usługi/procesy po stronie wybranego serwera. \u2713 = połączenie widoczne po obu stronach.</p>";
  } else {
    html += "<h3>Przegląd</h3><div class='muted'>Kliknij węzeł, aby zobaczyć jego połączenia. Kółko myszy = zoom, przeciąganie tła = przesuwanie, przeciąganie węzła = przestawienie.</div>";
    html += "<h4>Grupy (" + cur.gnames.length + ")</h4><table>" + cur.gnames.slice(0, 25).map(function(g){
      return '<tr><td><span class="sw" style="background:' + colorOf(g) + '"></span>' + esc(g) + '</td><td class="n">' + (cur.grouped ? cur.nmap.get(g).members.length : cur.groups.get(g)) + "</td></tr>";
    }).join("") + "</table>";
    var top = cur.nodes.slice().sort(function(a, b){ return b._deg - a._deg; }).slice(0, 12);
    html += "<h4>Najwięcej połączeń</h4><table>" + top.map(function(x){
      return '<tr><td><span class="peer" data-id="' + esc(x.id) + '">' + esc(x.id) + '</span></td><td class="n">' + x._deg + "</td></tr>";
    }).join("") + "</table>";
    html += "<p class='muted'>Wygenerowano: " + esc(DATA.generated) + "</p>";
  }
  panel.innerHTML = html;
}
panel.addEventListener("click", function(ev){
  var t = ev.target.closest(".peer");
  if (!t) return;
  if (t.hasAttribute("data-host")){ drill(t.getAttribute("data-host")); return; }
  var id = t.getAttribute("data-id"); select(id); if (cur.nEl.has(id)) centerOn(id);
});

/* ---------- sterowanie ---------- */
(function initControls(){
  var dl = $("names");
  DATA.nodes.slice().sort(function(a, b){ return a.id < b.id ? -1 : 1; }).forEach(function(n){
    var o = document.createElement("option"); o.value = n.id; dl.appendChild(o);
  });
  var cnt = new Map();
  DATA.edges.forEach(function(e){ var k = e.port + "/" + e.p; cnt.set(k, (cnt.get(k) || 0) + 1); });
  var box = $("ports"), lab = document.createElement("span"); lab.className = "lbl0"; lab.textContent = "Porty (klik = ukryj):"; box.appendChild(lab);
  Array.from(cnt.entries()).sort(function(a, b){ return b[1] - a[1]; }).slice(0, 60).forEach(function(kv){
    var sample = DATA.edges.find(function(e){ return e.port + "/" + e.p === kv[0]; });
    var c = document.createElement("span"); c.className = "chip";
    c.innerHTML = esc(sample.port ? sample.port + "/" + sample.p : sample.p) + (sample.svc ? " " + esc(sample.svc) : "") + "<small>" + kv[1] + "</small>";
    c.addEventListener("click", function(){
      if (state.hidden.has(kv[0])) state.hidden.delete(kv[0]); else state.hidden.add(kv[0]);
      c.classList.toggle("off", state.hidden.has(kv[0])); rebuild(0.3);
    });
    box.appendChild(c);
  });
  if (!cnt.size) box.style.display = "none";
  ["onlyok", "hideunk", "hideiso", "scope", "hideedges"].forEach(function(i){ $(i).addEventListener("change", function(){ rebuild(0.5); }); });
  $("view").addEventListener("change", function(){ state.sel = null; $("q").value = ""; pos.clear(); sim.autofit = true; rebuild(1); });
  $("colorby").addEventListener("change", function(){ rebuild(0.8); });
  $("relayout").addEventListener("click", function(){ pos.clear(); sim.autofit = true; rebuild(1); });
  $("fit").addEventListener("click", fit);
  $("q").addEventListener("input", function(){
    var v = this.value.trim(); if (nodesById.has(v)) goTo(v);
  });
  $("q").addEventListener("keydown", function(ev){
    if (ev.key !== "Enter") return;
    var v = this.value.trim().toLowerCase(); if (!v) return;
    var m = DATA.nodes.find(function(n){ return n.id.toLowerCase().indexOf(v) >= 0; });
    if (m) goTo(m.id);
  });
  document.addEventListener("keydown", function(ev){ if (ev.key === "Escape" && state.sel) select(null); });
  window.addEventListener("resize", fit);
})();

if (!DATA.edges.length){
  document.querySelector("main").innerHTML = '<div class="empty">Brak połączeń do pokazania (sprawdź --skip-ports / --min / --unknown).</div>';
} else {
  if (DATA.nodes.length > 60) $("view").value = "groups";     // duże środowisko: zacznij od przeglądu grup
  sim.autofit = true;
  rebuild(1);
  applyView();
}
window.__map = { state: state, cur: function(){ return cur; }, sim: sim, select: select, rebuild: rebuild };
})();
</script>
</body>
</html>
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", help="katalog z wynikami (przeszukiwany rekurencyjnie)")
    ap.add_argument("-o", "--out", help="katalog wyjściowy (domyślnie: root)")
    ap.add_argument("--hosts", help="plik 'ip nazwa' lub 'podsieć/CIDR nazwa' dla serwerów bez audytu (LB, bazy, DNS...)")
    ap.add_argument("--skip-ports", default="", help="porty do pominięcia, np. 22,53,123,9100")
    ap.add_argument("--unknown", choices=["subnet", "show", "hide"], default="subnet",
                    help="nieznane adresy: grupuj w /24 (domyślnie), pokaż każdy, ukryj")
    ap.add_argument("--min", type=int, default=1, help="minimalna liczba wystąpień wpisu")
    args = ap.parse_args()
    args.skip = {p.strip() for p in args.skip_ports.split(",") if p.strip()}

    servers, ipmap, dup = load_inventory(args.root)
    if not servers:
        sys.exit("Nie znaleziono żadnego info.txt w " + args.root)
    names, nets = load_names(args.hosts)
    edges = build_edges(servers, ipmap, names, nets, args)
    groups = split_groups(edges)
    out = args.out or args.root
    os.makedirs(out, exist_ok=True)
    audited = set(servers) | set(names.values()) | {n for _, n in nets}
    write_mermaid(os.path.join(out, "map.mmd"), groups, audited)
    write_markdown(os.path.join(out, "map.md"), os.path.join(out, "map.mmd"))
    write_dot(os.path.join(out, "map.dot"), groups, audited)
    write_html(os.path.join(out, "map.html"), edges, node_meta(servers, ipmap, names, nets, edges))
    write_csv(os.path.join(out, "edges.csv"), edges)
    conf = sum(1 for e in edges.values() if e["sides"] == {"OUT", "IN"})
    print(f"Serwery z audytem: {len(servers)}; połączeń: {len(edges)} (potwierdzonych z obu stron: {conf})")
    if dup:
        print("Pominięto adresy IP występujące na wielu hostach:", ", ".join(sorted(dup)))
    print("Zapisano map.html, map.md, map.mmd, map.dot, edges.csv w", out)


if __name__ == "__main__":
    main()
