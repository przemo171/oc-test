#!/usr/bin/env python3
"""conn-map.py - łączy wyniki conn-audit.sh z wielu serwerów w mapę połączeń.

Oczekiwany układ (jeden katalog wynikowy conn-audit.sh na serwer, nazwy dowolne):
    audyty/web01/{info.txt,summary.tsv,conntrack.tsv}
    audyty/app01/{info.txt,summary.tsv}
    ...
Użycie:
    python3 conn-map.py audyty [-o wyjscie] [--hosts hosts.txt] [--skip-ports 22,53,123]
                               [--unknown subnet|show|hide] [--min 1]
Wynik: map.mmd (Mermaid), map.dot (Graphviz), edges.csv (lista połączeń)
"""
import argparse, csv, ipaddress, os, sys
from collections import defaultdict

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
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.startswith("host:"):
            host = line.split(":", 1)[1].strip().split(".")[0]
        elif line.startswith("lokalne_ip:"):
            ips = [i for i in line.split(":", 1)[1].strip().split(",") if i]
    return host, ips


def rows(path):
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
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
        for line in open(path, encoding="utf-8"):
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
                    e = edges.setdefault((src, dst, r["proto"], int(port)),
                                         {"sides": set(), "n": 0, "client": set(), "server": set()})
                    e["sides"].add(kind)
                    e["n"] = max(e["n"], n)
                    unit = r.get("jednostka") or "-"
                    if unit != "-":
                        e["client" if kind == "OUT" else "server"].add(unit)
    return edges


def svc(proto, port):
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
            w.writerow([s, d, proto, port, PORTS.get(port, ""), "tak" if e["sides"] == {"OUT", "IN"} else "nie",
                        e["n"], ";".join(sorted(e["client"])), ";".join(sorted(e["server"]))])


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
    write_dot(os.path.join(out, "map.dot"), groups, audited)
    write_csv(os.path.join(out, "edges.csv"), edges)
    conf = sum(1 for e in edges.values() if e["sides"] == {"OUT", "IN"})
    print(f"Serwery z audytem: {len(servers)}; połączeń: {len(edges)} (potwierdzonych z obu stron: {conf})")
    if dup:
        print("Pominięto adresy IP występujące na wielu hostach:", ", ".join(sorted(dup)))
    print("Zapisano map.mmd, map.dot, edges.csv w", out)


if __name__ == "__main__":
    main()
