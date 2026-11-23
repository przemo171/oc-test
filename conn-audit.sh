#!/usr/bin/env bash
# conn-audit.sh - audyt połączeń sieciowych serwera (bez agentów, tylko ss + opcjonalnie conntrack)
#
# Użycie:  sudo ./conn-audit.sh [-i interwał_s] [-d czas_s] [-o katalog] [-l]
#   -i  co ile sekund próbkować (domyślnie 2)
#   -d  łączny czas działania w sekundach (domyślnie: do Ctrl+C / SIGTERM)
#   -o  katalog wyjściowy (domyślnie /var/tmp/conn-audit-<host>-<data>)
#   -l  uwzględnij ruch loopback (domyślnie pomijany)
#
# Wynik:  <katalog>/summary.tsv  (+ summary.txt)  - unikalne połączenia: kierunek, port, adres, proces
#         <katalog>/conntrack.tsv                  - (opcjonalnie) nowe przepływy z conntrack, łapie też krótkie połączenia i UDP
#         <katalog>/info.txt                       - metadane (host, adresy IP, czas startu/końca)
# IN  = ktoś łączy się DO tego serwera na lokalny port (port_lokalny)
# OUT = ten serwer łączy się DO kogoś (adres_zdalny:port_zdalny)

INTERVAL=2; DURATION=0; INCL_LO=0
OUTDIR="/var/tmp/conn-audit-$(hostname -s)-$(date +%Y%m%d-%H%M%S)"
while getopts "i:d:o:l" o; do
  case $o in
    i) INTERVAL=$OPTARG ;;
    d) DURATION=$OPTARG ;;
    o) OUTDIR=$OPTARG ;;
    l) INCL_LO=1 ;;
    *) sed -n '2,15p' "$0"; exit 1 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Uruchom jako root (potrzebne do nazw procesów)." >&2; exit 1; }
command -v ss >/dev/null || { echo "Brak polecenia ss (pakiet iproute)." >&2; exit 1; }
mkdir -p "$OUTDIR" || exit 1
SUMMARY="$OUTDIR/summary.tsv"
LIPS=$(ip -o addr show | awk '{split($4,a,"/"); print a[1]}' | paste -sd,)
{ echo "host: $(hostname -f 2>/dev/null || hostname)"; echo "start: $(date '+%F %T %z')"
  echo "interval: ${INTERVAL}s"; echo "lokalne_ip: $LIPS"; uname -r; } > "$OUTDIR/info.txt"

declare -A CNT FIRST LAST MAXC LABEL

pid_label() {   # jednostka systemd + wskazówka z cmdline (ważne dla wielu procesów "java")
  local pid=$1 unit cmd hint
  unit=$(grep -oE '[^/]+\.(service|scope)' "/proc/$pid/cgroup" 2>/dev/null | tail -1)
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
  hint=$(grep -oE -- '-jar [^ ]+|-Dcatalina\.base=[^ ]+|-Djboss\.server\.base\.dir=[^ ]+' <<<"$cmd" | tr '\n' ' ')
  [[ -z $hint ]] && hint=${cmd:0:80}
  printf '%s\t%s' "${unit:--}" "${hint:-?}" | tr -s ' ' | tr -d '\r\n'
}

sample() {
  local ts dir proto lport rip rport pid name n label key
  printf -v ts '%(%F %T)T' -1
  { ss -H -ntap 2>/dev/null | sed 's/^/tcp /'; ss -H -nuap 2>/dev/null | sed 's/^/udp /'; } |
  awk -v INCL="$INCL_LO" '
    function hp(s,  i){ i=match(s,/:[^:]*$/); A=substr(s,1,i-1); P=substr(s,i+1)
                        gsub(/[\[\]]/,"",A); sub(/%.*/,"",A); sub(/^::ffff:/,"",A) }
    function pr(line,  t){ PN=""; PI=""
      if(match(line,/users:\(\("[^"]*",pid=[0-9]+/)){ t=substr(line,RSTART,RLENGTH)
        PN=t; sub(/^users:\(\("/,"",PN); sub(/",pid=.*/,"",PN); PI=t; sub(/.*pid=/,"",PI) } }
    { rows[NR]=$0 }
    END{
      for(r=1;r<=NR;r++){ split(rows[r],f," ")
        if(f[2]=="LISTEN" || (f[1]=="udp" && f[2]=="UNCONN")){
          hp(f[5]); k=f[1] "/" P; pr(rows[r]); LN[k]=PN; LP[k]=PI } }
      for(r=1;r<=NR;r++){ n=split(rows[r],f," ")
        if(n<6 || f[2]=="LISTEN" || (f[1]=="udp" && f[2]=="UNCONN")) continue
        hp(f[5]); lport=P; hp(f[6]); rip=A; rport=P
        if(rip=="*" || rport=="*" || rip=="") continue
        if(!INCL && (rip ~ /^127\./ || rip=="::1")) continue
        k=f[1] "/" lport; dir=(k in LN) ? "IN" : "OUT"
        pr(rows[r])
        if(PN=="" && dir=="IN"){ PN=LN[k]; PI=LP[k] }
        if(PN=="") PN="-"
        if(PI=="") PI="-"
        key=dir "\t" f[1] "\t" (dir=="IN"?lport:"-") "\t" rip "\t" (dir=="OUT"?rport:"-") "\t" PI "\t" PN
        c[key]++ }
      for(key in c) print key "\t" c[key] }' > "$OUTDIR/.sample"
  while IFS=$'\t' read -r dir proto lport rip rport pid name n; do
    label="-"$'\t'"-"
    if [[ $pid != - ]]; then
      [[ -z ${LABEL[$pid]+x} ]] && LABEL[$pid]=$(pid_label "$pid")
      label=${LABEL[$pid]}
    fi
    key="$dir"$'\t'"$proto"$'\t'"$lport"$'\t'"$rip"$'\t'"$rport"$'\t'"$name"$'\t'"$label"
    CNT[$key]=$(( ${CNT[$key]:-0} + 1 ))
    [[ -z ${FIRST[$key]+x} ]] && FIRST[$key]=$ts
    LAST[$key]=$ts
    (( n > ${MAXC[$key]:-0} )) && MAXC[$key]=$n
  done < "$OUTDIR/.sample"
}

dump() {
  { printf 'kierunek\tproto\tport_lokalny\tadres_zdalny\tport_zdalny\tproces\tjednostka\tkomenda\tprobek\tmax_jednoczesnych\tpierwszy\tostatni\n'
    for k in "${!CNT[@]}"; do
      printf '%s\t%s\t%s\t%s\t%s\n' "$k" "${CNT[$k]}" "${MAXC[$k]}" "${FIRST[$k]}" "${LAST[$k]}"
    done | sort -t$'\t' -k1,1 -k3,3 -k5,5 -k4,4
  } > "$SUMMARY.tmp" && mv "$SUMMARY.tmp" "$SUMMARY"
  command -v column >/dev/null && column -t -s$'\t' "$SUMMARY" > "$OUTDIR/summary.txt"
}

finalize() {
  trap - INT TERM
  [[ -n ${CT_PID:-} ]] && { kill "$CT_PID" 2>/dev/null; sleep 1; }
  dump; echo "stop: $(date '+%F %T %z')" >> "$OUTDIR/info.txt"
  rm -f "$OUTDIR/.sample"
  echo "Gotowe. Wyniki: $OUTDIR" >&2; exit 0
}

# opcjonalnie: conntrack łapie krótkie połączenia i UDP (DNS, NTP...), jeśli jest dostępny
if command -v conntrack >/dev/null && conntrack -C >/dev/null 2>&1; then
  conntrack -E -e NEW -o timestamp 2>/dev/null > >(gawk -v LIPS="$LIPS" -v OUTF="$OUTDIR/conntrack.tsv" '
    BEGIN{ n=split(LIPS,a,","); for(i=1;i<=n;i++) L[a[i]]=1; last=systime() }
    function dump(  k){ print "kierunek\tproto\tport_lokalny\tadres_zdalny\tport_zdalny\tnowych\tpierwszy\tostatni" > OUTF
      for(k in c) print k "\t" c[k] "\t" f[k] "\t" l[k] > OUTF; close(OUTF) }
    /\[NEW\]/ { proto="-"; s=d=sp=dp=""
      for(i=1;i<=NF;i++){
        if($i=="[NEW]") proto=$(i+1)
        else if($i~/^src=/ && s=="") s=substr($i,5)
        else if($i~/^dst=/ && d=="") d=substr($i,5)
        else if($i~/^dport=/ && dp=="") dp=substr($i,7) }
      if(s=="" || s~/^127\./ || d~/^127\./ || ((s in L) && (d in L))) next
      if(dp=="") dp="-"
      if(s in L)      k="OUT\t" proto "\t-\t" d "\t" dp
      else if(d in L) k="IN\t"  proto "\t" dp "\t" s "\t-"
      else            k="FWD\t" proto "\t-\t" s " -> " d "\t" dp
      c[k]++; t=strftime("%F %T"); if(!(k in f)) f[k]=t; l[k]=t
      if(systime()-last>=30){ dump(); last=systime() } }
    END{ dump() }') &
  CT_PID=$!
fi

trap finalize INT TERM
START=$SECONDS; LASTDUMP=$SECONDS
echo "Start audytu -> $OUTDIR (Ctrl+C lub SIGTERM kończy i zapisuje wynik)" >&2
while :; do
  sample
  (( SECONDS - LASTDUMP >= 60 )) && { dump; LASTDUMP=$SECONDS; }
  (( DURATION > 0 && SECONDS - START >= DURATION )) && break
  sleep "$INTERVAL"
done
finalize
