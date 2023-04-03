#! /bin/bash -e
# IPV6=1 iptables-footprint.bash icmp and dst host 10.1.1.1
# we may want to run "sysctl -w net.netfilter.nf_log_all_netns=1" to log all namespaces

RED='\033[0;31m'
NC='\033[0m' # No Color

export iptables=iptables
if [[ -n "$IPV6" ]]; then
    export iptables=ip6tables
fi

bpf_bytecode=$(eval "nfbpf_compile RAW '$@'")

function foreach_chain() {
    action=$1
    for table in $($iptables-save | grep '^\*'); do
        table=${table##\*}
        for chain in $($iptables-save -t $table | awk '$1 ~ /^:/ {print $1}'); do
            chain=${chain##:}
            count=$($iptables-save -t $table | grep -c -- "-A $chain\s" || true)
            [[ "$count" == 0 ]] && continue
            $action $table $chain
        done
    done
}

function clear_log() {
    table=$1
    chain=$2

    declare -A rules
    idx=0
    while IFS= read -r line; do
        idx=$((idx+1))
        if [[ -z ${rules["$line"]} ]]; then
            rules["$line"]="$idx"
        else
            rules["$line"]="$idx,${rules["$line"]}"
        fi
    done < <($iptables-save -t $table | grep -- "-A $chain\s")

    while IFS= read -r line; do
        for idx in ${rules["$line"]//,/ }; do
            echo $iptables -t $table -D $chain $idx
            $iptables -t $table -D $chain $idx
        done
        rules["$line"]=""
    done < <($iptables-save -t $table | tac | grep -- "-A $chain\s.*$bpf_bytecode")
}

function insert_log() {
    table=$1
    chain=$2

    idx=1
    while IFS= read -r line; do
        line=${line%% -j *}
        line=${line%% -g *}
        line=${line#-A $chain } # would fail for bare '-A INPUT'
        line=${line#-A $chain} # doesn't have side effect if the previous one succeeds
        insert_idx=$((idx*2-1))
        echo $iptables -t $table -I $chain $insert_idx -m bpf --bytecode \"$bpf_bytecode\" $line -j LOG --log-prefix \"$insert_idx/$table/$chain\"
        eval $iptables -t $table -I $chain $insert_idx -m bpf --bytecode \"$bpf_bytecode\" $line -j LOG --log-prefix \"$insert_idx/$table/$chain\"
        ((idx++))
    done < <($iptables-save -t $table | grep -- "^-A $chain\s")
}

foreach_chain insert_log

function on_exit() {
    echo "Clearing log rules"
    foreach_chain clear_log
}
trap on_exit SIGINT

echo "tail -f /var/log/syslog"
while read line; do
    hit=$(echo $line | grep -Po '(?<= )[-\w]+/[-\w]+/[-\w]+?(?=IN=)' || true)
    [[ -z "$hit" ]] && continue
    echo "->$hit"
    IFS=/ read idx table chain <<<"$hit"
    chain=$($iptables-save -t $table | grep -Po "(?<=-A )$chain\S*" | sort -u)
    rule=$($iptables -t $table -L $chain $((idx+1)) | tr -s ' ')
    skb=$(echo $line | grep -Po 'IN=.*')
    echo -e "${RED}$rule${NC} hit by $skb"
done < <(tail -f /var/log/syslog) || true
