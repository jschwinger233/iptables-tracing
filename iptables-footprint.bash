#! /bin/bash -e
# CLEAR=1 ./iptables-footprint.bash icmp and dst host 10.1.1.1

bpf_bytecode=$(nfbpf_compile RAW "$@")

function foreach_chain() {
    action=$1
    for iptables in iptables ip6tables; do
        for table in $($iptables-save | grep '^\*'); do
            table=${table##\*}
            for chain in $($iptables-save -t $table | awk '$1 ~ /^:/ {print $1}'); do
                chain=${chain##:}
                count=$($iptables-save -t $table | grep -c -- "-A $chain\s" || true)
                [[ "$count" == 0 ]] && continue
                $action $iptables $table $chain $count
            done
        done
    done
}

function clear_log() {
    iptables=$1
    table=$2
    chain=$3
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
        for rule in ${rules["$line"]//,/ }; do
            echo $iptables -t $table -D $chain $rule
            $iptables -t $table -D $chain $rule
        done
        rules["$line"]=""
    done < <($iptables-save -t $table | tac | grep -- "-A $chain\s.*$bpf_bytecode")
}

if [[ "$CLEAR" == 1 ]]; then
    foreach_chain clear_log
    exit 0
fi

function insert_log() {
    iptables=$1
    table=$2
    chain=$3
    count=$4

    idx=1
    while IFS= read -r line; do
        line=${line#-A $chain }
        echo $iptables -t $table -I $chain $((idx*2-1)) -m bpf --bytecode \"$bpf_bytecode\" $line
        eval $iptables -t $table -I $chain $((idx*2-1)) -m bpf --bytecode \"$bpf_bytecode\" $line
        idx=$((idx+1))
    done < <($iptables-save -t $table | grep -- "^-A $chain\s")
}

foreach_chain insert_log
