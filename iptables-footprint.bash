#! /bin/bash
# CLEAR=1 ./iptables-footprint.bash icmp and dst host 10.1.1.1

function foreach_chain() {
    action=$1
    for iptables in iptables ip6tables; do
        for table in $($iptables-save | grep '^\*'); do
            table=${table##\*}
            for chain in $($iptables-save -t $table | awk '$1 ~ /^:/ {print $1}'); do
                chain=${chain##:}
                count=$($iptables-save -t $table | grep -c -- "-A $chain")
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
    while IFS= read -r line; do
        echo "$iptables -t $table -D ${line#* }"
        eval "$iptables -t $table -D ${line#* }"
    done < <($iptables-save -t $table | grep -- "-A $chain.*-j LOG ")
}

if [[ "$CLEAR" == 1 ]]; then
    foreach_chain clear_log
    exit 0
fi

bpf_bytecode=$(while IFS= read -r line; do
    [[ "$need_comma" == 1 ]] && echo -n ","
    echo -n "$line"
    need_comma=1
done < <(tcpdump -ddd $@))

function insert_log() {
    iptables=$1
    table=$2
    chain=$3
    count=$4
    for i in $(seq 1 $count); do
        echo $iptables -t $table -I $chain $((i*2-1)) -m bpf --bytecode "$bpf_bytecode" -j LOG --log-prefix "${iptables:0:3}/$table/$chain/$i: "
        $iptables -t $table -I $chain $((i*2-1)) -m bpf --bytecode "$bpf_bytecode" -j LOG --log-prefix "${iptables:0:3}/$table/$chain/$i: "
    done
}

foreach_chain insert_log
