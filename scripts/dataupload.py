#!/usr/bin/env python3
import sys, gzip, json, ipaddress, re, pathlib
from typing import Dict, List, Any

"""
Number of most significant bits used to partition the lookup db. Each partition is stored as one key/value pair in
Cloudflare KV, with the key derived from these most significant bits, and the value being all the list of IP entries
inside that partition.

The same number of most significant bits of an incoming requests' are used to look up in the key

Example: a v4 prefix len of 8 means that all IPs that share the same first octet are bundled in one partition
"""
V4_PREFIX_LEN = 12
V6_PREFIX_LEN = 24


"""
Splits up all entries into ip partitions, with each partition containing all ip entries that have the same first n bits
(determined by V4_PREFIX_LEN or V6_PREFIX_LEN), and returns the partitions as an array of key/value pairs
"""
def create_kv_ip_partitions(entries):
    partitions = {}
    for entry in entries:
        start_ip = ipaddress.ip_address(entry["s"])
        start_ip_int = int(start_ip)
        partition_prefix_len = V4_PREFIX_LEN if start_ip.version == 4 else V6_PREFIX_LEN
        mask = int('1'*partition_prefix_len, 2)

        # part_start is the top n bits of the starting ip in this entry, right shifted to max
        part_start = (start_ip_int >> (start_ip.max_prefixlen - partition_prefix_len)) & mask
        end_ip = entry["e"] if start_ip.version == 4 else ipaddress.ip_address(v6_uncompress(entry["e"]))
        part_end = (int(end_ip) >> (start_ip.max_prefixlen - partition_prefix_len)) & mask # partition end

        # because start/end space may span boundary created by network_prefix_len, we need to make sure that
        # we're creating duplicate entries so that a lookup using network_prefix_len of an incoming request
        # succeeds.
        # e.g. if start/end are 1.0.0.0 and 1.1.0.0.0, when network_prefix_len=16, an incoming request from an IP
        # 1.1.1.1 needs to be able to find the lookup key corresponding to it
        for i in range(0, 1 + part_end - part_start):
            key = "m%d/v%d/%d" % (partition_prefix_len, start_ip.version, part_start+i)
            if key not in partitions:
                arr = []
                partitions[key] = arr
            else:
                arr = partitions[key]
            arr.append(entry)

    return sorted([{"key": k, "value": json.dumps(v, separators=(',', ':'))} for k, v in partitions.items()],
                  key=lambda x: int(x["key"].split("/")[2]))


"""
Creates a partition for every ASN, with each partition containing the list of all IP subnets against that AS
"""
def create_kv_asn_partitions(entries):
    partitions = {}
    for entry in entries:
        start_ip = str(ipaddress.ip_address(entry["s"]))
        end_ip   = str(ipaddress.ip_address(entry["e"] if '.' in start_ip else v6_uncompress(entry["e"])))
        asn      = entry["a"]
        country  = entry["c"]
        name     = entry["n"]
        key      = "asn/v1/%d" % asn

        if key in partitions:
            asn_obj = partitions[key]
        else:
            asn_obj = { "as": { "asn": asn, "country": country, "name": name }, "networks": [] }
            partitions[key] = asn_obj

        if asn_obj["as"]["name"] != name or asn_obj["as"]["country"] != country:
            print("mismatching in AS %d %s: %s != %s; %s != %s" %
                  (asn, start_ip, asn_obj["as"]["name"], name, asn_obj["as"]["country"], country), file=sys.stderr)
        asn_obj["networks"].append({ "start": start_ip, "end": end_ip })

    return sorted([{"key": k, "value": json.dumps(v, separators=(',', ':'))} for k, v in partitions.items()],
                  key=lambda x: int(x["key"].split("/")[2]))


"""
Reads a tsv file containing v4/v6 entries, and returns an array of entries.

IPv4 entries are a dict with keys:
    s: starting ip as u32
    e: ending ip as u32
    a: asn as int
    c: country
    n: AS name

IPv6 entries are a dict of:
    s: starting ip as str
    p: network prefix len
    a: asn as int
    c: country
    n: AS name
"""
def read_ip_db(tsv_file):
    opener = gzip.open if tsv_file.endswith(".gz") else open
    with opener(tsv_file, "rt") as f:
        entries = []
        for line in f.readlines():
            line = line.strip()
            arr = line.split('\t')
            if len(arr) != 5: continue
            asn = int(arr[2])
            if asn == 0: continue
            country = arr[3]
            name = arr[4]

            if ':' in arr[0]: # v6
                start = arr[0]
                end = v6_compress(arr[1])
                entries.append({"s":start, "e":end, "a":asn, "c":country, "n":name})
            else: # v4
                start = int(ipaddress.ip_address(arr[0]))
                end = int(ipaddress.ip_address(arr[1]))
                entries.append({"s":start, "e":end, "a":asn, "c":country, "n":name})

        return entries


"""
Compresses an IPv6 address that trails with :ffff
"""
def v6_compress(ip):
    return re.sub(r'(:ffff)+$', ':X', ip)


"""
Uncompresses an IPv6 address that may have been compressed
"""
def v6_uncompress(ip):
    return ip.replace('X', ':'.join(['ffff']*(8-ip.count(':'))))


"""
Helper function for testing
"""
def test_ip_lookup(ip_addr, partitions):
    ip = ipaddress.ip_address(ip_addr)
    prefix_len = (V4_PREFIX_LEN if ip.version == 4 else V6_PREFIX_LEN)
    ip_int = int(ip)
    key = "m%d/v%d/%d" % (prefix_len, ip.version, ip_int >> ((ip.max_prefixlen - prefix_len) & int('1'*prefix_len, 2)))
    for part in partitions:
        if part["key"] == key:
            arr = json.loads(part["value"])
            for e in arr:
                if ip.version == 4:
                    if e["s"] <= ip_int <= e["e"]:
                        return {"s":ipaddress.ip_address(e["s"]), "e":ipaddress.ip_address(e["e"]),
                                "a":e["a"], "c":e["c"], "n":e["n"]}
                else:
                    if int(ipaddress.ip_address(e["s"])) <= ip_int <= int(ipaddress.ip_address(v6_uncompress(e["e"]))):
                        return {"s":ipaddress.ip_address(e["s"]), "e":ipaddress.ip_address(v6_uncompress(e["e"])),
                                "a":e["a"], "c":e["c"], "n":e["n"]}


def write_kv_upload_file(partitions, name):
    with open(name, "w") as fp:
        json.dump(partitions, fp, separators=(',', ':'))
    print(f"{name} : wrote {len(partitions)} entries")


"""
Main entry point
"""
def main():
    if len(sys.argv) < 2:
        print("usage: %s <path/to/ip-db.tsv.gz> [... <db2.gz>]" % sys.argv[0], file=sys.stderr)
        sys.exit(1)

    ip_entries = [item for sublist in map(lambda tsv: read_ip_db(tsv), sys.argv[1:]) for item in sublist]

    data_dir = pathlib.Path(__file__).parent.parent.joinpath("data")
    kv_ips_json = data_dir.joinpath("kv-ips.json")
    kv_asns_json = data_dir.joinpath("kv-asns.json")

    write_kv_upload_file(create_kv_ip_partitions(ip_entries), kv_ips_json)
    write_kv_upload_file(create_kv_asn_partitions(ip_entries), kv_asns_json)

    print("")
    print("Bulk upload files created. You may now upload using the following commands:")
    print(f"  wrangler kv:bulk put --binding IP2NETWORK --preview false {kv_ips_json}")
    print(f"  wrangler kv:bulk put --binding IP2NETWORK --preview false {kv_asns_json}")


if __name__ == "__main__":
    main()
