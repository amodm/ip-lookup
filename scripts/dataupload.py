#!/usr/bin/env python3
import sys, gzip, json, ipaddress, re, os, requests, toml
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


"""
Main entry point
"""
def main():
    if len(sys.argv) < 2:
        print("usage: %s <path/to/ip-db.tsv.gz> [... <db2.gz>]" % sys.argv[0], file=sys.stderr)
        sys.exit(1)

    wr = toml.load("wrangler.toml")
    cf_account_id = wr["account_id"]
    cf_namespace_id = wr["kv-namespaces"][0]["id"]
    cf_key = toml.load(os.path.join(os.getenv('HOME'),'.wrangler/config/default.toml')).get('api_token')

    if not cf_account_id or not cf_namespace_id or not cf_key:
        print("error: cloudflare credentials not set up in env", file=sys.stderr)
        sys.exit(1)

    ip_entries = [item for sublist in map(lambda tsv: read_ip_db(tsv), sys.argv[1:]) for item in sublist]

    cf_batch_size = 9900
    for partitions in [create_kv_ip_partitions(ip_entries), create_kv_asn_partitions(ip_entries)]:
    #for partitions in [create_kv_asn_partitions(ip_entries)]:
        for i in range(0, len(partitions), cf_batch_size):
            batch = partitions[i:i+cf_batch_size]
            body = json.dumps(batch, separators=(',', ':'))
            print("Uploading batch of %d entries of total size %d" % (len(batch), len(body)))
            url = "https://api.cloudflare.com/client/v4/accounts/%s/storage/kv/namespaces/%s/bulk" \
                  % (cf_account_id, cf_namespace_id)
            headers = {
                'content-type': 'application/json',
                'Authorization': "Bearer %s" % cf_key
            }
            requests.put(url, body, headers=headers).raise_for_status()
            print("Done")

if __name__ == "__main__":
    main()
