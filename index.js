addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
});

/**
 * Routes an incoming request to the right handler
 */
async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  const ip = request.headers.get('CF-Connecting-IP');
  const country = request.headers.get('CF-IPCountry');

  let pathMatch;
  if (path === '/') {
    return textView(await fetchIPDetails(ip, country, false), 0);
  }
  else if (path === '/json') {
    return jsonView(await fetchIPDetails(ip, country, false), 0);
  }
  else if ((pathMatch = path.match(/^\/as\/(\d+)$/)) || (pathMatch = path.match(/^\/lookup\/as(\d+)$/))) {
    const asData = await fetchASDetails(parseInt(pathMatch[1]));
    return asData ? jsonView(asData, 0) : errorView(404, 'Not found', true);
  }
  else if ((pathMatch = path.match(/^\/lookup(\/(\d+\.\d+\.\d+\.\d+))?$/)) ||
      (pathMatch = path.match(/^\/lookup(\/([a-f0-9:]+))?$/))) {
    const providedIp = pathMatch[2];
    const c = providedIp ? undefined : country;
    const cacheSecs = providedIp ? 3600 : 0;
    return jsonView(await fetchIPDetails(providedIp || ip, c, true), cacheSecs);
  }
  else {
    return errorView(404, 'Not found', true);
  }
}

/**
 * Error view
 */
function errorView(status, message, asJson) {
  const body = asJson ? JSON.stringify({error: message}) : message;
  const headers = new Headers({
    'Content-Type': (asJson ? 'application/plain' : 'text/plain') + ';charset=utf-8',
    'Cache-Control': 'no-cache'
  });
  return new Response(body, { headers, status })
}

/**
 * The simplest possible view - just the IP. This returns a text view to the client. This always includes only the IP,
 * even if data has network information
 *
 * If data is undefined, return a 404
 */
function textView(data, cacheSecs = 0) {
  const ip = data["ip"];

  const cache = cacheSecs > 0 ? `max-age=${cacheSecs}` : "no-cache";
  const headers = new Headers({ 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': cache });
  return new Response(`${ip}\n`, { headers });
}

/**
 * The JSON view
 */
function jsonView(data, cacheSecs = 0) {
  const cache = cacheSecs > 0 ? `max-age=${cacheSecs}` : "no-cache";
  const headers = new Headers({ 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': cache });
  return new Response(JSON.stringify(data, null, 2), { headers });
}

/**
 * Returns ASN data for the required asn from the DB
 */
async function fetchASDetails(asn) {
  const db = await IP2NETWORK.get(`asn/v1/${asn}`);
  if (db) {
    return JSON.parse(db);
  } else {
    return undefined;
  }
}

/**
 * Get the IP details from the request
 * @param ip
 * @param country
 * @param includeNetwork if true, also fetches additional network block information from the IP DB
 */
async function fetchIPDetails(ip, country, includeNetwork) {
  if (includeNetwork) {
    const getter = ip.includes(':') ? getIP6Network : getIP4Network;
    return getter(ip, country);
  }
  else {
    return getNetworkRecord(ip, country,
        undefined, undefined, undefined, undefined, undefined);
  }
}

/**
 * Given an ipv4, returns its full network information, which includes
 *    ip,
 *    country
 *    start of the network block,
 *    end of the network block,
 *    asn,
 *    network name
 */
async function getIP4Network(ip, country) {
  const v4PrefixLen = 12; // number of most significant bits used to get the ip db partition
  const ipU32 = ipv4stoi(ip);
  const partitionKey = (ipU32 >> (32 - v4PrefixLen)) & parseInt(Array(v4PrefixLen).fill('1').join(''), 2);
  const db = await IP2NETWORK.get(`m${v4PrefixLen}/v4/${partitionKey}`);
  let bestMatch = null;
  if (db) {
    const networks = JSON.parse(db);
    let bestMatchSize = 0xffffffff;
    for (let i=0; i<networks.length; i++) {
      if (networks[i].s <= ipU32 && ipU32 <= networks[i].e) {
        const networkSize = networks[i].e - networks[i].s;
        if (networkSize < bestMatchSize) { // pick the most narrow match
          bestMatch = networks[i];
          bestMatchSize = networkSize;
        }
      }
    }
  }
  if (bestMatch) {
    return getNetworkRecord(ip, country,
        ipv4itos(bestMatch["s"]), ipv4itos(bestMatch["e"]), bestMatch["a"], bestMatch["n"], bestMatch["c"]);
  } else {
    return getNetworkRecord(ip, country,
        undefined, undefined, undefined, undefined, undefined);
  }
}

/**
 * Given an ipv6, returns its full network information, which includes
 *    ip,
 *    country,
 *    start of the network block,
 *    end of the network block,
 *    asn,
 *    network name
 */
async function getIP6Network(ip, country) {
  const v6PrefixLen = 24; // number of most significant bits used to get the ip db partition
  const ip128 = ipv6stoi(ip);
  const partitionKey = ip128 >> BigInt(128 - v6PrefixLen);
  const db = await IP2NETWORK.get(`m${v6PrefixLen}/v6/${partitionKey}`);
  let bestMatch = null;
  if (db) {
    const networks = JSON.parse(db);
    let bestMatchSize = BigInt('0x' + Array(8).fill('ffff').join(""));
    for (let i=0; i<networks.length; i++) {
      const start128 = ipv6stoi(networks[i].s);
      const end128   = ipv6stoi(networks[i].e);

      if (start128 <= ip128 && ip128 <= end128) {
        const networkSize = end128 - start128;
        if (networkSize < bestMatchSize) { // pick the most narrow match
          bestMatch = networks[i];
          bestMatchSize = networkSize;
        }
      }
    }
  }
  if (bestMatch) {
    return getNetworkRecord(ip, country,
        bestMatch["s"], v6Uncompress(bestMatch["e"]), bestMatch["a"], bestMatch["n"], bestMatch["c"]);
  } else {
    return getNetworkRecord(ip, country,
        undefined, undefined, undefined, undefined, undefined);
  }
}

function getNetworkRecord(ip, country, networkStart, networkEnd, asn, asName, asCountry) {
  return { ip, country, network: {start: networkStart, end: networkEnd}, as: {asn, name: asName, country: asCountry} };
}

/**
 * Convert a u32 to an IPv4 representation
 */
function ipv4itos(ip) {
  const arr = [(ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff];
  return `${arr[0]}.${arr[1]}.${arr[2]}.${arr[3]}`;
}

/**
 * Convert an IPv4 octet notation to a u32
 */
function ipv4stoi(ip) {
  return parseInt(ip.split('.').map(x => parseInt(x).toString(16)).join(''), 16);
}

/**
 * Uncompresses an IPv6 representation, where we may have replaced :ffff with X to save space
 */
function v6Uncompress(ip) {
  return ip.replace('X', Array(8 - (ip.match(/:/g) || []).length).fill('ffff').join(':'));
}

/**
 * Convert an IPv6 hexadectets notation to a BigInt
 */
function ipv6stoi(ip) {
  let uncompressedIp = v6Uncompress(ip);
  const numColons = uncompressedIp.match(/:/g).length;

  // If we have a :: in the string, replace it with 0s
  if (numColons !== 7) {
    const filler = Array(8-numColons).fill("0").join(":");
    uncompressedIp = uncompressedIp.replace("::", `:${filler}:`);
  }

  // parse each hexadectet as a u16
  const arr = uncompressedIp.split(':').map(x => x==='' ? 0 : parseInt(x, 16));

  let i128 = 0n;
  for (let i=0; i<arr.length; i++) i128 |= BigInt(arr[i]) << BigInt(((7-i)*16));
  return i128;
}