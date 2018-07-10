
<img src="/docs/_images/waflz_white.svg" width="200"/>

# waflz
multi tenant modsecurity implementation. [Docs](https://verizondigital.github.io/waflz/ "waflz docs")

### Overview
An implementation of a WAF engine in c/c++ supporting processing a subset of ModSecurity rules functionalties, configurable with either json or ModSecurity rules.  waflz is performance optimized to support running many WAF profiles side by side, by using faster/smaller internal data types and sharing common ruleset data between the profiles -ie if multiple WAF profiles refer to the same ruleset(s), the ruleset(s) are loaded only once for all and shared in memory.

### Rationale
The VDMS global edge platform is a multi-tenant CDN supporting our hundreds of thousands individual customer configurations from any given location.  The VDMS WAF supports running OWASP Core Rulesets as well as some third-party rulesets.  The performance and resource allocation of any given customer configuration has the potential of impacting others -ie eventually all configurations live in memory on a physical server in a "Point of Presence" (POP) in a datacenter.  It was important then to the VDMS CDN the WAF be as high performant, memory constrained, and deterministic as possible.

### Capabilities
The open source standard implementation of the [ModSecurity Rules Engine](https://github.com/SpiderLabs/ModSecurity "ModSecurity") -while excellent, and extremely flexible for individuals' use-cases, could be problematic in a CDN, where performance is the product.  Several ModSecurity capabilities eg [SecRemoteRules](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecRemoteRules "SecRemoteRules") and [inspectFile](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#inspectFile "inspectFile"), were intentionally ommitted, due to potential performance impacts in a multi-tenant envronment.  A list of currently supported variables, operators and transforms are listed in the [capabilities section of the docs](https://verizondigital.github.io/waflz/capabilities "waflz capabilities")

### Build requirement (Ubuntu 14.04/16.04)

## Packages

```sh
$ sudo add-apt-repository ppa:maxmind/ppa
$ sudo apt-get update
$ sudo apt-get install -y libssl-dev libpcre3-dev libxml2-dev libicu-dev protobuf-compiler libprotobuf-dev python-pip libmaxminddb0 libmaxminddb-dev
```

## Python Packages
```sh
$ pip install -r requirements.txt
```

### Build steps

```sh
$ ./build.sh
```

### Running standalone waflz_server for testing WAF rules

```sh
$ cat rule.conf
  SecRule &REQUEST_HEADERS:Host "@eq 0" \
        "phase:2,rev:'2',ver:'OWASP_CRS/2.2.9',t:none,block,msg:'Request Missing a Host Header',id:'960008',tag:'OWASP_CRS/PROTOCOL_VIOLATION/MISSING_HEADER_HOST',tag:'WASCTC/WASC-21',tag:'OWASP_TOP_10/A7',tag:'PCI/6.5.10',severity:'4',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.warning_anomaly_score},setvar:tx.%{rule.id}-OWASP_CRS/PROTOCOL_VIOLATION/MISSING_HEADER-%{matched_var_name}=%{matched_var}"

$ ./build/util/waflz_server/waflz_server --conf-file=rule.conf

```

### curl'ing waflz_server

```sh
$ curl -s "http://localhost:12345/index.html" -H"Host:" | jq '.'
{
  "req_info": {
    "epoch_time": {
      "sec": 1527623134,
      "nsec": 2909744297
    },
    "virt_remote_host": "MC4wLjAuMA==",
    "request_method": "R0VU",
    "orig_url": "L2luZGV4Lmh0bWw=",
    "url": "L2luZGV4Lmh0bWw=",
    "common_header": {
      "user_agent": "Y3VybC83LjQ3LjA="
    },
    "req_uuid": "YWFiYmNjZGRlZWZm"
  },
  "rule_id": 981176,
  "rule_msg": "Inbound Anomaly Score Exceeded (Total Score: 3, SQLi=0, XSS=0): Last Matched Message: Request Missing a Host Header",
  "rule_target": [
    {
      "name": "TX",
      "param": "ANOMALY_SCORE"
    }
  ],
  "rule_op_name": "gt",
  "rule_op_param": "0",
  "rule_tag": [
    "OWASP_CRS/ANOMALY/EXCEEDED"
  ],
  "matched_var": {
    "name": "REQUEST_HEADERS",
    "value": "MA=="
  },
  "total_anomaly_score": 3,
  "total_sql_injection_score": 0,
  "total_xss_score": 0,
  "sub_event": [
    {
      "rule_id": 960008,
      "rule_msg": "Request Missing a Host Header",
      "rule_intercept_status": 403,
      "rule_target": [
        {
          "name": "REQUEST_HEADERS",
          "param": "Host",
          "is_counting": true
        }
      ],
      "rule_op_name": "EQ",
      "rule_op_param": "0",
      "rule_tag": [
        "OWASP_CRS/PROTOCOL_VIOLATION/MISSING_HEADER_HOST",
        "WASCTC/WASC-21",
        "OWASP_TOP_10/A7",
        "PCI/6.5.10"
      ],
      "matched_var": {
        "name": "REQUEST_HEADERS",
        "value": "MA=="
      },
      "total_anomaly_score": 3,
      "total_sql_injection_score": 0,
      "total_xss_score": 0,
      "waf_profile_id": "NA",
      "waf_profile_name": "NA"
    }
  ],
  "waf_profile_id": "NA",
  "waf_profile_name": "NA"
}

```
