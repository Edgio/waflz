
<img src="/docs/_images/WAFLZ_White.svg" width="200"/>

# waflz
multi tenant modsecurity implementation. [Docs](https://verizondigital.github.io/waflz/ "waflz docs")

### Overview
An implementation of WAF engine in c/c++ supporting processing modSecurity rules, configurable in a JSON config.  The engine compiles different rulesets only once, multiple WAF instances can share from same global rulesets.


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

### Running a standalone WAFLZ server

```sh
$ cat rule.conf
  SecRule &REQUEST_HEADERS:Host "@eq 0" \
        "skipAfter:END_HOST_CHECK,phase:2,rev:'2',ver:'OWASP_CRS/2.2.9',maturity:'9',accuracy:'9',t:none,block,msg:'Request Missing a Host Header',id:'960008',tag:'OWASP_CRS/PROTOCOL_VIOLATION/MISSING_HEADER_HOST',tag:'WASCTC/WASC-21',tag:'OWASP_TOP_10/A7',tag:'PCI/6.5.10',severity:'4',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.warning_anomaly_score},setvar:tx.%{rule.id}-OWASP_CRS/PROTOCOL_VIOLATION/MISSING_HEADER-%{matched_var_name}=%{matched_var}"

$ ./build/util/waflz_server/waflz_server --conf-file=rule.conf

```

### test

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
