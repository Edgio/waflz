Profiles
========

Overview
--------
A waflz "profile" is configuration that builds on top of an existing ruleset.  Beyond the basic ruleset/engine configuration, it adds "access control lists" (ACL's) for various use-cases we've found useful (eg url's/user-agents/ip's etc).  ACL's can of course be expressed in ModSecurity rules as well, but we've found it convenient to add ACL's into the profile json.  A profile just extends a ruleset, however, and a profile w/o a ruleset isn't useful for much other than outright blocking with ACL's.

Example Profile json
--------------------

.. code-block:: json

    {
      "name": "Koala Blocking Profile",
      "id": "WAF Test 13",
      "created_date": "12/02/2018 1:39:46 PM",
      "access_settings": {
        "ip": {
          "blacklist": [
            "2607:f8b0:4007:801::200e"
          ],
          "whitelist": []
        },
        "country": {
          "blacklist": [
            "AU"
          ],
          "whitelist": []
        },
        "url": {
          "blacklist": [
            "/login/login.jsp"
            ],
          "whitelist": []
        },
        "user-agent": {
          "blacklist": [
            "cerl/7.58.0"
          ],
          "whitelist": []
        },
        "referer": {
          "blacklist": [
            "http://www.hotzone.com/"
          ],
          "whitelist": []
        },
        "ignore_header": [
            "(?i)(benign-header)",
            "^D"
        ],
        "ignore_cookie": [
          "(?i)(crazy_cookie)",
          "^[0-9_].*$"
        ],
        "ignore_query_args": [
          "ignore",
          "this"
        ]
      },
      "general_settings": {
        "allowed_http_methods": [
          "GET",
          "POST"
        ],
        "disallowed_extensions": [
          ".bat",
          ".db",
          ".dll",
          ".sql",
          ".sys"
        ],
        "allowed_request_content_types": [
          "application/x-www-form-urlencoded",
          "multipart/form-data",
          "text/xml",
          "application/xml",
          "application/json"
        ],
        "disallowed_headers": [
          "Bad-Header"
        ],
        "arg_name_length": 1024,
        "arg_length": 8000,
        "max_num_args": 4,
        "total_arg_length": 64000,
        "combined_file_sizes": 6291456,
        "max_file_size": 6291456,
        "validate_utf8_encoding": true,
        "xml_parser": true,
        "anomaly_settings": {
          "error_score": 4,
          "notice_score": 2,
          "inbound_threshold": 1,
          "critical_score": 5,
          "outbound_threshold": 4,
          "warning_score": 3
        }
      },
      "ruleset_id": "OWASP-CRS-2.2.9",
      "ruleset_version": "2017-08-01",
      "policies" : [
        "modsecurity_crs_20_protocol_violations.conf",
        "modsecurity_crs_21_protocol_anomalies.conf",
        "modsecurity_crs_22_custom_ec_rules.conf",
        "modsecurity_crs_23_request_limits.conf",
        "modsecurity_crs_30_http_policy.conf",
        "modsecurity_crs_35_bad_robots.conf",
        "modsecurity_crs_40_generic_attacks.conf",
        "modsecurity_crs_41_sql_injection_attacks.conf",
        "modsecurity_crs_41_xss_attacks.conf",
        "modsecurity_crs_42_tight_security.conf",
        "modsecurity_crs_45_trojans.conf",
        "modsecurity_crs_47_common_exceptions.conf",
        "modsecurity_crs_49_inbound_blocking.conf",
        "modsecurity_crs_50_outbound.conf",
        "modsecurity_crs_59_outbound_blocking.conf",
        "modsecurity_crs_60_correlation.conf"
      ]
    }


.. _profiles-acls:

Access Control Lists
--------------------
Access control lists (ACL's) for various facets of an http client request are listed below.  ACL's are processed first before ruleset processing; whitelists followed by blacklists.  Whitelists are explicit call out to features if found in the client http request, all waflz processing is bypassed.  Blacklists are simple binary conditions, whereby if a feature matches, waflz creates and alert and ceases further processing.  It's a current legacy quirk that some fields that are *not* access control lists are included in the ``"access_settings"`` group and as well that some configuration that is an access control is in the ``"general_settings"`` group.

The following features are included in ACL's:
* ``"ip"``: IPv4/IPv6 address (w/ CIDR support)
* ``"country"``: 2 letter country code
* ``"user_agent"``: ``"User-Agent"`` header from client http request (w/ regex support)
* ``"referer"``: ``"Referer"`` header from client http request (w/ regex support)

Block Example
^^^^^^^^^^^^^

* IP addresses with "2001:db8::/32" ipv6 prefix or "192.0.2.0/24" ipv4 prefix
* IP addresses from Virgin Islands or Sweden
* curl or wget clients...
* traffic coming from google or yahoo (via referer)

.. code-block:: json

    {
    "access_settings": {
      "ip": {
        "blacklist": ["2001:db8::/32", "192.0.2.0/24"],
        "whitelist": []
      },
      "country": {
        "blacklist": ["VI", "SE"],
        "whitelist": []
      },
      "user_agent": {
        "blacklist": ["curl*", "wget*"],
        "whitelist": []
      },
      "referer": {
        "blacklist": ["http://google.com", "http://yahoo.com"],
        "whitelist": []
      },
    }

Ignore Fields
-------------

The following features are included in ACL's:
* ``"ignore_header"``: Headers from the client http request (w/ regex support)
* ``"ignore_cookie"``: Field names from the parsed ``"Cookie"`` header in the client http request (w/ regex support)
* ``"ignore_query_args"``: Fields names from the parsed query string in the url from the client http request line (w/ regex support)

Ignore Example
^^^^^^^^^^^^^^

* ``Benign-Header`` (case insensitive), and any headers starting with numbers.
* ``crazy_cookie`` cookies, and cookies starting with characters ``a``,``b``, or ``c``.
* query string arguments named ``ignore`` or ``this``.

.. code-block:: json

    {
      "ignore_header": [
        "(?i)(benign-header)",
        "^\d"
      ],
      "ignore_cookie": [
        "(?i)(crazy_cookie)",
        "^[a-c]"
      ],
      "ignore_query_args": [
        "ignore",
        "this"
      ]
    }


General Settings
----------------


Allowed Settings
^^^^^^^^^^^^^^^^

.. code-block:: json

    {
      "allowed_http_methods": [
        "GET",
        "POST"
      ],
      "disallowed_extensions": [
        ".bat",
        ".db",
        ".dll",
        ".sql",
        ".sys"
      ],
      "allowed_request_content_types": [
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/xml",
        "application/xml",
        "application/json"
      ],
      "disallowed_headers": [
        "Bad-Header"
      ]
    }

Anomaly Settings
^^^^^^^^^^^^^^^^^

.. code-block:: json

    {
        "anomaly_settings": {
          "error_score": 4,
          "notice_score": 2,
          "inbound_threshold": 1,
          "critical_score": 5,
          "outbound_threshold": 4,
          "warning_score": 3
        }
    }

WAF Ruleset
-----------
Specify the WAF ruleset and "version" to use.

Ruleset Configuration
^^^^^^^^^^^^^^^^^^^^^
**waflz** expects the ruleset directory to be setup as:
* ``<"ruleset_id">/version/<"ruleset_version">/...``  We've found it useful to have a top level directory of rulesets that were versioned (usually by date).

So in the example below if

.. code-block:: json

    {
      "ruleset_id": "OWASP-CRS-2.2.9",
      "ruleset_version": "2017-08-01",
    }

The contents of ruleset directory would look like:

.. code-block:: sh

  OWASP-CRS-2.2.9/
    version/
      2017-08-01/
        modsecurity_crs_20_protocol_violations.conf
        ...

Policy Configuration
^^^^^^^^^^^^^^^^^^^^
Within a given ruleset/version directory, the policies to be included are specified in the ``"policies"`` array.  

.. code-block:: json

    {
      "policies" : [
        "modsecurity_crs_20_protocol_violations.conf",
        "modsecurity_crs_21_protocol_anomalies.conf",
        "modsecurity_crs_22_custom_ec_rules.conf",
        "modsecurity_crs_23_request_limits.conf",
        "modsecurity_crs_30_http_policy.conf",
        "modsecurity_crs_35_bad_robots.conf",
        "modsecurity_crs_40_generic_attacks.conf",
        "modsecurity_crs_41_sql_injection_attacks.conf",
        "modsecurity_crs_41_xss_attacks.conf",
        "modsecurity_crs_42_tight_security.conf",
        "modsecurity_crs_45_trojans.conf",
        "modsecurity_crs_47_common_exceptions.conf",
        "modsecurity_crs_49_inbound_blocking.conf",
        "modsecurity_crs_60_correlation.conf"
      ]
    }

