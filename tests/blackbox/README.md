# WAF RULE Tests

##
Gives the ability to test if new updated policies are working as expected.
```bash
$ mkdir /EdgeCast && chown $(whoami):$(whoami) /EdgeCast && cd /EdgeCast
$ git clone https://git.edgecastcdn.net/EdgeCast/waf

$ ./run_tests.sh ruleset/bb_test_ruleset.py && lsof -i :12345
```
Example output: 
```bash
testbox-hworkpc:/EdgeCast/waf$ /home/testuser/git/dev/waflz-src/tests/blackbox/run_tests.sh /home/testuser/git/dev/waflz-src/tests/blackbox/ruleset/test_bb_ruleset.py
bb_test_ruleset_001 ... ok
2.2.9 modsecurity_crs_21_protocol_anomalies ... ok
2.2.9 modsecurity_crs_41_sql_injection_attacks ... ok
2.2.9 modsecurity_crs_20_protocol_violations.conf ... ok
2.2.9 modsecurity_crs_40_generic_attacks ... ok
2.2.9 modsecurity_crs_23_request_limits.conf ... ok
2.2.9 modsecurity_crs_35_bad_robots ... ok
2.2.9 modsecurity_crs_22_custom_ec_rules ... ok

----------------------------------------------------------------------
Ran 8 tests in 2.098s

OK
testbox-hworkpc:/EdgeCast/waf$ 

```
