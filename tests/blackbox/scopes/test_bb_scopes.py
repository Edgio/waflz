#!/usr/bin/env python3
'''Test scopes with custom rules'''
# ------------------------------------------------------------------------------
# imports
# ------------------------------------------------------------------------------
import pytest
import subprocess
import os
import sys
import json
import time
import requests
import base64
import time
# ------------------------------------------------------------------------------
# constants
# ------------------------------------------------------------------------------
G_TEST_HOST = 'http://127.0.0.1:12345'
# ------------------------------------------------------------------------------
# run_command
# ------------------------------------------------------------------------------
def run_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)
# ------------------------------------------------------------------------------
# setup scopez server with scopes dir
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_scopez_server():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_scopez_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_scopez_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/scopez_server/scopez_server'))
    l_subproc = subprocess.Popen([l_scopez_server_path,
                                  '-d', l_conf_dir,
                                  '-S', l_scopez_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-i', l_geoip2ISP_path])
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_scopez_server
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# setup scopez server with single scope for an 0050
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_scopez_server_single():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_scopez_file = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes/0050.scopes.json'))
    l_scopez_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/scopez_server/scopez_server'))
    l_subproc = subprocess.Popen([l_scopez_server_path,
                                  '-d', l_conf_dir,
                                  '-s', l_scopez_file,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-i', l_geoip2ISP_path])
    print('cmd: {}'.format(' '.join([l_scopez_server_path,
                                  '-d', l_conf_dir,
                                  '-s', l_scopez_file,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-i', l_geoip2ISP_path])))
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_scopez_server_single
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# setup scopez server in action mode
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_scopez_server_action():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_scopez_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes'))
    l_scopez_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/scopez_server/scopez_server'))
    l_subproc = subprocess.Popen([l_scopez_server_path,
                                  '-d', l_conf_dir,
                                  '-S', l_scopez_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-i', l_geoip2ISP_path,
                                  '-a'])
    print('cmd: {}'.format(' '.join([l_scopez_server_path,
                                  '-d', l_conf_dir,
                                  '-S', l_scopez_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-i', l_geoip2ISP_path,
                                  '-a'])))
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_scopez_server_action
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)

# ------------------------------------------------------------------------------
# an 0050
# ------------------------------------------------------------------------------
def test_scopes_dir_for_an_0050(setup_scopez_server):
    # ------------------------------------------------------
    # test without UA for AN 0050
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile'] == None
    # ------------------------------------------------------
    # test with UA for AN 0050
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'monkeez',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is monkeez'
# ------------------------------------------------------------------------------
# an 0051
# ------------------------------------------------------------------------------
def test_scopes_dir_for_an_0051(setup_scopez_server):
    # ------------------------------------------------------
    # test with wrong path for AN 0051
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/index.html'
    l_headers = {'host': 'bananas.com',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile'] == None
    # ------------------------------------------------------
    # test with wrong host for AN 0051
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'wronghost.com',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile'] == None
    # ------------------------------------------------------
    # test with correct host and path and without UA for AN 0051
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'bananas.com',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile'] == None
    # ------------------------------------------------------
    # test with correct host and path and with UA for AN 0051
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'bananas.com',
                 'user-agent': 'bananas',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is bananas'
# ------------------------------------------------------------------------------
# single scope
# ------------------------------------------------------------------------------
def test_single_scope(setup_scopez_server_single):
    # ------------------------------------------------------
    # test single scope for AN 0050
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'monkeez',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is monkeez'
    # ------------------------------------------------------
    # test acl
    # ------------------------------------------------------
    l_headers['user-agent'] = 'gizoogle'
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist User-Agent match'
    # ------------------------------------------------------
    # test acl
    # ------------------------------------------------------
    l_headers['user-agent'] = 'curl'
    l_uri = G_TEST_HOST + '/?a=%27select%20*%20from%20testing%27'
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'SQL Injection Attack Detected via libinjection'
# ------------------------------------------------------------------------------
# test audit and prod alert for an 0050
# ------------------------------------------------------------------------------
def test_audit_and_prod_for_scope(setup_scopez_server_single):
    # ------------------------------------------------------
    # test audit and prod acl
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'test.com',
                 'user-agent': 'gizoogle',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] ['sub_event'][0]['rule_msg'] == 'Blacklist User-Agent match'
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist User-Agent match'
    # ------------------------------------------------------
    # test audit acl only
    # ------------------------------------------------------
    l_uri = G_TEST_HOST + '/audit.html'
    l_headers = {'host': 'test.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] ['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile'] == None
    # ------------------------------------------------------
    # test prod acl only
    # ------------------------------------------------------
    l_uri = G_TEST_HOST + '/prod.html'
    l_headers = {'host': 'test.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    # ------------------------------------------------------
    # test audit and prod profile
    # ------------------------------------------------------
    l_uri = G_TEST_HOST + '/?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'test.com',
                  'waf-scopes-id': '0050',
                  'user-agent': 'curl'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'SQL Injection Attack Detected via libinjection'
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'SQL Injection Attack Detected via libinjection'
    # ------------------------------------------------------
    # test prod rule
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'test.com',
                 'waf-scopes-id': '0050',
                 'user-agent': 'monkeez'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is monkeez'
    # ------------------------------------------------------
    # test audit rule
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'test.com',
                 'waf-scopes-id': '0050',
                 'user-agent': 'bananas'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is bananas'
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile'] == None
# ------------------------------------------------------------------------------
# test acl, rules and profile alert ordering for an 0050
# ------------------------------------------------------------------------------
def test_alert_order(setup_scopez_server_single):
    # ------------------------------------------------------
    # acl alert should kick in for prod (URL blacklist) 
    # acl alert should kick in for audit(User-Agent blacklist)
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/prod.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'test.com',
                  'user-agent': 'gizoogle',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']['sub_event'][0]['rule_msg'] == 'Blacklist User-Agent match' 
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    # ------------------------------------------------------
    # acl alert should kick in for prod(URL blacklist)
    # custom rule alert should kick in audit (User-agent match)
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/prod.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'test.com',
                  'user-agent': 'bananas',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is bananas' 
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    # ------------------------------------------------------
    # acl alert should kick in for prod(URL blacklist)
    # waf profile alert should kick in for audit (SQL injection)
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/prod.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'test.com',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']['sub_event'][0]['rule_msg'] == 'SQL Injection Attack Detected via libinjection' 
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    # ------------------------------------------------------
    # acl alert should kick in for audit(URL blacklist)
    # waf profile alert should kick in for prod (SQL injection)
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/audit.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'test.com',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] =='SQL Injection Attack Detected via libinjection'
    # ------------------------------------------------------
    # acl alert should kick in for audit(URL blacklist)
    # custom rule alert should kick in for prod (SQL injection)
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/audit.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'test.com',
                  'user-agent': 'monkeez',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] =='Request User-Agent is monkeez'

# ------------------------------------------------------------------------------
# test limit and waf with scopes
# ------------------------------------------------------------------------------
def test_limit_and_waf_with_scopes(setup_scopez_server_action):
    # ------------------------------------------------------
    # shoot 3 request in 5 sec
    # 3rd request should get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'limit.com',
                 'waf-scopes-id': '0050'}
    for x in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200

    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is ddos custom response\n'
    # ------------------------------------------------------
    # shoot SQL injection request during enforcement window.
    # Should still get a ddos custom response
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'limit.com',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is ddos custom response\n'
    # ------------------------------------------------------
    # shoot acl request during enforcement period.
    # should see acl action
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/audit.html'
    l_headers = {'host': 'limit.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is acl custom response\n'
    # ------------------------------------------------------
    # sleep for 5 seconds enforcement period.
    # Shoot SQL injection request again.
    # should see waf action
    # ------------------------------------------------------
    time.sleep(5)
    l_uri = G_TEST_HOST+'/test.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'limit.com',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is profile custom response\n'
# ------------------------------------------------------------------------------
# test scopes operator
# ------------------------------------------------------------------------------
def test_scopes_operators(setup_scopez_server_action):
    # ------------------------------------------------------
    # test for EM
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'bananas.com',
                 'user-agent': 'bananas',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == "This is from EM scope\n"
    # ------------------------------------------------------
    # test for RX
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test/path.html'
    l_headers = {'host': 'test.regexhost.com',
                 'user-agent': 'bananas',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == "This is from RX scope\n"
    # ------------------------------------------------------
    # test for GLOB - random hostname and path
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/somepath.html'
    l_headers = {'host': 'somedomain.com',
                 'user-agent': 'bananas',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == "This is from GLOB scope\n"
# ------------------------------------------------------------------------------
# test acl whitelist
# ------------------------------------------------------------------------------
def test_acl_whitelist(setup_scopez_server_action):
    # ------------------------------------------------------
    # Request with more than number of args configured in
    # profile. waf should alert
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html?arg1&arg2&arg3&arg4'
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == "This is profile custom response\n"
    # ------------------------------------------------------
    # Request with lot of args in whitelisted url
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/robots.txt?arg1&arg2&arg3&arg4'
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# test mutiple scopes for ratelimiting
# ------------------------------------------------------------------------------
def test_multiple_scopes_for_limit(setup_scopez_server_action):
    # ------------------------------------------------------
    # Make 3 request in 5 sec.
    # 3rd request should get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'limit.com',
                 'waf-scopes-id': '0050'}
    for x in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200

    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is ddos custom response\n'
    # ------------------------------------------------------
    # Make another request for different scope during enf
    # window of first request. should get 200 and followed
    # by enforcement for that scope
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'test.limit.com',
                 'waf-scopes-id': '0050'}
    for x in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200

    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == "custom response for limits from limit_id_2\n"
    # ------------------------------------------------------
    # sleep for 5 seconds.
    # Enforcements should expire for both scopes
    # ------------------------------------------------------
    time.sleep(5)
    # ------------------------------------------------------
    # making single request for each scope should give 200
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'limit.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200

    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'test.limit.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# custom rules in scopes
# ------------------------------------------------------------------------------
def test_custom_rules_in_scopes(setup_scopez_server_action):
    # ------------------------------------------------------
    # create request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'rulestest.com',
                 'user-agent': 'RULESTEST',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'basic custom rule triggered\n'
# ------------------------------------------------------------------------------
# chained custom rules in scopes
# ------------------------------------------------------------------------------   
def test_chained_custom_rules_in_scopes(setup_scopez_server_action):
    # ------------------------------------------------------
    # create request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'chainedrulestest.com',
                 'waf-scopes-id': '0052',
                 'Pragma': 'NO-CACHE'
                 }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'response from chained custom rules\n'
