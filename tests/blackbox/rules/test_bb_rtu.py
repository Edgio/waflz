#!/usr/bin/env python3
'''Test WAF Access settings'''
#TODO: make so waflz_server only runs once and then can post to it
# ------------------------------------------------------------------------------
# Imports
# ------------------------------------------------------------------------------
import pytest
import subprocess
import os
import sys
import json
import time
import requests
import base64
# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------
G_TEST_HOST = 'http://127.0.0.1:12345/'
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
def run_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)
# ------------------------------------------------------------------------------
# fixture
# ------------------------------------------------------------------------------
@pytest.fixture(scope='module')
def setup_waflz_server():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_profile_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_rtu.waf.prof.json'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-f', l_profile_path,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path])
    #time.sleep(1)
    g_server_pid = l_subproc.pid
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# test_bb_rtu_request_body
# ------------------------------------------------------------------------------
def test_bb_rtu_request_body(setup_waflz_server):
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'Content-Type': 'application/x-www-form-urlencoded',
                 'User-Agent': 'Mozilla'}
    l_body = 'java.io.FileWriter'
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=l_body)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert l_r_json['rule_intercept_status'] == 403
    assert 'Suspicious Java class detected' in l_r_json['sub_event'][0]['rule_msg']
    assert l_r_json['matched_var']['name'] == 'UkVRVUVTVF9CT0RZ'
    #-------------------------------------------------------
    # create config
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_rtu.waf.prof.json'))
    try:
        with open(l_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    #-------------------------------------------------------
    # Add a rule target update
    # ------------------------------------------------------
    l_conf['rule_target_updates'] = [
        {
            'replace_target': '',
            'rule_id': '944130',
            'is_regex': True,
            'is_negated': True,
            'target_match': '.*',
            'target': 'ARGS_NAMES'
        },
        {
            'replace_target': '',
            'rule_id': '944130',
            'is_regex': True,
            'is_negated': True,
            'target_match': '.*',
            'target': 'REQUEST_BODY'
        }
    ]
    # ------------------------------------------------------
    # post conf
    # ------------------------------------------------------
    l_url = '%supdate_profile' % (G_TEST_HOST)
    # ------------------------------------------------------
    # urlopen (POST)
    # ------------------------------------------------------
    l_headers = {'Content-Type': 'application/json'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    #-------------------------------------------------------
    # GET the same uri which returned a 403 before RTU
    # ------------------------------------------------------
    l_headers = {'host': 'myhost.com',
                 'Content-Type': 'application/x-www-form-urlencoded',
                 'User-Agent': 'Mozilla'}
    l_body = 'java.io.BufferedInputStream'
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=l_body)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    #-------------------------------------------------------
    # check no event is returned
    # ------------------------------------------------------
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
# ------------------------------------------------------------------------------
# test_bb_rtu_chained_rule
# ------------------------------------------------------------------------------
def test_bb_rtu_chained_rule(setup_waflz_server):
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'Cookie': 'mycookie=true|c|-1|easyweb|-|1607356144310|554290487_890|https://mysite.com/waw/brk/wb/wbr/static/main/index.html|webbroker - order status|1607356081298|/page/trading/order-status?accountid=uass7j-9elpoiabja6eykgubinbzfbh1b2hw2zbetqs=',
                 'User-Agent': 'Mozilla'}
    l_r = requests.get(l_uri,
                        headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert l_r_json['rule_intercept_status'] == 403
    # ------------------------------------------------------
    # Get event from a chained rule and check rule target
    # "rule_target": [
    #            {
    #                "name": "UkVRVUVTVF9DT09LSUVT",
    #                "param": "/__utm/",
    #                "is_negated": true
    #            }
    # ------------------------------------------------------
    assert 932200 == l_r_json['sub_event'][0]['rule_id']
    assert base64.b64decode(l_r_json['matched_var']['value']).decode("utf-8") == 'true|c|-1|easyweb|-|1607356144310|554290487_890|https://mysite.com/waw/brk/wb/wbr/static/main/index.html|webbroker - order status|1607356081298|/page/trading/order-status?accountid=uass7j-9elpoiabja6eykgubinbzfbh1b2hw2zbetqs='
    assert '/__utm/' in l_r_json['sub_event'][0]['rule_target'][0]['param']
    #-------------------------------------------------------
    # create config
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_rtu.waf.prof.json'))
    try:
        with open(l_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    #-------------------------------------------------------
    # add rtu
    # ------------------------------------------------------
    l_conf['rule_target_updates'] = [
        {
         "rule_id" : "932200",
         "target_match" : "mycookie",
         "is_regex" : False,
         "target" : "REQUEST_COOKIES"
        }
    ]
    # ------------------------------------------------------
    # post conf
    # ------------------------------------------------------
    l_url = '%supdate_profile' % (G_TEST_HOST)
    # ------------------------------------------------------
    # urlopen (POST)
    # ------------------------------------------------------
    l_headers = {'Content-Type': 'application/json'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    #-------------------------------------------------------
    # GET the same uri which returned a 403 before RTU
    # ------------------------------------------------------
    l_headers = {'host': 'myhost.com',
                 'Cookie': 'mycookie=true|c|-1|easyweb|-|1607356144310|554290487_890|https://mysite.com/waw/brk/wb/wbr/static/main/index.html|webbroker - order status|1607356081298|/page/trading/order-status?accountid=uass7j-9elpoiabja6eykgubinbzfbh1b2hw2zbetqs=',
                 'User-Agent': 'Mozilla'}
    l_r = requests.post(l_uri,
                        headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    #-------------------------------------------------------
    # check no event is returned
    # ------------------------------------------------------
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
    #-------------------------------------------------------
    # Now change the cookie name to something else than RTU
    # the chained rule should fire on this one again
    # ------------------------------------------------------
    l_headers = {'host': 'myhost.com',
                 'Cookie': 'banana=true|c|-1|easyweb|-|1607356144310|554290487_890|https://mysite.com/waw/brk/wb/wbr/static/main/index.html|webbroker - order status|1607356081298|/page/trading/order-status?accountid=uass7j-9elpoiabja6eykgubinbzfbh1b2hw2zbetqs=',
                 'User-Agent': 'Mozilla'}
    l_r = requests.get(l_uri,
                        headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    #-------------------------------------------------------
    # check we get an event from same rule
    # ------------------------------------------------------
    assert 932200 == l_r_json['sub_event'][0]['rule_id']
    assert base64.b64decode(l_r_json['matched_var']['value']).decode("utf-8") == 'true|c|-1|easyweb|-|1607356144310|554290487_890|https://mysite.com/waw/brk/wb/wbr/static/main/index.html|webbroker - order status|1607356081298|/page/trading/order-status?accountid=uass7j-9elpoiabja6eykgubinbzfbh1b2hw2zbetqs='
    # ------------------------------------------------------
    # Check rule targets to make sure that the RTU is applied
    # Rule 932200 targets before RTU
    # REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*
    # After applying the RTU the REQUEST_COOKIES should
    # have mycookie as a negated target, which means RTU was applied
    # the rule target will look like this
    #    "rule_target": [
    #            {
    #                "name": "UkVRVUVTVF9DT09LSUVT",
    #                "param": "mycookie",
    #                "is_negated": true
    #            },
    #
    # ------------------------------------------------------
    assert 'mycookie' in l_r_json['sub_event'][0]['rule_target'][0]['param']
