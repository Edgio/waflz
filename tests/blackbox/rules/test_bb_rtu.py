#!/usr/bin/python
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
from pprint import pprint
import time
import requests
from urllib2 import Request
from urllib2 import urlopen
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
                 'Content-Type' : 'application/x-www-form-urlencoded',
                 'User-Agent': 'Mozilla'}
    l_body = 'java.io.BufferedInputStream'
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=l_body)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    print json.dumps(l_r_json,indent=4)
    assert l_r_json['rule_intercept_status'] == 403
    assert 'Inbound Anomaly Score Exceeded (Total Score: 5): Last Matched Message: Suspicious Java class detected' in l_r_json['rule_msg']
    assert l_r_json['matched_var']['name'] == 'REQUEST_BODY'
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
        print 'error opening config file: %s.  Reason: %s error: %s, doc: %s, message: %s'%(
            l_conf_path, type(l_e), l_e, l_e.__doc__, l_e.message)
        assert False
    #-------------------------------------------------------
    # Add a rule target update
    # ------------------------------------------------------
    l_conf['rule_target_updates'] = [
        {
            'replace_target' : '',
             'rule_id' : '944130',
             'is_regex' : True,
             'is_negated' : True,
             'target_match' : '.*',
             'target' : 'ARGS_NAMES'
        },
        {
            'replace_target' : '',
             'rule_id' : '944130',
             'is_regex' : True,
             'is_negated' : True,
             'target_match' : '.*',
             'target' : 'REQUEST_BODY'
        }
        ]
    # ------------------------------------------------------
    # post conf
    # ------------------------------------------------------
    l_url = '%supdate_profile'%(G_TEST_HOST)
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
                 'Content-Type' : 'application/x-www-form-urlencoded',
                 'User-Agent': 'Mozilla'}
    l_body = 'java.io.BufferedInputStream'
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=l_body)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    print json.dumps(l_r_json,indent=4)
    #-------------------------------------------------------
    # check no event is returned
    # ------------------------------------------------------
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
