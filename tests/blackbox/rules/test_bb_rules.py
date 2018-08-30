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
# globals
# ------------------------------------------------------------------------------
g_server_pid = -1
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
def run_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)
# ------------------------------------------------------------------------------
#setup_func
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_func():
    global g_server_pid
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'));
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'));
    l_profile_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_rules.waf.prof.json'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-f', l_profile_path,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path])
    time.sleep(1)
    g_server_pid = l_subproc.pid
    time.sleep(1)
    print 'setup g_server_pid: %d'%(g_server_pid)
    time.sleep(1)
# ------------------------------------------------------------------------------
#teardown_func
# ------------------------------------------------------------------------------
def teardown_func():
    global g_server_pid
    time.sleep(.5)
    print 'teardown g_server_pid: %d'%(g_server_pid)
    if g_server_pid != -1:
        l_code, l_out, l_err = run_command('kill -9 %d'%(g_server_pid))
        time.sleep(.5)
# ------------------------------------------------------------------------------
# test_bb_modsecurity_ec_access_settings_ignore_args
# ------------------------------------------------------------------------------
def test_bb_without_rule_target_update_fail(setup_func):
    l_uri = G_TEST_HOST + '?' + 'origin=Mal%C3%A9&destination=Southeast+Asia&marketcode=MLESEA&countrycode=MV'
    l_headers = {"host": "myhost.com"}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    print json.dumps(l_r_json,indent=4)
    assert l_r_json['rule_intercept_status'] == 403
    #assert 'modsecurity_crs_23_request_limits.conf' in l_r_json['sub_event'][0]['rule_file']
    # ensure 403 because exceeded max_num_args
    assert 'UTF8 Encoding Abuse Attack Attempt' in l_r_json['rule_msg']
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_rules.waf.prof.json'))
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
            "replace_target" : "",
             "rule_id" : "950801",
             "is_regex" : False,
             "is_negated" : True,
             "target_match" : "origin",
             "target" : "ARGS"
        }]
    # ------------------------------------------------------
    # post conf
    # ------------------------------------------------------
    l_url = '%s/update_profile'%(G_TEST_HOST)
    # ------------------------------------------------------
    # urlopen (POST)
    # ------------------------------------------------------
    #print 'l_url:  %s'%(l_url)
    print 'l_body: %s'%(json.dumps(l_conf))
    l_headers = {"Content-Type": "application/json"}
    l_r = requests.post(l_url,
                            headers=l_headers,
                            data=json.dumps(l_conf))
    assert l_r.status_code == 200
    #assert l_result._status_code() == 200, 'non-200 for request: %s'%(json.dumps(l_url))
    #l_result = json.loads(l_result.text)
    #print l_result
    #-------------------------------------------------------
    # GET the same uri which returned a 403 before RTU
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    teardown_func()
    assert l_r.status_code == 100
    l_r_json = l_r.json()
    #-------------------------------------------------------
    # check no event is returned
    # ------------------------------------------------------
    #assert len(l_r_json) == 0 
    teardown_func()
