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
    l_profile_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_profile.waf.prof.json'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-f', l_profile_path,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path])
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
# test_bb_profile_01_no_log_matched_data
# ------------------------------------------------------------------------------
def test_bb_profile_01_no_log_matched_data(setup_waflz_server):
    l_uri = G_TEST_HOST + '/?a=%27select%20*%20from%20testing%27'
    l_headers = {'Host': 'myhost.com'}
    l_r = requests.get(url=l_uri,
                        headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    l_matched_var_name = 'ARGS:a'
    l_matched_var_value = '\'select * from testing\''
    assert l_matched_var_name == base64.b64decode(l_r_json['matched_var']['name']).decode("utf-8")
    assert l_matched_var_value == base64.b64decode(l_r_json['matched_var']['value']).decode("utf-8")
    assert l_matched_var_name == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['name']).decode("utf-8")
    assert l_matched_var_value == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['value']).decode("utf-8")
    #-------------------------------------------------------
    # create config
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_profile.waf.prof.json'))
    try:
        with open(l_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    #-------------------------------------------------------
    # Update profile to not log matched data value
    # ------------------------------------------------------
    l_conf['general_settings']['no_log_matched'] = True
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
    # ------------------------------------------------------
    # test again verify that matched data value is scrubbed
    # ------------------------------------------------------
    l_headers = {'Host': 'myhost.com'}
    l_r = requests.get(url=l_uri,
                        headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert l_matched_var_name == base64.b64decode(l_r_json['matched_var']['name']).decode("utf-8")
    assert '**SANITIZED**' == base64.b64decode(l_r_json['matched_var']['value']).decode("utf-8")
    assert l_matched_var_name == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['name']).decode("utf-8")
    assert '**SANITIZED**' == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['value']).decode("utf-8")
    assert '2022-05-7T19:48:25.142172Z' == l_r_json['config_last_modified']
