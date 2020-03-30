#!/usr/bin/env python3
'''Test config updates '''
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
import time
# ------------------------------------------------------------------------------
# Constants
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

def test_acl_config_update(setup_scopez_server_action):
    '''
    update acl config 0050-ZrLf2KkQ - remove gizoogle from
    user agent black list and test if request returns 200
    '''
    # ------------------------------------------------------
    # test an 0050 with user-agent acl 'gizoogle' in the 
    # request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'gizoogle',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is acl custom response\n'
    #-------------------------------------------------------
    # load acl config and remove gizoogle from blacklist
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_acl_conf_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/acl/0050-ZrLf2KkQ.acl.json'))
    try:
        with open(l_acl_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_acl_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    l_conf['user_agent']['blacklist'] = []
    # ------------------------------------------------------
    # post/update acl conf
    # ------------------------------------------------------
    l_url = '%s/update_acl'%(G_TEST_HOST)
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # blacklist should have been updated and should get 200
    #-------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'gizoogle',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200

def test_rules_config_update(setup_scopez_server_action):
    '''
    update rules config 0050-ZrLf3KKq.rules.json - change 
    user agent to Donkeez from Monkeez
    '''
    # ------------------------------------------------------
    # test an 0050 with user-agent 'Monkeez' in the 
    # request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'monkeez',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is rules custom response\n'
    #-------------------------------------------------------
    # load rules config and changes monkeez to donkeez in 
    # custom rules
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_rules_conf_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/rules/0050-ZrLf3KkQ.rules.json'))
    try:
        with open(l_rules_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    l_conf['directive'][1]['sec_rule']['operator']['value'] = 'donkeez'
    # ------------------------------------------------------
    # post/update rules conf
    # ------------------------------------------------------
    l_url = '%s/update_rules'%(G_TEST_HOST)
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # test again with user-agent 'Monkeez' in the 
    # request. It should pass
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'monkeez',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # test with user-agent 'donkeez' in the 
    # request. should be blocked
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'donkeez',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is rules custom response\n'

def test_profile_config_update(setup_scopez_server_action):
    '''
    update profile config 0050-YrLf3KkQ.wafprof.json - change
    ignore_query_args to test from ignore
    '''
    # ------------------------------------------------------
    # test an 0050 with sql injection
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/profile.html?a=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is profile custom response\n'
    # ------------------------------------------------------
    # test an 0050 with sql injection and query_args "ignore"
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/profile.html?ignore=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    #-------------------------------------------------------
    # load profile config and change "ignore_query_args"
    # to "test"
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_profile_conf_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/profile/0050-YrLf3KkQ.wafprof.json'))
    try:
        with open(l_profile_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_profile_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    l_conf["general_settings"]["ignore_query_args"] = ["test"]
    # ------------------------------------------------------
    # post/update profile conf
    # ------------------------------------------------------
    l_url = '%s/update_profile'%(G_TEST_HOST)
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # test an 0050 with sql injection and query_args "ignore"
    # should get 403
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/profile.html?ignore=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is profile custom response\n'
    # ------------------------------------------------------
    # test an 0050 with sql injection and query_args "test"
    # sql injection should be ignored and get 200
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/profile.html?test=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200

