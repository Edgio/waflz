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
    user agent black list and test
    '''
    # ------------------------------------------------------
    # test an 0050 with any acl in the request
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
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    l_conf['user_agent']['blacklist'] = []
    # ------------------------------------------------------
    # post conf
    # ------------------------------------------------------
    l_url = '%s/update_acl'%(G_TEST_HOST)
    print l_url
    # ------------------------------------------------------
    # (POST)
    # ------------------------------------------------------
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # blacklist should have been update and should get 200
    #-------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'gizoogle',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
