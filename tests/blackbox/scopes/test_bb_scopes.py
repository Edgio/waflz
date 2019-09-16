#!/usr/bin/python
'''Test scopes with custom rules'''
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
from urllib2 import urlopen
from urllib2 import Request
import base64
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
# setup scopez server with scopes dir
# ------------------------------------------------------------------------------
@pytest.fixture(scope='module')
def setup_scopez_server():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_scopez_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_scopez_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/scopez_server/scopez_server'))
    l_subproc = subprocess.Popen([l_scopez_server_path,
                                  '-d', l_conf_dir,
                                  '-S', l_scopez_dir,
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
# setup scopez server with single scope
# ------------------------------------------------------------------------------
@pytest.fixture(scope='module')
def setup_scopez_server_single():
     # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_scopez_file = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes/0050.scopes.json'))
    l_scopez_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/scopez_server/scopez_server'))
    l_subproc = subprocess.Popen([l_scopez_server_path,
                                  '-d', l_conf_dir,
                                  '-s', l_scopez_file,
                                  '-g', l_geoip2city_path,
                                  '-i', l_geoip2ISP_path])
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
                 'user-agent':'monkeez',
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
                 'user-agent':'bananas',
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
                 'user-agent':'monkeez',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is monkeez'
