#!/usr/bin/env python3
'''Test limit '''
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
# setup waflz server with scopes
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_scopes_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-L',
                                  '-j'])
    print('cmd: \n{}\n'.format(' '.join([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-L',
                                  '-j'])))
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
# setup waflz server with only limit and geoip db's
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_limit():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_limit_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/limit/0053-kobjYva2.limit.json'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-l', l_limit_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-j'])
    print('cmd: \n{}\n'.format(' '.join([l_waflz_server_path,
                                  '-l', l_limit_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-j'])))
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_limit
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)

# ------------------------------------------------------------------------------
# Test geo condition group
# ------------------------------------------------------------------------------
def test_geo_condition_group(setup_waflz_server):
    # ------------------------------------------------------
    # Make 2 request in 2 sec from brazil IP.
    # 3rd request should get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'limitzgeo.com',
                 'waf-scopes-id': '0053',
                 'x-waflz-ip':'200.196.153.102'}
    for x in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200

    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'geo ddos enforcement\n'

    # Make a request from US ip for the same 
    # scope during enforcement
    # window. Request should get through
    l_headers['x-waflz-ip'] = '34.200.39.53'
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200

    # Change to US ip and make requests above threshold.
    # Requests shouldn't get blocked
    l_headers['x-waflz-ip'] = '34.200.39.53'
    for x in range(5):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200

    #sleep through enforcement period
    time.sleep(2)
# ------------------------------------------------------------------------------
# Test asn condition group
# ------------------------------------------------------------------------------
def test_asn_condition_group(setup_waflz_server):
    # ------------------------------------------------------
    # Make 2 request in 2 sec from Japan IP.
    # 3rd request should get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.txt?version=2.2.2'
    l_headers = {'host': 'limitzasn.com',
                 'waf-scopes-id': '0053',
                 'x-waflz-ip':'202.32.115.5'}
    # ------------------------------------------------------
    # Make 2 request in 2 sec from Japan IP & different file
    # ext, .txt and .js. They both should contribute to counts
    # because of condition groups
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_uri = G_TEST_HOST+'/test.js?version=2.2.2'
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # 3rd request should get rate limited
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'asn ddos enforcement\n'
     # ------------------------------------------------------
    # 4rd request should go through because of diff file_ext
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # Make a request from US ip & different file_ext for
    # the same scope during enforcement
    # window. Request should get through
    # ------------------------------------------------------
    l_headers['x-waflz-ip'] = '34.200.39.53'
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200

    # Change to US ip and make requests above threshold.
    # Requests shouldn't get blocked
    l_uri = G_TEST_HOST+'/test.html'
    l_headers['x-waflz-ip'] = '34.200.39.53'
    for x in range(5):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200

    #sleep through enforcement period
    time.sleep(2)
# ------------------------------------------------------------------------------
# Test both geo and asn in single condition group
# ------------------------------------------------------------------------------
def test_asn_and_geo_cg(setup_waflz_server_limit):
    # ------------------------------------------------------
    # Make 2 request in 2 sec from US IP and ASN 15133.
    # 3rd request should get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'x-waflz-ip':'192.229.234.2'}
    for x in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200

    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403

    # Sleep through enforcement period 
    time.sleep(2)

    # Make single request again. should go through
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200

    # Make 4 request from US ip, but from different
    # ASN. All requests should go through
    l_headers['x-waflz-ip'] = '162.115.42.1'
    for x in range(4):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200


