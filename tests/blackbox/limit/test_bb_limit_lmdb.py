#!/usr/bin/env python3
'''Test limit with lmdb'''
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
# setup single scopez server with lmdb
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_lmdb():
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
    yield setup_waflz_server_lmdb
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# setup three scopez server with lmdb in different ports
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_multiple_waflz_server_lmdb():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_scopes_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes'))
    l_an_list = os.path.realpath(os.path.join(l_file_path, '../../data/an/an-scopes.json'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_port1 = str(12345)
    l_port2 = str(12346)
    l_port3 = str(12347)
    # ------------------------------------------------------
    # start three scopez server in 3 ports
    # ------------------------------------------------------
    l_subproc1 = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-p', l_port1,
                                  '-L',
                                  '-j',
                                  '-I'])
    l_subproc2 = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-p', l_port2,
                                  '-L',
                                  '-j',
                                  '-I'])
    l_subproc3 = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-p', l_port3,
                                  '-L',
                                  '-j',
                                  '-I'])
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_multiple_waflz_server_lmdb
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc1.pid))
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc2.pid))
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc3.pid))

    time.sleep(0.5)

# ------------------------------------------------------------------------------
# Test single process rl using lmdb
# ------------------------------------------------------------------------------
def test_single_process_counting(setup_waflz_server_lmdb):
    # ------------------------------------------------------
    # Make 3 request in 2 sec.
    # 4th request should get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'limitz.com',
                 'waf-scopes-id': '0053'}
    for x in range(3):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200

    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'ddos enforcement from limit config\n'

    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'ddos enforcement from limit config\n'
    #sleep through enforcement period
    time.sleep(2)
# ------------------------------------------------------------------------------
# Test multiple process rl using lmdb
# Spread requests across multiple process.After enforcement, again start 
# making requests to the process in the same order, behavior should be same
# ------------------------------------------------------------------------------
def test_multiple_process_counting1(setup_multiple_waflz_server_lmdb):
    # ------------------------------------------------------
    # Make 3 request in 2 sec to different
    # waflz_server
    # ------------------------------------------------------
    l_url1 = 'http://127.0.0.1:12345/test.html'
    l_url2 = 'http://127.0.0.1:12346/test.html'
    l_url3 = 'http://127.0.0.1:12347/test.html'
    l_headers = {'host': 'limitz.com',
                 'waf-scopes-id': '0053'}
    l_r = requests.get(l_url1, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_url2, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_url3, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # 4th /subsequent request to
    # any of the process should get enforced
    # ------------------------------------------------------
    l_r = requests.get(l_url1, headers=l_headers)
    assert l_r.status_code == 403
    l_r = requests.get(l_url2, headers=l_headers)
    assert l_r.status_code == 403
    l_r = requests.get(l_url3, headers=l_headers)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    #  sleep through enforcement period,
    # make request again, counting should be reset
    # ------------------------------------------------------
    time.sleep(3)
    l_r = requests.get(l_url1, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_url2, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_url3, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # 4th request should be blocked
    # ------------------------------------------------------
    l_r = requests.get(l_url2, headers=l_headers)
    assert l_r.status_code == 403
    #sleep through enforcement period
    time.sleep(2)
# ------------------------------------------------------------------------------
# Test multiple process rl using lmdb - second scenario
# Spread 3 requests only across 1st and 2nd process. Make 4th request
# 3rd process. Enforcement should be thrown.
# This proves ttl in value is working properly, because 3rd process PQ
# would have been empty
# ------------------------------------------------------------------------------
def test_multiple_process_counting2(setup_multiple_waflz_server_lmdb):
    # ------------------------------------------------------
    # Make 3 request in 2 sec to 2 
    # waflz_server
    # ------------------------------------------------------
    l_url1 = 'http://127.0.0.1:12345/test.html'
    l_url2 = 'http://127.0.0.1:12346/test.html'
    l_url3 = 'http://127.0.0.1:12347/test.html'
    l_headers = {'host': 'limitz.com',
                 'waf-scopes-id': '0053'}
    l_r = requests.get(l_url1, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_url2, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_url2, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # Make 4th request to 3rd process 
    # ------------------------------------------------------
    l_r = requests.get(l_url3, headers=l_headers)
    assert l_r.status_code == 403
    #sleep through enforcement period
    time.sleep(2)
    # ------------------------------------------------------
    # Make requests again and check counting is reset
    # ------------------------------------------------------
    l_r = requests.get(l_url1, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_url2, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_url3, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_url2, headers=l_headers)
    assert l_r.status_code == 403
    #sleep through enforcement period
    time.sleep(2)
# ------------------------------------------------------------------------------
# Test multiple process rl using lmdb - third scenario
# This is to check if keys are getting cleared using PQ 
# Make 1 request for 1st scope which has the ttl of 2 seconds to P1.
# Sleep for 2 seconds and make request for 2nd scope to P1.
# This should have cleared scope1 key in P1 using PQ and counting should
# have been reset for scope1.
# ------------------------------------------------------------------------------
def test_multiple_process_counting3(setup_multiple_waflz_server_lmdb):
    l_url1 = 'http://127.0.0.1:12345/test.html'
    l_url2 = 'http://127.0.0.1:12346/test.html'
    l_url3 = 'http://127.0.0.1:12347/test.html'
    l_headers1 = {'host': 'limitz.com',
                 'waf-scopes-id': '0053'}
    # ------------------------------------------------------
    # Make 1st request for 1st scope to P1
    # ------------------------------------------------------
    l_r = requests.get(l_url1, headers=l_headers1)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # Sleep for ttl duration of 2 sec. Make requests to
    # P1 for 2nd scope. This should have cleared scope1
    # key using PQ
    # ------------------------------------------------------
    time.sleep(2)
    l_headers2 = {'host': 'Morelimitz.com',
                 'waf-scopes-id': '0053'}
    l_r = requests.get(l_url2, headers=l_headers2)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # check if counting is reset for scope1. Should get
    # blocked only on 4th request and make all the requests
    # to P2 and P3
    # ------------------------------------------------------
    l_r = requests.get(l_url2, headers=l_headers1)
    assert l_r.status_code == 200
    l_r = requests.get(l_url3, headers=l_headers1)
    assert l_r.status_code == 200
    l_r = requests.get(l_url2, headers=l_headers1)
    assert l_r.status_code == 200
    l_r = requests.get(l_url2, headers=l_headers1)
    assert l_r.status_code == 403
    l_r = requests.get(l_url3, headers=l_headers1)
    assert l_r.status_code == 403
    l_r = requests.get(l_url1, headers=l_headers1)
    assert l_r.status_code == 403
    #sleep through enforcement period
    time.sleep(2)
