#!/usr/bin/python
'''Test WAF Ruleset Policies'''
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
from urllib2 import urlopen
from urllib2 import Request
import base64
# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------
G_TEST_HOST = 'http://127.0.0.1:12345'
# ------------------------------------------------------------------------------
# globals
# ------------------------------------------------------------------------------
g_server_pid = -1
# ------------------------------------------------------------------------------
# run_command
# ------------------------------------------------------------------------------
def run_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)
# ------------------------------------------------------------------------------
# fixture
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_func():
    global g_server_pid
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'));
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'));
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'template.waf.prof.json'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-f', l_conf_path,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path])
    print 'cmd: %s'%(' '.join([l_waflz_server_path,
                    '-f', l_conf_path,
                    '-r', l_ruleset_path,
                    '-g', l_geoip2city_path,
                    '-s', l_geoip2ISP_path]))
    g_server_pid = l_subproc.pid
    time.sleep(0.3)
# ------------------------------------------------------------------------------
# teardown_func
# ------------------------------------------------------------------------------
def teardown_func():
    global g_server_pid
    l_code, l_out, l_err = run_command('kill -9 %d'%(g_server_pid))
# ------------------------------------------------------------------------------
# run_around_tests
# ------------------------------------------------------------------------------
@pytest.yield_fixture(autouse=True)
def run_around_tests():
    # before
    setup_func()
    # ...
    yield
    # after
    teardown_func()
# ------------------------------------------------------------------------------
# check_rqst
# ------------------------------------------------------------------------------
def check_rqst(a_host, a_id, a_rqst):
    #print 'get_rqst: a_idx: %d'%(a_idx)
    #time.sleep(1.0)
    l_url = a_host
    l_headers = {'x-ec-waf-instance-id': str(a_id)}
    l_body = ''
    #l_headers = {'x-ec-waf-instance-id': str(1)}
    if 'uri' in a_rqst:
        l_url = '%s/%s'%(a_host, a_rqst['uri'])
    if 'query_str' in a_rqst:
        l_url += '?'
        l_url += a_rqst['query_str']
    if 'headers' in a_rqst and len(a_rqst['headers']):
        l_headers.update(a_rqst['headers'])
    if 'body' in a_rqst:
        l_body = base64.b64decode(a_rqst['body'])
    l_r = None  
    #print '*************************************************'
    #print 'l_url:     %s'%(l_url)
    #print 'l_headers: %s'%(l_headers)
    #print '*************************************************'
    try:
        l_rq = Request(url=l_url,
                       data=l_body,
                       headers=l_headers)
        l_r = urlopen(l_rq, timeout=20.0)
    except Exception as l_e:
        print 'error requesting.  Reason: %s error: %s, doc: %s, message: %s'%(
            type(l_e), l_e, l_e.__doc__, l_e.message)
        pass
    # ------------------------------------------------------
    # verify response exists
    # ------------------------------------------------------
    if not l_r:
        assert False, 'no response for request: %s'%(json.dumps(a_rqst))
    assert l_r.getcode() == 200, 'non-200 for request: %s'%(json.dumps(a_rqst))
    assert l_r.info().getheader('Content-Type') == 'application/json', 'wrong content-type: %s'%(l_r.info().getheader('Content-Type'))
    l_body = l_r.read()
    l_r_json = None
    try:
        l_r_json = json.loads(l_body)
    except:
        assert False, 'error parsing body'
    if not l_r_json:
        assert False, 'json body empty'
    print json.dumps(l_r_json, indent=4)
    if 'response' not in a_rqst:
        assert False, 'no response data in vector to verify: \n%s'%(json.dumps(a_rqst))
    # ------------------------------------------------------
    # check fields
    # ------------------------------------------------------
    l_v_r = a_rqst['response']
    for l_k, l_v in l_v_r.iteritems():
        if l_k == 'sub_event':
            l_num_to_match = len(l_v_r[l_k])
            for i_idx, i_s in enumerate(l_v_r[l_k]):
                print '-------------SUB_EVENT--------------'
                l_match = False
                print '++||||||||||| TESTING EACH |||||||||||||||||++'
                for i_actual_s in l_r_json[l_k]:
                    print 'i_actual_s: %s'%(json.dumps(i_actual_s))
                    # Find subevent matching since
                    # events could appear in any order
                    l_diff = False
                    for l_k_s, l_v_s in i_s.iteritems():
                        print 'XPECTD: %s: %s'%(l_k_s, l_v_s)
                        if l_k_s not in i_actual_s:
                            l_diff = True
                            continue;
                        print 'ACTUAL: %s: %s'%(l_k_s, i_actual_s[l_k_s])
                        if l_v_s != i_actual_s[l_k_s]:
                            l_diff = True
                            continue;
                    if not l_diff:
                        print '+FOUND*********************'
                        l_match = True
                        break
                if l_match:
                    print 'FOUND*********************'
                    l_num_to_match -= 1
                print '------------------------------------'
            assert l_num_to_match == 0, 'missing subevents'
        else:
            print 'XPECTD: %s --> %s'%(l_k, l_v)
            assert l_k in l_r_json
            print 'ACTUAL: %s --> %s'%(l_k, l_r_json[l_k])
            assert l_r_json[l_k] == l_v
# ------------------------------------------------------------------------------
# check_vectors
# ------------------------------------------------------------------------------
def check_vectors(a_file):
    # load files
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    # ------------------------------------------------------
    # read vector file
    # ------------------------------------------------------
    l_vector_path = os.path.realpath(os.path.join(l_file_path, a_file))
    l_vectors = {}
    try:
        with open(l_vector_path) as l_f:
            l_vectors = json.load(l_f)
    except Exception as l_e:
        print 'error opening vector file: %s.  Reason: %s error: %s, doc: %s, message: %s'%(
            l_vector_path, type(l_e), l_e, l_e.__doc__, l_e.message)
        assert False
    # ------------------------------------------------------
    # update template
    # ------------------------------------------------------
    l_conf = {}
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'template.waf.prof.json'))
    try:
        with open(l_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print 'error opening config file: %s.  Reason: %s error: %s, doc: %s, message: %s'%(
            l_conf_path, type(l_e), l_e, l_e.__doc__, l_e.message)
        assert False
    if 'config' in l_vectors:
        l_config_overrides = l_vectors['config']
        for l_k, l_v in l_config_overrides.iteritems():
            if isinstance(l_v, dict):
                for l_k_1, l_v_1 in l_v.iteritems():
                    l_conf[l_k][l_k_1] = l_v_1
            else:
                l_conf[l_k] = l_v
    # ------------------------------------------------------
    # post conf
    # ------------------------------------------------------
    l_url = '%s/update_profile'%(G_TEST_HOST)
    l_body = json.dumps(l_conf)
    # ------------------------------------------------------
    # urlopen (POST)
    # ------------------------------------------------------
    try:
        #print 'l_url:  %s'%(l_url)
        #print 'l_body: %s'%(l_body)
        l_rq = Request(l_url)
        l_rq.add_header('Content-Type','application/json')
        l_r = urlopen(l_rq, l_body, timeout=2)
    except Exception as l_e:
        print 'error: performing POST to %s. Exception: %s'% (l_url, l_e)
        assert False, ''
    assert l_r.getcode() == 200, 'non-200 for request: %s'%(json.dumps(l_url))
    # ------------------------------------------------------
    # validate
    # ------------------------------------------------------
    assert 'vectors' in l_vectors, 'no vectors field found in file: %s'%(l_vector_path)
    for i_v in l_vectors['vectors']:
        check_rqst(G_TEST_HOST, '4291', i_v)
# ------------------------------------------------------------------------------
# owasp 2.2.9 anomaly
# ------------------------------------------------------------------------------
def test_OWASP_2_2_9_anomaly():
    check_vectors('OWASP_2_2_9.anomaly.vectors.json')
# ------------------------------------------------------------------------------
# owasp 2.2.9 anomaly low inbound score
# ------------------------------------------------------------------------------
def test_OWASP_2_2_9_anomaly_low():
    check_vectors('OWASP_2_2_9.anomaly_low.vectors.json')
# ------------------------------------------------------------------------------
# owasp 3.0.2 anomaly
# ------------------------------------------------------------------------------
def test_OWASP_3_0_2_anomaly():
   check_vectors('OWASP_3_0_2.anomaly.vectors.json')
# ------------------------------------------------------------------------------
# owasp 3.0.2 anomaly low inbound score
# ------------------------------------------------------------------------------
def test_OWASP_3_0_2_anomaly_low():
   check_vectors('OWASP_3_0_2.anomaly_low.vectors.json')

