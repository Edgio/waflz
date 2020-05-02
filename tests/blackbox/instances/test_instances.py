#!/usr/bin/env python3
'''Test WAF instances with Policies'''
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
try:
    from urllib.request import urlopen
    from urllib.request import Request
except ImportError:
    # python2 fallback
    from urllib2 import urlopen
    from urllib2 import Request
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
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'template.waf.instance.json'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-i', l_conf_path,
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
# check_rqst
# ------------------------------------------------------------------------------
def check_rqst(a_host, a_id, a_rqst):
    # print('get_rqst: a_idx: %d'%(a_idx))
    # time.sleep(1.0)
    l_url = a_host
    l_headers = {'x-ec-waf-instance-id': str(a_id)}
    l_body = ''
    # l_headers = {'x-ec-waf-instance-id': str(1)}
    if 'uri' in a_rqst:
        l_url = '%s/%s' % (a_host, a_rqst['uri'])
    if 'query_str' in a_rqst:
        l_url += '?'
        l_url += a_rqst['query_str']
    if 'headers' in a_rqst and a_rqst['headers']:
        l_headers.update(a_rqst['headers'])
    if 'body' in a_rqst:
        l_body = base64.b64decode(a_rqst['body'])
    else:
        l_body = l_body.encode()
    l_r = None
    # print('*************************************************')
    # print('l_url:     %s'%(l_url))
    # print('l_headers: %s'%(l_headers))
    # print('*************************************************')
    try:
        l_rq = Request(url=l_url,
                       data=l_body,
                       headers=l_headers)
        l_r = urlopen(l_rq, timeout=20.0)
    except Exception as l_e:
        print('error requesting.  Reason: %s error: %s, doc: %s, message: %s' % (
            type(l_e), l_e, l_e.__doc__, l_e))
        pass
    # ------------------------------------------------------
    # verify response exists
    # ------------------------------------------------------
    if not l_r:
        assert False, 'no response for request: %s' % (json.dumps(a_rqst))
    assert l_r.getcode() == 200, 'non-200 for request: %s' % (json.dumps(a_rqst))
    assert l_r.info().get('Content-Type') == 'application/json', 'wrong content-type: %s' % (l_r.info().get('Content-Type'))
    l_body = l_r.read().decode()
    l_r_json = None
    try:
        l_r_json = json.loads(l_body)
    except:
        assert False, 'error parsing body'
    if not l_r_json:
        assert False, 'json body empty'
    print(json.dumps(l_r_json, indent=4))
    if 'response' not in a_rqst:
        assert False, 'no response data in vector to verify: \n%s'%(json.dumps(a_rqst))
    # ------------------------------------------------------
    # check fields
    # ------------------------------------------------------
    l_v_r = a_rqst['response']
    print(a_rqst)
    for l_k, l_v in l_v_r.items():
        if l_k == 'sub_event':
            l_num_to_match = len(l_v_r[l_k])
            for i_idx, i_s in enumerate(l_v_r[l_k]):
                print('-------------SUB_EVENT--------------')
                l_match = False
                print('++||||||||||| TESTING EACH |||||||||||||||||++')
                for i_actual_s in l_r_json['prod_profile'][l_k]:
                    print('i_actual_s: %s'%(json.dumps(i_actual_s)))
                    # Find subevent matching since
                    # events could appear in any order
                    l_diff = False

                    for l_k_s, l_v_s in i_s.items():
                        print('XPECTD: %s: %s'%(l_k_s, l_v_s))
                        if l_k_s not in i_actual_s:
                            l_diff = True
                            continue;
                        print('ACTUAL: %s: %s'%(l_k_s, i_actual_s[l_k_s]))
                        if l_v_s != i_actual_s[l_k_s]:
                            l_diff = True
                            continue;
                    if not l_diff:
                        print('+FOUND*********************')
                        l_match = True
                        break
                if l_match:
                    print('FOUND*********************')
                    l_num_to_match -= 1
                print('------------------------------------')
            assert l_num_to_match == 0, 'missing subevents'
        else:
            print('XPECTD: %s --> %s'%(l_k, l_v))
            assert l_k in l_r_json['prod_profile']
            print('ACTUAL: %s --> %s'%(l_k, l_r_json['prod_profile'][l_k]))
            assert l_r_json['prod_profile'][l_k] == l_v
    assert 'X-EC-Security' in l_r_json['prod_profile']['response_header_name']
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
        print('error opening vector file: %s.  Reason: %s error: %s, doc: %s' % (
            l_vector_path, type(l_e), l_e, l_e.__doc__))
        assert False
    # ------------------------------------------------------
    # update template
    # ------------------------------------------------------
    l_conf = {}
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'template.waf.instance.json'))
    try:
        with open(l_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    if 'config' in l_vectors:
        l_config_overrides = l_vectors['config']
        for l_k, l_v in l_config_overrides.items():
            if isinstance(l_v, dict):
                for l_k_1, l_v_1 in l_v.items():
                    l_conf['prod_profile'][l_k][l_k_1] = l_v_1
            else:
                l_conf['prod_profile'][l_k] = l_v
    # ------------------------------------------------------
    # post conf
    # ------------------------------------------------------
    l_url = '%s/update_instance'%(G_TEST_HOST)
    l_body = json.dumps(l_conf)
    # ------------------------------------------------------
    # urlopen (POST)
    # ------------------------------------------------------
    try:
        # print('l_url:  %s'%(l_url))
        # print('l_body: %s'%(l_body))
        l_rq = Request(l_url)
        l_rq.add_header('Content-Type', 'application/json')
        l_r = urlopen(l_rq, l_body.encode(), timeout=2)
    except Exception as l_e:
        print('error: performing POST to %s. Exception: %s'% (l_url, l_e))
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
def test_OWASP_2_2_9_anomaly(setup_waflz_server):
    check_vectors('OWASP_2_2_9.anomaly.vectors.json')
# ------------------------------------------------------------------------------
# owasp 2.2.9 anomaly low inbound score
# ------------------------------------------------------------------------------
def test_OWASP_2_2_9_anomaly_low(setup_waflz_server):
    check_vectors('OWASP_2_2_9.anomaly_low.vectors.json')
# ------------------------------------------------------------------------------
# owasp 3.0.2 anomaly
# ------------------------------------------------------------------------------
def test_OWASP_3_2_anomaly(setup_waflz_server):
   check_vectors('OWASP_3_2.anomaly.vectors.json')
# ------------------------------------------------------------------------------
# owasp 3.0.2 anomaly low inbound score
# ------------------------------------------------------------------------------
def test_OWASP_3_2_anomaly_low(setup_waflz_server):
   check_vectors('OWASP_3_2.anomaly_low.vectors.json')
# ------------------------------------------------------------------------------
# test_bb_instances_acl_first_before_waf
# ------------------------------------------------------------------------------
def test_bb_instances_acl_first_before_waf(setup_waflz_server):
    # test with a url that can be catched by waf. But ACL should catch it 
    # and event should be acl
    l_uri = G_TEST_HOST + '/mytest.asa?' + 'a=%27select%20*%20from%20testing%27'
    l_headers = {"host": "myhost.com"}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    # print(json.dumps(l_r_json,indent=4))
    assert l_r_json['prod_profile']['rule_intercept_status'] == 403
    assert l_r_json['audit_profile']['rule_intercept_status'] == 403
    # Both profiles should catch with acl
    assert 'File extension is not allowed by policy' in l_r_json['prod_profile']['rule_msg']
    assert 'File extension is not allowed by policy' in l_r_json['audit_profile']['rule_msg']
# ------------------------------------------------------------------------------
# test_bb_instances_acl_audit_waf_prod
# ------------------------------------------------------------------------------
def test_bb_instances_acl_audit_waf_prod(setup_waflz_server):
    # ------------------------------------------------------
    # update template
    # ------------------------------------------------------
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_conf = {}
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'template.waf.instance.json'))
    try:
        with open(l_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False

    l_conf['audit_profile']['general_settings']['disallowed_extensions'] = [
        "html"
    ]
    # ------------------------------------------------------
    # post conf
    # ------------------------------------------------------
    l_url = '%s/update_instance'%(G_TEST_HOST)
    # ------------------------------------------------------
    # urlopen (POST)
    # ------------------------------------------------------
    l_headers = {"Content-Type": "application/json"}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # test with a url that can be catched by waf. But ACL should catch it
    # and event should be acl
    l_uri = G_TEST_HOST + '/mytest.asa?' + 'a=%27select%20*%20from%20testing%27'
    l_headers = {"host": "myhost.com"}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    # print(json.dumps(l_r_json,indent=4))
    assert l_r_json['prod_profile']['rule_intercept_status'] == 403
    assert l_r_json['audit_profile']['rule_intercept_status'] == 403
    # same request but prod prodile should catch with acl
    assert 'File extension is not allowed by policy' in l_r_json['prod_profile']['rule_msg']
    # Audit profile should catch using waf
    assert 'Inbound Anomaly Score Exceeded (Total Score: 20): Last Matched Message: 981247-Detects concatenated basic SQL injection and SQLLFI attempts' in l_r_json['audit_profile']['rule_msg']
# ------------------------------------------------------------------------------
# test_bb_instances_whitelist_audit_waf_prod
# ------------------------------------------------------------------------------
def test_bb_instances_whitelist_audit_waf_prod(setup_waflz_server):
    # ------------------------------------------------------
    # update template
    # ------------------------------------------------------
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_conf = {}
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'template.waf.instance.json'))
    try:
        with open(l_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s'%(
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False

    l_conf['audit_profile']['access_settings']['url']['whitelist'] = ["mycooltest/bleep"]
    # ------------------------------------------------------
    # post conf
    # ------------------------------------------------------
    l_url = '%s/update_instance' % (G_TEST_HOST)
    print(l_conf['audit_profile']['general_settings'])
    # ------------------------------------------------------
    # urlopen (POST)
    # ------------------------------------------------------
    l_headers = {"Content-Type": "application/json"}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # test with a url that can be catched by waf. But ACL should catch it
    # and event should be acl
    l_uri = G_TEST_HOST + '/mycooltest/bleep?' + 'a=%27select%20*%20from%20testing%27'
    l_headers = {"host": "myhost.com"}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    # print(json.dumps(l_r_json,indent=4))
    # check that audit profile returns null because of whitelisted url
    assert l_r_json['audit_profile'] == None
    assert l_r_json['prod_profile']['rule_intercept_status'] == 403
    # same request but prod prodile should catch with waf
    # Test that whitelist are exlusive between audit and prod
    assert 'Inbound Anomaly Score Exceeded (Total Score: 20): Last Matched Message: 981247-Detects concatenated basic SQL injection and SQLLFI attempts' in l_r_json['prod_profile']['rule_msg']
