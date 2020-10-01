#!/usr/bin/env python3
'''Test Json detection mechanism for avoid false positives'''
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
    l_profile_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_json_bodies.waf.prof.json'))
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
# helper for verifying json detection and event verification
# ------------------------------------------------------------------------------
def post_json_body_str_and_validate_event(a_body):
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'Content-Type': 'application/x-www-form-urlencoded',
                 'User-Agent': 'Mycooltest'}

    # ------------------------------------------------------
    # the default settings for this profile is the optimal
    # settings for a profile
    # Anomaly_threshold: 10
    # paranoia_level: 2
    # Json Parser: enabled
    # ------------------------------------------------------
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=a_body)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    #print(json.dumps(l_r_json,indent=4))
    #-------------------------------------------------------
    # check we have an event
    # ------------------------------------------------------
    assert l_r_json['rule_intercept_status'] == 403
    assert l_r_json['total_anomaly_score'] == 10
    assert len(l_r_json['sub_event']) == 2
    assert 'SQL Injection Attack: Common DB Names Detected' == l_r_json['sub_event'][0]['rule_msg']
    assert 'ARGS:PARAMETER' == l_r_json['sub_event'][0]['matched_var']['name']
    assert 'Detects MSSQL code execution and information gathering attempts' == l_r_json['sub_event'][1]['rule_msg']
    assert 'ARGS:PARAMETER' == l_r_json['sub_event'][1]['matched_var']['name']
# ------------------------------------------------------------------------------
# test_bb_json_in_url_encoded_c_type_generate_false_positive
# ------------------------------------------------------------------------------
def test_bb_json_in_url_encoded_c_type_generate_false_positive(setup_waflz_server):
    # ------------------------------------------------------
    # POST a json body with wrong content-type header
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'Content-Type': 'application/x-www-form-urlencoded',
                 'User-Agent': 'Mycooltest'}
    l_body = {
                'mmparams.d':{},
                'mmparams.p':{
                                'pd':'1631394411114|"2128210975|AgAAAApVAwAcbER6ihM/QAABEgABQgDwS9uNAQDQUYaallbYSLZfZtCSVthIAAAAAP//////////AAZEaXJlY3QBihMBAAAAAAAAAAAA////////////////AAAAAAAAAAFF"',
                                'bid':'1599859010741|"prodphxcgus01"',
                                'srv':'1631394411135|"prodphxcgus01"'
                             }
             }
    # ------------------------------------------------------
    # the default settings for this profile is the optimal
    # settings for a profile
    # Anomaly_threshold: 10
    # paranoia_level: 2
    # Json Parser: disabled
    # ------------------------------------------------------
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=json.dumps(l_body))
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    #print(json.dumps(l_r_json,indent=4))
    assert l_r_json['rule_intercept_status'] == 403
    assert l_r_json['total_anomaly_score'] == 10
    assert len(l_r_json['sub_event']) == 2
    # ------------------------------------------------------
    # When the content is parsed as url-encoded, whole json lands up in ARG_NAMES variables
    # This is a false positive
    assert l_r_json['matched_var']['name'] == 'ARGS_NAMES:{\"mmparams.d\": {}, \"mmparams.p\": {\"pd\": \"1631394411114|\\\"2128210975|AgAAAApVAwAcbER6ihM/QAABEgABQgDwS9uNAQDQUYaallbYSLZfZtCSVthIAAAAAP//////////AAZEaXJlY3QBihMBAAAAAAAAAAAA////////////////AAAAAAAAAAFF\\\"\", \"bid\": \"1599859010741|\\\"prodphxcgus01\\\"\", \"srv\": \"1631394411135|\\\"prodphxcgus01\\\"\"}}'
# ------------------------------------------------------------------------------
# test_bb_json_in_url_encoded_c_type_detect_json_when_parser_turned_on
# ------------------------------------------------------------------------------
def test_bb_json_in_url_encoded_c_type_detect_json_when_parser_turned_on(setup_waflz_server):
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_json_bodies.waf.prof.json'))
    try:
        with open(l_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    #-------------------------------------------------------
    # enable json parser for profile
    # ------------------------------------------------------
    l_conf['general_settings']['json_parser'] = True
    # ------------------------------------------------------
    # post conf
    # ------------------------------------------------------
    l_url = '%supdate_profile' % (G_TEST_HOST)
    # ------------------------------------------------------
    # urlopen (POST)
    # ------------------------------------------------------
    l_headers = {'Content-Type': 'application/json'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # POST a json body with wrong content-type header
    # This time the engine should detect JSON in body
    # and correctly parse contents. This will not cause any
    # alert unlike previous test
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'Content-Type': 'application/x-www-form-urlencoded',
                 'User-Agent': 'Mycooltest'}
    l_body = {
                'mmparams.d':{},
                'mmparams.p':{
                                'pd':'1631394411114|"2128210975|AgAAAApVAwAcbER6ihM/QAABEgABQgDwS9uNAQDQUYaallbYSLZfZtCSVthIAAAAAP//////////AAZEaXJlY3QBihMBAAAAAAAAAAAA////////////////AAAAAAAAAAFF"',
                                'bid':'1599859010741|"prodphxcgus01"',
                                'srv':'1631394411135|"prodphxcgus01"'
                             }
             }
    # ------------------------------------------------------
    # the default settings for this profile is the optimal
    # settings for a profile
    # Anomaly_threshold: 10
    # paranoia_level: 2
    # Json Parser: enabled
    # ------------------------------------------------------
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=json.dumps(l_body))
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    #-------------------------------------------------------
    # check no event is returned
    # ------------------------------------------------------
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
# ------------------------------------------------------------------------------
# test_bb_json_in_url_encoded_c_type_detect_SQLi
# ------------------------------------------------------------------------------
def test_bb_json_in_url_encoded_c_type_detect_SQLi(setup_waflz_server):
    # ------------------------------------------------------
    # POST a json body with wrong content-type header
    # The engine should detect JSON in body
    # and correctly parse contents. We send a SQLi attack
    # in the body, the engine should detect the attack
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'Content-Type': 'application/x-www-form-urlencoded',
                 'User-Agent': 'Mycooltest'}
    l_body = {
                'PARAMETER1': 'PARAMETER',
                'PARAMETER': 'PARAMETER:\'4\' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--'
             }
    # ------------------------------------------------------
    # the default settings for this profile is the optimal
    # settings for a profile
    # Anomaly_threshold: 10
    # paranoia_level: 2
    # Json Parser: enabled
    # ------------------------------------------------------
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=json.dumps(l_body))
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    #-------------------------------------------------------
    # check we have an event
    # ------------------------------------------------------
    assert l_r_json['rule_intercept_status'] == 403
    assert l_r_json['total_anomaly_score'] == 10
    assert len(l_r_json['sub_event']) == 2
    assert 'SQL Injection Attack: Common DB Names Detected' == l_r_json['sub_event'][0]['rule_msg']
    assert 'ARGS:PARAMETER' == l_r_json['sub_event'][0]['matched_var']['name']
    assert 'Detects MSSQL code execution and information gathering attempts' == l_r_json['sub_event'][1]['rule_msg']
    assert 'ARGS:PARAMETER' == l_r_json['sub_event'][1]['matched_var']['name']
# ------------------------------------------------------------------------------
# test_bb_json_in_url_encoded_c_type_detect_SQLi
# ------------------------------------------------------------------------------
def test_bb_detect_different_json_structures(setup_waflz_server):
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'Content-Type': 'application/x-www-form-urlencoded',
                 'User-Agent': 'Mycooltest'}
    # ------------------------------------------------------
    # Compose different combination of json strings
    # ------------------------------------------------------
    # ------------------------------------------------------
    # 1. { and spaces
    # ------------------------------------------------------
    l_body = "{                        \
                \"PARAMETER1\": \"PARAMETER\",\
                \"PARAMETER\": \"PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--\"\
              }"
    post_json_body_str_and_validate_event(l_body)
    # ------------------------------------------------------
    # 2. [{ and spaces
    # ------------------------------------------------------
    l_body = "[{                        \
                \"PARAMETER1\": \"PARAMETER\",\
                \"PARAMETER\": \"PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--\"\
              }]"
    post_json_body_str_and_validate_event(l_body)
    # ------------------------------------------------------
    # 3. tabs newline and spaces in the begining with list
    # ------------------------------------------------------
    l_body = "     \t\n   \n  [\t\t\n\n{\
                \"PARAMETER1\": \"PARAMETER\",\
                \"PARAMETER\": \"PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--\"\
              }"
    #print( 'string: {}'.format(l_body))
    post_json_body_str_and_validate_event(l_body)
    # ------------------------------------------------------
    # 4. {"
    # ------------------------------------------------------
    l_body = "{\"PARAMETER1\": \"PARAMETER\",\
                \"PARAMETER\": \"PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--\"\
              }"
    post_json_body_str_and_validate_event(l_body)
    # ------------------------------------------------------
    # 5. ["
    # ------------------------------------------------------
    l_body = "[\"abc\", {\"PARAMETER1\": \"PARAMETER\",\
                \"PARAMETER\": \"PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--\"\
              }]"
    post_json_body_str_and_validate_event(l_body)
    # ------------------------------------------------------
    # 6. [ and boolean
    # ------------------------------------------------------
    l_body = "[true, {\"PARAMETER1\": \"PARAMETER\",\
                \"PARAMETER\": \"PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--\"\
              }]"
    post_json_body_str_and_validate_event(l_body)
    l_body = "[false, {\"PARAMETER1\": \"PARAMETER\",\
                \"PARAMETER\": \"PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--\"\
              }]"
    post_json_body_str_and_validate_event(l_body)
    # ------------------------------------------------------
    # 7. [ and null
    # ------------------------------------------------------
    l_body = "[null, {\"PARAMETER1\": \"PARAMETER\",\
                \"PARAMETER\": \"PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--\"\
              }]"
    post_json_body_str_and_validate_event(l_body)
    
    # ------------------------------------------------------
    # 8. [ and number
    # ------------------------------------------------------
    l_body = "[0,2, {\"PARAMETER1\": \"PARAMETER\",\
                \"PARAMETER\": \"PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--\"\
              }]"
    post_json_body_str_and_validate_event(l_body)
    l_body = "[1,2, {\"PARAMETER1\": \"PARAMETER\",\
                \"PARAMETER\": \"PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--\"\
              }]"
    post_json_body_str_and_validate_event(l_body)
    l_body = "[9,2, {\"PARAMETER1\": \"PARAMETER\",\
                \"PARAMETER\": \"PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--\"\
              }]"
    post_json_body_str_and_validate_event(l_body)