#!/usr/bin/env python3
'''Test scopes with custom rules'''
# ------------------------------------------------------------------------------
# Imports
# ------------------------------------------------------------------------------
import subprocess
import os
import json
import time
import re
import requests
import pytest
try:
    from html.parser import HTMLParser
except ImportError:
    # python2 fallback
    from HTMLParser import HTMLParser
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
# setup waflz server in event mode
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_scopes_dir = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/conf/scopes'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/conf'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/ruleset'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
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
# setup waflz server in action mode
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_action():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    # l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/conf'))
    l_challenge = os.path.realpath(os.path.join(l_file_path, '../../../data/bot/bot-challenges.json'))
    l_cust_chal_js = os.path.realpath(os.path.join(l_file_path, '../../../data/bot/bot-js.txt'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/ruleset'))
    l_scopes_dir = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/conf/scopes'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-c', l_challenge,
                                  '-n', l_cust_chal_js,
                                  '-j'])
    print('cmd: \n{}\n'.format(' '.join([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-c', l_challenge,
                                  '-n', l_cust_chal_js,
                                  '-j'])))
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_action
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    _, _, _ = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# setup waflz server in action mode for custom challenge
# load only the js to be inserted for custom challenge.
# not loading global challenge in this server to test custom challenge
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_custom_challenge():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    # l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/conf'))
    l_cust_chal_js = os.path.realpath(os.path.join(l_file_path, '../../../data/bot/bot-js.txt'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/ruleset'))
    l_scopes_dir = os.path.realpath(os.path.join(l_file_path, '../../../data/waf/conf/scopes'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-n', l_cust_chal_js,
                                  '-j'])
    print('cmd: \n{}\n'.format(' '.join([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-n', l_cust_chal_js,
                                  '-j'])))
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_custom_challenge
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    _, _, _ = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# parse html
# ------------------------------------------------------------------------------
class html_parse(HTMLParser):
   #Store data
   m_data = ""
   def handle_data(self, data):
        if data.startswith('function'):
            self.m_data = data

class custom_html_parse(HTMLParser):
    m_data = ""
    def handle_data(self, data):
        if data.startswith('window.onload'):
            self.m_data = data
# ------------------------------------------------------------------------------
# Solve browser challenge
# TODO: This is based on assumption that the problem will be a simple addition
# operation in js. If problem changes in data file, this needs to be updated
# ------------------------------------------------------------------------------
def solve_challenge(a_html):
    l_problem_p = re.search('val =.[0-9]{3}\+[0-9]{3}', a_html)
    l_problem_vars = l_problem_p.group(0).split("=")[-1].split('+')

    l_solution = int(l_problem_vars[0]) + int(l_problem_vars[1])
    l_ectoken_p = re.search('__ecbmchid=(.*?)"', a_html)
    l_ectoken = l_ectoken_p.group(0)
    return '__eccha = ' + str(l_solution) + ';' + l_ectoken[:-1]
# ------------------------------------------------------------------------------
# test bot challenge events with both bot rule & bot manager config
# TODO: remove this test and corresponding scope after migration
# ------------------------------------------------------------------------------
def test_challenge_events(setup_waflz_server):
    # ------------------------------------------------------
    # test for recieving a bot challenge
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['challenge_status'] == "CHAL_STATUS_NO_TOKEN"
    assert l_r_json['prod_profile']['token_duration_sec'] == 3
    assert l_r_json['prod_profile']['config_last_modified'] == "2019-04-18T19:48:25.142172Z"
    #verify alert is coming from bot manager
    assert 'bot_manager_config_id' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['bot_manager_config_id'] == "7kDny8RP"
    assert 'scope_config_id' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['scope_config_id'] == "Rml2d8dr"
    # ------------------------------------------------------
    # send random corrupted token
    # ------------------------------------------------------
    l_solution_cookies = '__ecbmchid=d3JvbmdfdG9rZW4K;__eccha=300'
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['challenge_status'] == "CHAL_STATUS_TOKEN_CORRUPTED"
    assert l_r_json['prod_profile']['token_duration_sec'] == 3
    assert 'bot_manager_config_id' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['bot_manager_config_id'] == "7kDny8RP"
# ------------------------------------------------------------------------------
# test bot challenge in action mode in a scope with both
# bot rule and bot manager config
# TODO: remove this test after migration to bot manager
# ------------------------------------------------------------------------------
def test_challenge_in_bot_config(setup_waflz_server_action):
    # ------------------------------------------------------
    # test for recieving a bot challenge
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # solve challenge
    # ------------------------------------------------------
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data
    l_solution_cookies = solve_challenge(l_parser.m_data)
    # ------------------------------------------------------
    # test again with solved challenge and cookies
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    #-------------------------------------------------------
    # check no event is returned
    # ------------------------------------------------------
    assert l_r_json['errors'][0]['message'] == 'OK'
    #-------------------------------------------------------
    # sleep for 3 seconds for challenge to expire
    # ------------------------------------------------------
    time.sleep(3)
    # ------------------------------------------------------
    # test with previous solved challenge, new challenge
    # should be returned
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data
# ------------------------------------------------------------------------------
# test bot challenge with limits in a scope with both bot manager and
# bot rules
# TODO: remove this test after migration to bot manager
# ------------------------------------------------------------------------------
def test_challenge_with_limits(setup_waflz_server_action):
    # ------------------------------------------------------
    # test for recieving a bot challenge
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # solve challenge
    # ------------------------------------------------------
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data
    l_solution_cookies = solve_challenge(l_parser.m_data)
    # ------------------------------------------------------
    # send the solved challenge thrice
    # rate limiting should block the request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == "ddos enforcement from bot config\n"
    # ------------------------------------------------------
    # sleep for 3 seconds for challenge and rate limiting
    # enforcement to expire
    # ------------------------------------------------------
    time.sleep(3)
    # ------------------------------------------------------
    # test with previous solved challenge, new challenge
    # should be returned
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data
# ------------------------------------------------------------------------------
# test bot challenge with profile in a scope with both
# bot manager and bot rules
# TODO: Remove after migration
# ------------------------------------------------------------------------------
def test_challenge_with_profile(setup_waflz_server_action):
    # ------------------------------------------------------
    # test for recieving a bot challenge with attack vector
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html?a=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # solve challenge
    # ------------------------------------------------------
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data
    l_solution_cookies = solve_challenge(l_parser.m_data)
    # ------------------------------------------------------
    # send the solved challenge with attack vector
    # should get custoem response from profile
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html?a=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is profile custom response\n'
    # ------------------------------------------------------
    # send the solved challenge without attack vector
    # request should go through
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    #-------------------------------------------------------
    # check no event is returned
    # ------------------------------------------------------
    assert l_r_json['errors'][0]['message'] == 'OK'
    #-------------------------------------------------------
    # sleep for 3 seconds for challenge to expire
    # ------------------------------------------------------
    time.sleep(3)
    # ------------------------------------------------------
    # test with previous solved challenge, new challenge
    # should be returned
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data

# ------------------------------------------------------------------------------
# test bot challenge events from bot manager config
# ------------------------------------------------------------------------------
def test_challenge_events_in_bot_manager(setup_waflz_server):
    # ------------------------------------------------------
    # test for recieving a bot challenge
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['challenge_status'] == "CHAL_STATUS_NO_TOKEN"
    assert l_r_json['prod_profile']['token_duration_sec'] == 3
    assert l_r_json['prod_profile']['config_last_modified'] == "2019-04-18T19:48:25.142172Z"
    #verify alert is coming from bot manager
    assert 'bot_manager_config_id' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['bot_manager_config_id'] == "7kDny8RP"
    assert 'scope_config_id' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['scope_config_id'] == "ft3l_JSX"
    # ------------------------------------------------------
    # send random corrupted token
    # ------------------------------------------------------
    l_solution_cookies = '__ecbmchid=d3JvbmdfdG9rZW4K;__eccha=300'
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['challenge_status'] == "CHAL_STATUS_TOKEN_CORRUPTED"
    assert l_r_json['prod_profile']['token_duration_sec'] == 3
    assert 'bot_manager_config_id' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['bot_manager_config_id'] == "7kDny8RP"
# ------------------------------------------------------------------------------
# test bot challenge in action mode 
# ------------------------------------------------------------------------------
def test_challenge_in_bot_manager(setup_waflz_server_action):
    # ------------------------------------------------------
    # test for recieving a bot challenge
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # solve challenge
    # ------------------------------------------------------
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data
    l_solution_cookies = solve_challenge(l_parser.m_data)
    # ------------------------------------------------------
    # test again with solved challenge and cookies
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    #-------------------------------------------------------
    # check no event is returned
    # ------------------------------------------------------
    assert l_r_json['errors'][0]['message'] == 'OK'
    #-------------------------------------------------------
    # sleep for 3 seconds for challenge to expire
    # ------------------------------------------------------
    time.sleep(3)
    # ------------------------------------------------------
    # test with previous solved challenge, new challenge
    # should be returned
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data
# ------------------------------------------------------------------------------
# test bot challenge with limits 
# ------------------------------------------------------------------------------
def test_challenge_with_limits_using_botmanager(setup_waflz_server_action):
    # ------------------------------------------------------
    # test for recieving a bot challenge
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # solve challenge
    # ------------------------------------------------------
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data
    l_solution_cookies = solve_challenge(l_parser.m_data)
    # ------------------------------------------------------
    # send the solved challenge thrice
    # rate limiting should block the request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == "ddos enforcement from bot config\n"
    # ------------------------------------------------------
    # sleep for 3 seconds for challenge and rate limiting
    # enforcement to expire
    # ------------------------------------------------------
    time.sleep(3)
    # ------------------------------------------------------
    # test with previous solved challenge, new challenge
    # should be returned
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data
# ------------------------------------------------------------------------------
# test bot challenge with profile 
# ------------------------------------------------------------------------------
def test_challenge_with_profile_using_botmanager(setup_waflz_server_action):
    # ------------------------------------------------------
    # test for recieving a bot challenge with attack vector
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html?a=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # solve challenge
    # ------------------------------------------------------
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data
    l_solution_cookies = solve_challenge(l_parser.m_data)
    # ------------------------------------------------------
    # send the solved challenge with attack vector
    # should get custoem response from profile
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html?a=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is profile custom response\n'
    # ------------------------------------------------------
    # send the solved challenge without attack vector
    # request should go through
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    #-------------------------------------------------------
    # check no event is returned
    # ------------------------------------------------------
    assert l_r_json['errors'][0]['message'] == 'OK'
    #-------------------------------------------------------
    # sleep for 3 seconds for challenge to expire
    # ------------------------------------------------------
    time.sleep(3)
    # ------------------------------------------------------
    # test with previous solved challenge, new challenge
    # should be returned
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data
# ------------------------------------------------------------------------------
# test custom challenge in bot manager config
# ------------------------------------------------------------------------------
def test_custom_challenge(setup_waflz_server_custom_challenge):
    # ------------------------------------------------------
    # test for recieving a bot challenge
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mycustombotmanagerchallenge.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # solve challenge
    # ------------------------------------------------------
    l_parser = custom_html_parse()
    l_parser.feed(l_r.text)

    assert 'function()' in l_parser.m_data
    l_solution_cookies = solve_challenge(l_parser.m_data)
    # ------------------------------------------------------
    # test again with solved challenge and cookies
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mycustombotmanagerchallenge.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    #-------------------------------------------------------
    # check no event is returned
    # ------------------------------------------------------
    assert l_r_json['errors'][0]['message'] == 'OK'
    #-------------------------------------------------------
    # sleep for 3 seconds for challenge to expire
    # ------------------------------------------------------
    time.sleep(3)
    # ------------------------------------------------------
    # test with previous solved challenge, new challenge
    # should be returned
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mycustombotmanagerchallenge.com',
                 'user-agent': 'bot-testing',
                 'Cookie': l_solution_cookies,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    l_parser = custom_html_parse()
    l_parser.feed(l_r.text)
    assert 'function()' in l_parser.m_data
