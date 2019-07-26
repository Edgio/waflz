#!/usr/bin/python
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
from pprint import pprint
import time
# ------------------------------------------------------------------------------
# globals
# ------------------------------------------------------------------------------
g_file_path = ''
g_ruleset_path = ''
g_wjc_path = ''
# ------------------------------------------------------------------------------
# fixture
# ------------------------------------------------------------------------------
@pytest.fixture(scope='module')
def setup_wjc():
    global g_file_path
    global g_ruleset_path
    global g_wjc_path
    l_cwd = os.getcwd()
    g_file_path = os.path.dirname(os.path.abspath(__file__))
    g_ruleset_path = os.path.realpath(os.path.join(g_file_path, '../../data/waf/ruleset'))
    g_wjc_path = os.path.abspath(os.path.join(g_file_path, '../../../build/util/wjc/wjc'))
# ------------------------------------------------------------------------------
# test output with bad regex
# ------------------------------------------------------------------------------
def test_bb_wjc_bad_regex(setup_wjc):
    global g_file_path
    global g_ruleset_path
    global g_wjc_path

    l_profile_path = os.path.realpath(os.path.join(g_file_path, 'test_bb_wjc_bad_regex.waf.prof.json'))
    l_sp = subprocess.Popen([g_wjc_path, '-p', l_profile_path, '-r', g_ruleset_path], stderr=subprocess.PIPE)
    l_sp_stderr =  l_sp.communicate()[1]
    #print(l_sp_stderr)
    #print('return code: %d'%(l_sp.returncode))
    assert l_sp.returncode != 0
    assert l_sp_stderr == 'compiling url blacklist\n'
# ------------------------------------------------------------------------------
# test output with bad regex
# ------------------------------------------------------------------------------
def test_bb_wjc_bad_asn(setup_wjc):
    global g_file_path
    global g_ruleset_path
    global g_wjc_path
    l_profile_path = os.path.realpath(os.path.join(g_file_path, 'test_bb_wjc_bad_asn.waf.prof.json'))
    l_sp = subprocess.Popen([g_wjc_path, '-p', l_profile_path, '-r', g_ruleset_path], stderr=subprocess.PIPE)
    l_sp_stderr =  l_sp.communicate()[1]
    #print(l_sp_stderr)
    #print('return code: %d'%(l_sp.returncode))
    assert l_sp.returncode != 0
    assert l_sp_stderr == 'expecting type: uint32 for field: \'waflz_pb.acl.lists_asn_t.blacklist\'\n'
