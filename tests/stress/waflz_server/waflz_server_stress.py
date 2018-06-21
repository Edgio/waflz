#!/usr/bin/python
# ------------------------------------------------------------------------------
# stress test waflz_server
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# Imports
# ------------------------------------------------------------------------------
import sys
import argparse
import time
import signal
import json
from urllib2 import urlopen
from urllib2 import Request
import random
import base64
import datetime
# ------------------------------------------------------------------------------
# Globals
# ------------------------------------------------------------------------------
g_run = True
# ------------------------------------------------------------------------------
# 
# ------------------------------------------------------------------------------
def signal_handler(signal, frame):
    global g_run
    g_run = False
# ------------------------------------------------------------------------------
# 
# ------------------------------------------------------------------------------
def print_banner():
    print '+-----------------------------------------------------------------------------+'
    print '|            W A F L Z   S E R V E R   S T R E S S   T E S T E R              |'
    print '+------------+------------+------------+------------+------------+------------+'
    print '| Req/s      | 200s       | 300s       | 400s       | 500s       | Confs/s    |'
    print '+------------+------------+------------+------------+------------+------------+'
# ------------------------------------------------------------------------------
# 
# ------------------------------------------------------------------------------
def print_stats_line(a_time_delta_ms, a_num_reqs, a_num_configs, a_results):
    if '200' not in a_results:
        a_results['200'] = 0
    if '300' not in a_results:
        a_results['300'] = 0
    if '400' not in a_results:
        a_results['400'] = 0
    if '500' not in a_results:
        a_results['500'] = 0
    print '| %10.2f | %10d | %10d | %10d | %10d | %10d |'%(
        (a_num_reqs*1000/a_time_delta_ms),
        a_results['200'],
        a_results['300'],
        a_results['400'],
        a_results['500'],
        (a_num_configs*1000/a_time_delta_ms))
# ------------------------------------------------------------------------------
# 
# ------------------------------------------------------------------------------
def get_rqst(a_host, a_id, a_vectors, a_idx, a_results):
    #print 'get_rqst: a_idx: %d'%(a_idx)
    #time.sleep(1.0)
    l_url = a_host
    l_v = a_vectors[a_idx]
    l_headers = {'x-ec-waf-instance-id': str(a_id)}
    l_body = ''
    #l_headers = {'x-ec-waf-instance-id': str(1)}
    if 'uri' in l_v:
        l_url = '%s/%s'%(a_host, l_v['uri'])
    if 'query_string' in l_v:
        l_url += '?'
        l_url += l_v['query_string']
    if 'headers' in l_v and len(l_v['headers']):
        l_headers.update(l_v['headers'])
    if 'body' in l_v:
        l_body = base64.b64decode(l_v['body'])
    l_r = None  
    try:
        #print 'l_url:     %s'%(l_url)
        #print 'l_headers: %s'%(l_headers)
        l_rq = Request(url=l_url,
                       data=l_body,
                       headers=l_headers)
        l_r = urlopen(l_rq, timeout=20.0)
    except Exception as l_e:
        print 'error requesting.  Reason: %s error: %s, doc: %s, message: %s'%(
            type(l_e), l_e, l_e.__doc__, l_e.message)
        pass
    # ------------------------------------------------------
    # codes
    # ------------------------------------------------------
    if not l_r:
        if '500' in a_results:
            a_results['500'] += 1
        else:
            a_results['500'] = 1
    else:
        l_code = l_r.getcode()
        if l_code >= 200 and l_code < 300:
            if '200' in a_results:
                a_results['200'] += 1
            else:
                a_results['200'] = 1
        if l_code >= 300 and l_code < 400:
            if '300' in a_results:
                a_results['300'] += 1
            else:
                a_results['300'] = 1
        if l_code >= 400 and l_code < 500:
            if '400' in a_results:
                a_results['400'] += 1
            else:
                a_results['400'] = 1
        if l_code >= 500 and l_code < 600:
            if '500' in a_results:
                a_results['500'] += 1
            else:
                a_results['500'] = 1
    #if l_r.getcode() != 200:
    #    print 'error: performing GET to %s -status: %d. Response: %s'%(l_url, l_r.getcode(), l_body)
    #    sys.exit(1)
    #try:
    #    l_body = l_r.read()
    #    l_r_json = json.loads(l_body)
    #except:
    #    print 'error: performing POST to %s Response not json'%(l_url)
    #    sys.exit(1)
    #print l_r_json
# ------------------------------------------------------------------------------
# 
# ------------------------------------------------------------------------------
def post_config(a_host, a_template, a_idx):    
    #print 'post_config: a_idx: %s'%(a_idx)
    #print json.dumps(a_template)
    #if 'id' in a_template:
    #    a_template['id'] = str(a_idx)
    #else:
    #    a_template['id'] = '1'
    if isinstance(a_template, list):
        for l_instance in a_template:
            if 'last_modified_date' in l_instance:
                l_instance['last_modified_date'] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if 'id' in l_instance:
           l_instance['id'] = str(a_idx)
        else:
           l_instance['id'] = '1'
    else:
        if "last_modified_date" in a_template:
            a_template['last_modified_date'] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if 'id' in a_template:
           a_template['id'] = str(a_idx)
        else:
           a_template['id'] = '1'
    l_headers = {}
    l_headers['Content-type'] = 'application/json'
    l_url = '%s/update_instance'%(a_host)
    l_body = json.dumps(a_template)
    #print l_body
    # ------------------------------------------------------
    # urlopen (POST)
    # ------------------------------------------------------
    try:
        l_rq = Request(l_url, l_body, l_headers)
        l_r = urlopen(l_rq, timeout=20.0)
    except Exception as l_e:
        print 'error: performing POST to %s. Exception: %s'% (l_url, l_e)
        sys.exit(1)
    l_body = l_r.read()
    if l_r.getcode() != 200:
        print 'error: performing POST to %s -status: %d. Response: %s'%(l_url, l_r.getcode(), l_body)
        sys.exit(1)
    #try:
    #    l_body = l_r.read()
    #    l_r_json = json.loads(l_body)
    #except:
    #    print 'error: performing POST to %s Response not json'%(l_url)
    #    sys.exit(1)
    #print l_r_json
# ------------------------------------------------------------------------------
# 
# ------------------------------------------------------------------------------
def waflz_server_stress(a_verbose,
                        a_port,
                        a_template,
                        a_vector_file,
                        a_num_ids):

    global g_run
    l_host = 'http://127.0.0.1:%d'%(a_port)
    # ------------------------------------------------------
    # read template
    # ------------------------------------------------------
    l_template = []
    try:
        with open(a_template) as l_f:
            l_template = json.load(l_f)
    except Exception as l_e:
        print 'error opening template file: %s.  Reason: %s error: %s, doc: %s, message: %s'%(
            a_vector_file, type(l_e), l_e, l_e.__doc__, l_e.message)
        sys.exit(-1)
    print 'preloading configs'
    l_time_ms_last = time.time()*1000
    i_c = 0
    while g_run:
        i_c += 1
        post_config(l_host, l_template, i_c)
        l_time_ms_cur = time.time()*1000
        if l_time_ms_cur > (l_time_ms_last + 100):
            l_time_ms_last = time.time()*1000
            l_time_ms_next = l_time_ms_last + 100
            print '%6.2f done'%((((float(i_c))) / (a_num_ids)) *100.0)
        if i_c == a_num_ids:
            break
    if not g_run:
        return
    print_banner()
    # ------------------------------------------------------
    # read vector file
    # ------------------------------------------------------
    l_vectors = []
    try:
        with open(a_vector_file) as l_f:
            l_vectors = json.load(l_f)
    except Exception as l_e:
        print 'error opening vector file: %s.  Reason: %s error: %s, doc: %s, message: %s'%(
            a_vector_file, type(l_e), l_e, l_e.__doc__, l_e.message)
        sys.exit(-1)
    #print l_vectors
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_v_size = len(l_vectors)
    l_v_idx = 0
    l_time_ms_last = time.time()*1000
    l_num_reqs = 0
    l_num_reqs_total = 0
    l_num_confs = 0
    l_num_confs_total = 0
    l_results = {}
    # ------------------------------------------------------
    # run...
    # ------------------------------------------------------
    while g_run:
        l_id = random.randint(1,a_num_ids)
        get_rqst(l_host, l_id, l_vectors, l_v_idx, l_results)
        l_v_idx += 1
        if l_v_idx >= l_v_size:
            l_v_idx = 0
        l_num_reqs += 1
        l_num_reqs_total += 1
        if l_num_reqs_total % 100 == 0:
            post_config(l_host, l_template, int(l_id))
            l_num_confs += 1
            l_num_confs_total += 1
        l_time_ms_cur = time.time()*1000
        if l_time_ms_cur > (l_time_ms_last + 100):
            print_stats_line(l_time_ms_cur - l_time_ms_last, l_num_reqs, l_num_confs, l_results)
            l_time_ms_last = time.time()*1000
            l_time_ms_next = l_time_ms_last + 100
            l_num_reqs = 0
            l_num_confs = 0
            l_results = {}
    # ------------------------------------------------------
    # done...
    # ------------------------------------------------------
    print '...shutting down...'
# ------------------------------------------------------------------------------
# main
# ------------------------------------------------------------------------------
def main(argv):
    l_arg_parser = argparse.ArgumentParser(
        description='waflz_server stress tester',
        usage= '%(prog)s -t <instance_template>',
        epilog= '')
    l_arg_parser.add_argument(
        '-v',
        '--verbose',
        dest='verbose',
        help='Verbosity.',
        action='store_true',
        default=False,
        required=False)
    l_arg_parser.add_argument(
        '-t',
        '--template',
        dest='template',
        help='instance template (REQUIRED).',
        required=True)
    l_arg_parser.add_argument(
        '-x',
        '--vectors',
        dest='vector_file',
        help='request vector file (REQUIRED).',
        required=True)
    l_arg_parser.add_argument(
        '-p',
        '--port',
        dest='port',
        help='waflz_server port (default: 12345).',
        default=12345,
        type=int,
        required=False)
    l_arg_parser.add_argument(
        '-n',
        '--num_ids',
        dest='num_ids',
        help='number of account id\'s to cycle through (default: 10).',
        type=int,
        default=1,
        required=False)
    l_args = l_arg_parser.parse_args()
    signal.signal(signal.SIGINT, signal_handler)
    waflz_server_stress(a_verbose=l_args.verbose,
                        a_port=l_args.port,
                        a_template=l_args.template,
                        a_vector_file=l_args.vector_file,
                        a_num_ids=l_args.num_ids)
# ------------------------------------------------------------------------------
#  
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    main(sys.argv[1:])
