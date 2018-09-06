#!/usr/bin/python
import os
import sys
import argparse
import subprocess
import json
# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def create_json_rules(a_policy_dir):
	l_policy_files = []
	#print a_policy_dir
	for l_f in os.listdir(a_policy_dir):
		if l_f.endswith('.conf'):
			l_policy_files.append(l_f)
	# -----------------------------------
	# create cmd and gen json output
	for l_p_f in l_policy_files:
		l_cmd = ['waflz_dump',
				 '--input=' + a_policy_dir + '/' + l_p_f,
				 '-M',
				 '-j',
				 '--output=' + a_policy_dir + l_p_f + '.json'
				]
		l_waflz_dump_cmd_result = ''
		print l_cmd
		try:
			l_waflz_dump_cmd_result = subprocess.check_output(l_cmd,
															  stderr=subprocess.STDOUT)
		except Exception as e:
			raise Exception('Error generating json output. Reason: %s'%(e.output.replace('\n', ' ').replace('\r', ' ')))


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main(argv):
	arg_parser = argparse.ArgumentParser(
				 description='Create json rule files from modsec conf files',
				 usage='%(prog)s',
				 epilog= '')
	arg_parser.add_argument('-p',
							'--policy_dir',
							dest='policy_dir',
							help='Ruleset policy files dir',
							required=True)
	args = arg_parser.parse_args()

	create_json_rules(a_policy_dir=args.policy_dir)
# ----------------------------------------------------------------------
# 
# ----------------------------------------------------------------------
if __name__ == "__main__":
	main(sys.argv[1:])




