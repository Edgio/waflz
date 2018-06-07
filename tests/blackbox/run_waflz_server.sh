#!/bin/bash
#This start up waflz_server to run tests against
# ------------------------------------------------------------------------------
#Vars
# ------------------------------------------------------------------------------
is_running=$(ps aux | grep waflz_server | grep ruleset)
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
main() {

    if [ -z is_running ];then
        echo "Server is already running, please shut down and try again"
        sys.exit(1)
    else
        #TODO start the waflz_server
        echo "This part is not finished.. still in development"
    fi
}


main