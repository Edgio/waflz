#!/bin/bash
# ------------------------------------------------------------------------------
# script to create tarballs from a deb package
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# \brief   create tarball from debian package
# \return  NA
# \param   NA
# ------------------------------------------------------------------------------
deb2tar () {
    # ------------------------------------------------------
    # arguments
    # ------------------------------------------------------
    local l_deb=$1
    # ------------------------------------------------------
    # check deb specified and file exists
    # ------------------------------------------------------
    if test "x$l_deb" = "x"; then
        echo ": error: no deb specified" 1>&2
        echo ": usage: $0 [--deb /path/to/deb] ..." 1>&2
        exit 1
    fi
    if [[ ! -f $l_deb ]]; then
        echo ": error: file: $l_deb does not exist" 1>&2
        exit 1
    fi
    # ------------------------------------------------------
    # extract deb to temp dir
    # ------------------------------------------------------
    echo ": extracting deb: $l_deb"
    local l_deb_tmp_dir=$(mktemp -d /tmp/deb2tar_XXXXXXXX)
    echo ": extract to:             $l_deb_tmp_dir"
    dpkg -x $l_deb $l_deb_tmp_dir
    # ------------------------------------------------------
    # create bin dir
    # ------------------------------------------------------
    local l_deb_tmp_bin_dir=$(mktemp -d /tmp/deb2tar_XXXXXXXX)
    echo ": create bundle dir:      $l_deb_tmp_bin_dir"
    if [ "$(uname)" == "Darwin" ]; then
        local l_os_prefix_dir="macOS"-$(uname -m)
    else
        local l_os_prefix_dir=$(lsb_release -i | cut -f 2 | tr '[:upper:]' '[:lower:]')$(lsb_release -r | cut -f 2)-$(uname -m)
    fi
    local l_os_dir=$l_deb_tmp_bin_dir/$l_os_prefix_dir
    echo ": make os dir:            $l_os_dir"
    mkdir -p $l_os_dir
    # ------------------------------------------------------
    # copy in bundled exe/lib
    # ------------------------------------------------------
    cp -r ${l_deb_tmp_dir}/usr/bin ${l_os_dir}/bin
    cp -r ${l_deb_tmp_dir}/usr/lib ${l_os_dir}/lib
    cp -r ${l_deb_tmp_dir}/usr/include ${l_os_dir}/include
    # ------------------------------------------------------
    # fix perms
    # ------------------------------------------------------
    chmod -R a+r ${l_os_dir}
    chmod a+x ${l_os_dir}/bin/*
    chmod a+x ${l_os_dir}/lib/*
    # ------------------------------------------------------
    # create tarball
    # ------------------------------------------------------
    echo ": creating tarball..."
    local l_tar_name=${l_deb/.deb/.tar.gz}
    tar -czf $l_tar_name -C $l_deb_tmp_bin_dir $l_os_prefix_dir &>/dev/null
    echo ": created:                $l_tar_name"
    # ------------------------------------------------------
    # cleanup
    # ------------------------------------------------------
    echo ": cleaning up"
    rm -rf $l_deb_tmp_dir
    rm -rf $l_deb_tmp_bin_dir
}
# ------------------------------------------------------------------------------
# \brief   Usage
# \return  NA
# \param   NA
# ------------------------------------------------------------------------------
usage () {
cat <<EOM
deb2tar.sh [OPTIONS]
create tarball from deb

OPTIONS:
    -h  (help)     print usage and exit
    -v  (verbose)  enable verbose output (used for debugging)
    -d  (deb)      debian package [REQUIRED]
EOM
	exit 1
}

# ------------------------------------------------------------------------------
# \brief   parse arguments and run function
# \return
# \param   All params from the command line
# ------------------------------------------------------------------------------
deb=''
# ----------------------------------------------------------
# parse args
# ----------------------------------------------------------
while getopts "hvd:" opts; do
	case "${opts}" in
		h)
            usage
            exit 0
			;;
		v)
            set -o xtrace
            shift
			;;
		d)
			deb=${OPTARG}
			;;
		*)
			usage
            exit 0
		;;
	esac
done
# ----------------------------------------------------------
# run
# ----------------------------------------------------------
deb2tar $deb
