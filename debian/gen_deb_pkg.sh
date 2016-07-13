#!/usr/bin/env sh

set -e
set -u

##------------------------------------------------------------
P_NAME='nagios-plugin-check-logfiles'
P_AUTHOR='Gerhard Laußer <gerhard.lausser@consol.de>'

CL_DEB="$( dirname "$0" )/debian/changelog"
CL_US="$( dirname $0 )/ChangeLog"

readonly P_NAME P_AUTHOR CL_DEB CL_US


##------------------------------------------------------------
rebuildChangelog() {
    awk -vRS='* ' \
        -vAUTHOR="$P_AUTHOR" \
        -vNAME="$P_NAME" \
        'function convDate(ts) {
           cmd="date --rfc-2822 -d " gensub(/\./, "-", "g", ts)
           cmd | getline converted
           return converted
         }
         {
           v=$1           # version
           if ($2 == "-") {
             d=$3         # date
             $1=$2=$3=""  # clear the previous fields
           } else {
             d=$2         # date
             $1=$2=""     # clear the previous fields
           }
           d=convDate(d)
           gsub(/^[ \t]+|[ \t]+$/, "")
           t=$0
           if (length(v) && length(d) && length(t))
             print NAME " (" v ") stable; urgency=medium\n\n  * " t "\n\n -- " AUTHOR "  " d "\n"
         }'
}


##------------------------------------------------------------
buildPkg() {
    debuild -uc -us
}


##------------------------------------------------------------
main() {
    rebuildChangelog <"$CL_US" >"$CL_DEB"
    buildPkg
}


##------------------------------------------------------------
##------------------------------------------------------------
main "$@"

