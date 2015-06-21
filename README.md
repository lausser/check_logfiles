Description
===========

check_logfiles is a Plugin for Icinga which scans log files for specific patterns.

Motivation
==========

The conventional plugins which scan log files are not adequate in a mission critical environment. Especially the missing ability to handle logfile rotation and inclusion of the rotated archives in the scan allow gaps in the monitoring. Check_logfiles was written because these deficiencies would have prevented Nagios from replacing a propritetary monitoring system.

Features
========

* Detection of rotations - usually nightly logfiles are rotated and compressed. Each operating system or company has it's own naming scheme. If this rotation is done between two runs of check_logfiles also the rotated archive has to be scanned to avoid gaps. The most common rotation schemes are predefined but you can describe any strategy (shortly: where and under which name is a logfile archived).
* More than one pattern can be defined which again can be classified as warning patterns and critical patterns.
* Triggered actions - Usually nagios plugins return just an exit code and a line of text, describing the result of the check. Sometimes, however, you want to run some code during the scan every time you got a hit. Check_logfiles lets you call scripts either after every hit or at the beginning or the end of it's runtime.
* Exceptions - If a pattern matches, the matched line could be a very special case which should not be counted as an error. You can define exception patterns which are more specific versions of your critical/warning patterns. Such a match would then cancel an alert.
* Thresholds - You can define the number of matching lines which are necessary to activate an alert.
* Protocol - The matching lines can be written to a protocol file the name of which will be included in the plugin's output.
* Macros - Pattern definitions and logfile names may contain macros, which are resolved at runtime.
* Performance data - The number of lines scanned and the number of warnings/criticals is output.
* Windows - The plugin works with Unix as well as with Windows (e.g. with ActiveState Perl).

Examples
========

    nagios$ check_logfiles --logfile /var/adm/messages \
         --criticalpattern 'Failed password' --tag ssh
    CRITICAL - (4 errors) - May  9 11:33:12 localhost sshd[29742] Failed password for invalid user8 ... |ssh_lines27 ssh_warnings=0 ssh_criticals=4 ssh_unknowns=0

Homepage
========
The full documentation can be found here: [check_logfiles @ ConSol Labs](http://labs.consol.de/nagios/check_logfiles)

