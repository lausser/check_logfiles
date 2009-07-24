## Process this file with automake to produce Makefile.in

SUFFIXES = .pl .pm .sh

VPATH=$(top_srcdir) $(top_srcdir)/plugins-scripts $(top_srcdir)/plugins-scripts/t

libexec_SCRIPTS=check_logfiles
EXTRA_DIST=check_logfiles.pl Nagios/CheckLogfiles.pm Nagios/CheckLogfiles/Search/Errpt.pm Nagios/CheckLogfiles/Search/Psloglist.pm Nagios/CheckLogfiles/Search/Ipmitool.pm Nagios/CheckLogfiles/Search/Oraclealertlog.pm Nagios/CheckLogfiles/Search/Eventlog.pm Nagios/CheckLogfiles/Search/Dummy.pm Nagios/CheckLogfiles/Test.pm Nagios/Tivoli/Config/Logfile.pm

CLEANFILES=$(libexec_SCRIPTS)

AM_INSTALL_PROGRAM_FLAGS=@INSTALL_OPTS@

.pm :
	$(AWK) -f ./subst $< > $@
	chmod +x $@

.pl :
	$(AWK) -f ./subst $< > $@
	chmod +x $@

.sh :
	$(AWK) -f ./subst $< > $@
	chmod +x $@

$(libexec_SCRIPTS) : $(EXTRA_DIST)
	$(ECHO) "#! #PERL# -w" | $(AWK) -f ./subst > $@
	$(ECHO) "# nagios: -epn" >> $@
	$(SED) -e 's/^1;//g' < Nagios/Tivoli/Config/Logfile.pm | $(AWK) -f ./subst >> $@
	$(SED) -e 's/^1;//g' < Nagios/CheckLogfiles.pm | $(AWK) -f ./subst >> $@
	$(SED) -e 's/^1;//g' < Nagios/CheckLogfiles/Search/Dummy.pm | $(AWK) -f ./subst >> $@
	$(SED) -e 's/^1;//g' < Nagios/CheckLogfiles/Search/Errpt.pm | $(AWK) -f ./subst >> $@
	$(SED) -e 's/^1;//g' < Nagios/CheckLogfiles/Search/Ipmitool.pm | $(AWK) -f ./subst >> $@
	$(SED) -e 's/^1;//g' < Nagios/CheckLogfiles/Search/Oraclealertlog.pm | $(AWK) -f ./subst >> $@
	$(CAT) check_logfiles.pl | $(AWK) -f ./subst >> $@
	chmod +x $@