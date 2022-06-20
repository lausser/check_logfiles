libexec_SCRIPTS=check_logfiles
EXTRA_MODULES=\
  Nagios/Tivoli/Config/Logfile.pm \
  Nagios/CheckLogfiles.pm \
  Nagios/CheckLogfiles/Search/Errpt.pm \
  Nagios/CheckLogfiles/Search/Ipmitool.pm \
  Nagios/CheckLogfiles/Search/Oraclealertlog.pm \
  Nagios/CheckLogfiles/Search/Esxdiag.pm \
  Nagios/CheckLogfiles/Search/Executable.pm \
  Nagios/CheckLogfiles/Search/Dummy.pm \
  Nagios/CheckLogfiles/Search/Journald.pm \
  Nagios/CheckLogfiles/Search/Dmesg.pm

TEST_MODULES=\
  Nagios/CheckLogfiles/Test.pm

WIN_MODULES=\
  Nagios/CheckLogfiles/Search/Dumpel.pm \
  Nagios/CheckLogfiles/Search/Eventlog.pm \
  Nagios/CheckLogfiles/Search/Psloglist.pm \
  Nagios/CheckLogfiles/Search/Wevtutil.pm


SED=/bin/sed
GREP=/bin/grep
CAT=/bin/cat
ECHO=/bin/echo

SUFFIXES = .pl .pm .sh

VPATH=$(top_srcdir) $(top_srcdir)/plugins-scripts $(top_srcdir)/plugins-scripts/t

EXTRA_DIST=$(libexec_SCRIPTS).pl $(EXTRA_MODULES) $(TEST_MODULES) $(WIN_MODULES)

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
	$(ECHO) "#! #PERL# " | $(AWK) -f ./subst > $@
	$(ECHO) "# nagios: -epn" >> $@
	$(ECHO) >> $@
	for m in ${EXTRA_MODULES}; do \
		$(SED) -e 's/^1;//g' < $$m | $(SED) -e '/^__END__/,$$d' | $(AWK) -f ./subst >> $@; \
	done
	$(CAT) check_logfiles.pl | $(AWK) -f ./subst >> $@
	chmod +x $@
