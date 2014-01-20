#!/usr/bin/perl -w
#
# ~/check_logfiles/test/029prefilter.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 26;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "siapp8",
	      prefilter => '$CL_TAG$',
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      options => "perfdata"
	    },
	    {
	      tag => "ipata22",
	      prefilter => '$CL_TAG$',
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      options => "perfdata"
	    },
	    {
	      tag => "simple",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      options => "perfdata"
	    },
	]    });
my $siapp8 = $cl->get_search_by_tag("siapp8");
$siapp8->delete_logfile();
$siapp8->delete_seekfile();
$siapp8->trace("deleted logfile and seekfile");
my $ipata22 = $cl->get_search_by_tag("ipata22");
$ipata22->delete_logfile();
$ipata22->delete_seekfile();
$ipata22->trace("deleted logfile and seekfile");
my $simple = $cl->get_search_by_tag("simple");
$simple->delete_logfile();
$simple->delete_seekfile();
$simple->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$simple->trace(sprintf "+----------------------- test %d ------------------", 1);
$simple->loggercrap(undef, undef, 100);
sleep 1;
$simple->trace("initial run");
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 2 write 4 criticals concerning host lpdbs01
$simple->trace(sprintf "+----------------------- test %d ------------------", 2);
$simple->loggercrap(undef, undef, 100);
$simple->logger(undef, undef, 4, "lpdbs01: Failed password for invalid user1...");
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 4, 0, 2));

# 3 write 3 criticals concerning host siapp8 + 7 simples
$simple->trace(sprintf "+----------------------- test %d ------------------", 3);
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 1, "siapp8: Failed password for invalid user1...");
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 3, "lpdbs01: Failed password for invalid user1...");
$simple->loggercrap(undef, undef, 2);
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 5, 0, 2));

# 4 write 3 criticals concerning host siapp8 + 7 simples
$simple->trace(sprintf "+----------------------- test %d ------------------", 4);
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 1, "siapp8: Failed password for invalid user1...");
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 3, "lpdbs01: Failed password for invalid user1...");
$simple->loggercrap(undef, undef, 2);
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 30, "ipata22: Failed password for invalid user1...");
$cl->reset();
sleep 1;
$cl->run();
ok($siapp8->{perfdata});
diag($ipata22->{perfdata});
diag($simple->{perfdata});
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 65, 0, 2));
ok($cl->{perfdata} =~ /.*simple_criticals=34.*/);
ok($cl->{perfdata} =~ /.*siapp8_criticals=1.*/);
ok($cl->{perfdata} =~ /.*ipata22_criticals=30.*/);


#
#
# repeat the tests. instead of prefilter we set the syslogclient option
#
$cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "siapp9",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      options => "perfdata,syslogclient=siapp9"
	    },
	    {
	      tag => "ipata23",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      options => 'perfdata,syslogclient=$CL_TAG$'
	    },
	    {
	      tag => "simple",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      options => "perfdata"
	    },
	]    });
$siapp8 = $cl->get_search_by_tag("siapp9");
$siapp8->delete_logfile();
$siapp8->delete_seekfile();
$siapp8->trace("deleted logfile and seekfile");
$ipata22 = $cl->get_search_by_tag("ipata23");
$ipata22->delete_logfile();
$ipata22->delete_seekfile();
$ipata22->trace("deleted logfile and seekfile");
$simple = $cl->get_search_by_tag("simple");
$simple->delete_logfile();
$simple->delete_seekfile();
$simple->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$simple->trace(sprintf "+----------------------- test %d ------------------", 5);
$simple->loggercrap(undef, undef, 100);
sleep 1;
$simple->trace("initial run");
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 2 write 4 criticals concerning host lpdbs01
$simple->trace(sprintf "+----------------------- test %d ------------------", 6);
$simple->loggercrap(undef, undef, 100);
$simple->logger(undef, undef, 4, "lpdbs01: Failed password for invalid user1...");
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 4, 0, 2));

# 3 write 3 criticals concerning host siapp8 + 7 simples
$simple->trace(sprintf "+----------------------- test %d ------------------", 7);
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 1, "siapp9: Failed password for invalid user1...");
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 3, "lpdbs01: Failed password for invalid user1...");
$simple->loggercrap(undef, undef, 2);
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 5, 0, 2));

# 4 write 3 criticals concerning host siapp8 + 7 simples
$simple->trace(sprintf "+----------------------- test %d ------------------", 8);
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 1, "siapp9: Failed password for invalid user1...");
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 3, "lpdbs01: Failed password for invalid user1...");
$simple->loggercrap(undef, undef, 2);
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 30, "ipata23: Failed password for invalid user1...");
$cl->reset();
sleep 1;
$cl->run();
ok($siapp8->{perfdata});
diag($ipata22->{perfdata});
diag($simple->{perfdata});
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 65, 0, 2));
ok($cl->{perfdata} =~ /.*simple_criticals=34.*/);
ok($cl->{perfdata} =~ /.*siapp9_criticals=1.*/);
ok($cl->{perfdata} =~ /.*ipata23_criticals=30.*/);
ok(@{$ipata22->{preliminaryfilter}->{NEED}}[0] eq "ipata23");

diag("add case insensitivity");
#
#
# repeat the tests. we set the syslogclient option and mix cases
#
$cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "siapp9",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      options => "perfdata,syslogclient=siapp9,nocase"
	    },
	    {
	      tag => "ipata23",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      options => 'perfdata,syslogclient=$CL_TAG$,nocase'
	    },
	    {
	      tag => "simple",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      options => "perfdata"
	    },
	]    });
$siapp8 = $cl->get_search_by_tag("siapp9");
$siapp8->delete_logfile();
$siapp8->delete_seekfile();
$siapp8->trace("deleted logfile and seekfile");
$ipata22 = $cl->get_search_by_tag("ipata23");
$ipata22->delete_logfile();
$ipata22->delete_seekfile();
$ipata22->trace("deleted logfile and seekfile");
$simple = $cl->get_search_by_tag("simple");
$simple->delete_logfile();
$simple->delete_seekfile();
$simple->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$simple->trace(sprintf "+----------------------- test %d ------------------", 5);
$simple->loggercrap(undef, undef, 100);
sleep 1;
$simple->trace("initial run");
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); #18

# 2 write 4 criticals concerning host lpdbs01
$simple->trace(sprintf "+----------------------- test %d ------------------", 6);
$simple->loggercrap(undef, undef, 100);
$simple->logger(undef, undef, 4, "lpdbs01: Failed password for invalid user1...");
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 4, 0, 2)); #19

# 3 write 3 criticals concerning host siapp8 + 7 simples
$simple->trace(sprintf "+----------------------- test %d ------------------", 7);
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 1, "SIAPP9: Failed password for invalid user1...");
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 3, "lpdbs01: Failed password for invalid user1...");
$simple->loggercrap(undef, undef, 2);
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 5, 0, 2)); #20

# 4 write 3 criticals concerning host siapp8 + 7 simples
$simple->trace(sprintf "+----------------------- test %d ------------------", 8);
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 1, "siapp9: Failed password for invalid user1...");
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 3, "lpdbs01: Failed password for invalid user1...");
$simple->loggercrap(undef, undef, 2);
$simple->loggercrap(undef, undef, 2);
$simple->logger(undef, undef, 15, "ipata23: Failed password for invalid user1...");
$simple->logger(undef, undef, 15, "IPATA23: Failed password for invalid user1...");
$cl->reset();
sleep 1;
$cl->run();
ok($siapp8->{perfdata});
diag($ipata22->{perfdata});
diag($simple->{perfdata});
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 65, 0, 2));
ok($cl->{perfdata} =~ /.*simple_criticals=34.*/);
ok($cl->{perfdata} =~ /.*siapp9_criticals=1.*/);
ok($cl->{perfdata} =~ /.*ipata23_criticals=30.*/);
ok(@{$ipata22->{preliminaryfilter}->{NEED}}[0] eq "(?i)ipata23");


