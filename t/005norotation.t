#!/usr/bin/perl -w
#
# ~/check_logfiles/test/005norotation.t
#
#  Test logfiles which will be deleted and recreated instead of rotated.
#
#  fill a logfile with crap. run. must be ok
#  add criticals. run. must be critical
#  delete logfile. add crap. run. must be ok. tracefile must mention recreation
#  add errors. run .must be critical
#  delete logfile. run. must be critical
#  add 100 lines of crap. run. must be ok
#  delete logfile. add 10 lines of criticals. add 10 lines of crap. run. must be critical
#  delete logfile. run. must be critical
#  add 100 lines of crap. run. must be ok
#  delete logfile. add 10 lines of criticals. add 100 lines of crap. run. must be critical
#  delete logfile. touch logfile. run. must be ok.
#  the same with no_logfile_no_cry => 1

use strict;
use Test::More tests => 22;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	    }
	]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

$ssh->trace("==== 1 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 500);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->trace("==== 2 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 20);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 20);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

$ssh->trace("==== 3 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 20);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->trace("==== 4 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 200);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 200);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

$ssh->trace("==== 5 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 1, 3));

$ssh->trace("==== 6 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 100);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->trace("==== 7 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->logger(undef, undef, 10, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 10);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 10, 0, 2));

$ssh->trace("==== 8 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 1, 3));

$ssh->trace("==== 9 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 10);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->trace("==== 10 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->logger(undef, undef, 10, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 100);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 10, 0, 2));

$ssh->trace("==== 11 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->touch_logfile();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

#
#
#
# now scream on deleted logfiles
#
$cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
              options => "nologfilenocry"
	    }
	]    });
$ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

$ssh->trace("==== 12 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 20);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->trace("==== 13 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 200);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 200);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

$ssh->trace("==== 14 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 200);
$ssh->loggercrap(undef, undef, 200);
$ssh->loggercrap(undef, undef, 200);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->trace("==== 15 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 200);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 200);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

$ssh->trace("==== 16 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->trace("==== 17 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 100);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->trace("==== 18 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->logger(undef, undef, 10, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 10);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 10, 0, 2));

$ssh->trace("==== 19 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->trace("==== 20 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 100);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->trace("==== 21 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->logger(undef, undef, 10, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 100);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 10, 0, 2));

$ssh->trace("==== 22 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->touch_logfile();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));



