#!/usr/bin/perl -w
#
# ~/check_logfiles/test/004rotation.t
#
# Bugfix for 
# issue #6
#

use strict;
use Test::More tests => 4;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "betagan",
	      logfile => TESTDIR."/var/adm/my.log",
	      criticalpatterns => "ERROR",
	      rotation => "my.log.gz",
option => "randominode",
	    }
	]    });
my $betagan = $cl->get_search_by_tag("betagan");
$betagan->trace("cleaning up, removing my.log and my.log.gz, creating empty my.log and initialize run check_logfiles");
diag("cleaning up, removing my.log and my.log.gz, creating empty my.log and initialize run check_logfiles");
$betagan->delete_logfile();
$betagan->delete_seekfile();
$betagan->logger(undef, undef, 1, "OK some dummy text");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$betagan->trace("append an ERROR line");
diag("append an ERROR line");
$betagan->logger(undef, undef, 1, "ERROR dummy");
sleep 1;
$betagan->trace("running check_logfiles for the first time (should and does return CRITICAL)");
diag("running check_logfiles for the first time (should and does return CRITICAL)");
$cl->reset();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));

$betagan->trace("performing log rotation and put one OK line in the new logfile");
diag("performing log rotation and put one OK line in the new logfile");
#$betagan->rotate();
#system("gzip -c $betagan->{logfile} > $betagan->{logfile}.gz");
system("gzip $betagan->{logfile}");
system("rm $betagan->{logfile}; echo OK > $betagan->{logfile}; ls -i $betagan->{logfile}");
sleep 1;
$betagan->trace("running check_logfiles for the second time (should and does return OK)");
diag("running check_logfiles for the second time (should and does return OK)");
$cl->reset();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$betagan->trace("append a second OK line to the logfile");
diag("append a second OK line to the logfile");
$betagan->logger(undef, undef, 1, "OK some dummy text");
sleep 1;
$betagan->trace("running check_logfiles for the third time (should return OK BUT DOES RETURN CRITICAL INSTEAD!!");
$cl->reset();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

