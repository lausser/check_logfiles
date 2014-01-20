#!/usr/bin/perl -w
#
# ~/check_logfiles/test/026case.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 3;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

if ($^O ne "aix") {
  diag ("this test only runs on aix if at all");
  ok(1); ok(1); ok(1);
  exit 0;
}

my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "mem",
	      type => "errpt",
	      criticalpatterns => ["Memory failure"],
	      options => "noprotocol"
	    }
	]    });
my $mem = $cl->get_search_by_tag("mem");
$mem->delete_logfile();
$mem->delete_seekfile();
$mem->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$mem->trace(sprintf "+----------------------- test %d ------------------", 1);
$mem->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));

# 2 now find the two criticals
$mem->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));
sleep 62;
# 3 now find the two criticals and the two warnings
$mem->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));

sleep 300;
# 3 now find the two criticals and the two warnings
# $mem->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));

