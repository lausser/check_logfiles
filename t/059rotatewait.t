#!/usr/bin/perl -w
#
# ~/check_logfiles/test/o59rotatewait.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 2;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $cl = Nagios::CheckLogfiles::Test->new({
        options => "rotatewait",
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => ["Failed password", "!OKOK" ],
	      warningpatterns => "Unknown user",
	      warningexceptions => "Unknown user sepp",
	      options => "nocase"
	    }
	]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->trace(sprintf "+----------------------- test %d ------------------", 1);
$ssh->logger(undef, undef, 2, "FAIlEd pAsswOrd fOr InvAlId UsEr1...");
$ssh->trace(sprintf "in 1: ctime %s",
    scalar localtime ((stat TESTDIR."/var/adm/messages")[10]));
$ssh->trace(sprintf "in 1: mtime %s",
    scalar localtime ((stat TESTDIR."/var/adm/messages")[9]));
sleep 2;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "OKOK");
sleep 1;
#
# wait until **:[00,15,30,45]:00
my ($sec, $min, $hour, $mday, $mon, $year) = (localtime)[0, 1, 2, 3, 4, 5];
while ($min != 0 && $min != 15 && $min != 30 && $min != 45) {
  sleep 1;
  ($sec, $min, $hour, $mday, $mon, $year) = (localtime)[0, 1, 2, 3, 4, 5];
  diag("wait.....".(scalar localtime));
}
my $now = time;
diag(scalar localtime);
#
$ssh->trace("initial run");
$cl->run();
#
# must be **:**:15
diag(scalar localtime);
ok((time - $now) > 14);
#
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));

