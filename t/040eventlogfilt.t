#!/usr/bin/perl -w
#
# ~/check_logfiles/test/040eventlog.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";
use Data::Dumper;

sub sleep_until_next_minute {
  my($sec, $min, $hour, $mday, $mon, $year) = (localtime)[0, 1, 2, 3, 4, 5];
  while ($sec < 59) {
    sleep 1;
    ($sec, $min, $hour, $mday, $mon, $year) = (localtime)[0, 1, 2, 3, 4, 5];
  }
  sleep 2;
  # now it is ~ hh:00, hh:01
}

if (($^O ne "cygwin") and ($^O !~ /MSWin/)) {
  diag("this is not a windows machine");
  plan skip_all => 'Test only relevant on Windows';
} else {
  plan tests => 6;
}

my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      type => "eventlog",
              criticalpatterns => '.*',
              eventlog => {
              	eventlog => "application",
                include => {
                  EventType => 'Error',
                  Source => 'check_logfiles',
                },
                exclude => {
                  EventID => '13,23',
                },
              }
	    }
	]    });
my $ssh = $cl->get_search_by_tag("ssh");
if ($^O !~ /MSWin|cygwin/) {
  diag("windows only");
  foreach (1..7) {ok(1)};
  exit 0;
}
$ssh->delete_seekfile();
$ssh->trace("deleted seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->trace(sprintf "+----------------------- test %d ------------------", 1);
sleep_until_next_minute();
$ssh->trace("initial run");
$cl->run(); # cleanup
diag("1st run");
$cl->reset();
diag("cleanup");
$ssh->trace(sprintf "+----------------------- test %d ------------------", 7);
$ssh->logger(undef, undef, 1, "Firewall problem1", undef, { 
  EventType => 'Error',
  EventID => '0010',
});
$ssh->logger(undef, undef, 1, "Firewall problem2", undef, {
  EventType => 'Error',
  EventID => '0011',
});
$ssh->logger(undef, undef, 1, "DVD problem1", undef, {
  EventType => 'Error',
  EventID => '0012',
  Source => 'DVD',   # block
});
$ssh->logger(undef, undef, 1, "Firewall problem3", undef, {
  EventType => 'Error',
  EventID => '23',   # block
});
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); #1

# 2 now find the two criticals 1xFWproblem1 1xFWproblem2
$ssh->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
sleep_until_next_minute();
# these events were created in the current minute and are ignored by the run()
$ssh->logger(undef, undef, 1, "Fireball 2hihi");
$ssh->logger(undef, undef, 1, "Fireball 3hihi");
$ssh->logger(undef, undef, 1, "Firewall problem1");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage}.'|'.$cl->{perfdata});
ok($cl->expect_result(0, 0, 2, 0, 2)); #2


sleep 2;
$cl->reset();
diag("now commandline");
$ssh->trace(sprintf "+----------------------- test %d ------------------", 7);
$ssh->logger(undef, undef, 1, "Firewall problem1", undef, {
  EventType => 'Error',
  EventID => '0010',
});
$ssh->logger(undef, undef, 1, "Firewall problem2", undef, {
  EventType => 'Error',
  EventID => '0011',
});
$ssh->logger(undef, undef, 1, "DVD problem1", undef, {
  EventType => 'Error',
  EventID => '0012',
  Source => 'DVD',   # block
});
$ssh->logger(undef, undef, 1, "Firewall problem3", undef, {
  EventType => 'Error',
  EventID => '23',   # block
});
# run commandline
my $cmd = sprintf "perl ../plugins-scripts/check_logfiles --tag %s --seekfilesdir %s --criticalpattern \".*\" --type \"eventlog:eventlog=application,include,EventType=Error,Source=check_logfiles,exclude,eventid=13,eventid=23\"",
  "ssh", TESTDIR."/var/tmp";
diag($cmd);
my $result = `$cmd`;
diag($result);
ok($result =~ /OK - no errors or warnings/);
ok(($? >> 8) == 0);

# 2 now find the two criticals 1xFWproblem1 1xFWproblem2
$ssh->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
sleep_until_next_minute();
$ssh->logger(undef, undef, 1, "Fireball 2hihi");
$ssh->logger(undef, undef, 1, "Fireball 3hihi");
$ssh->logger(undef, undef, 1, "Firewall problem1");
# run commandline
$result = `$cmd`;
diag($result);
ok($result =~ /CRITICAL - \(2 errors in/);
ok(($? >> 8) == 2);

