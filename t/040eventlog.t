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

if (($^O ne "cygwin") and ($^O !~ /MSWin/)) {
  diag("this is not a windows machine");
  plan skip_all => 'Test only relevant on Windows';
} else {
  plan tests => 7;
}

my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      type => "eventlog",
              criticalpatterns => ["Adobe", "Firewall" ],
              eventlog => {
              	eventlog => "application",
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
sleep 2;
$ssh->trace("initial run");
$cl->run(); # cleanup
diag("1st run");
$cl->reset();
diag("cleanup");
$ssh->logger(undef, undef, 1, "Fireball 1hihi");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); #1

# 2 now find the two criticals
$ssh->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
sleep 30;
$ssh->logger(undef, undef, 1, "Fireball 2hihi");
$ssh->logger(undef, undef, 1, "Fireball 3hihi");
$ssh->logger(undef, undef, 1, "Firewall problem1");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage}.'|'.$cl->{perfdata});
ok($cl->expect_result(0, 0, 0, 0, 0)); #2

# 3 now find the critical (Firewall problem1)
$ssh->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
sleep 120;
$cl->run();
$ssh->logger(undef, undef, 2, "Fireball huhuhuhhihi");
diag($cl->has_result());
diag($cl->{exitmessage}.'|'.$cl->{perfdata});
ok($cl->expect_result(0, 0, 1, 0, 2)); #3

# 2 now find the two criticals
$ssh->trace(sprintf "+----------------------- test %d ------------------", 4);
$cl->reset();
$ssh->logger(undef, undef, 1, "Firewall problem2");
sleep 20;
$ssh->logger(undef, undef, 1, "Firewall problem3");
$ssh->logger(undef, undef, 1, "Fireball hihi");
sleep 10;
$ssh->logger(undef, undef, 1, "Firewall problem4");
$ssh->logger(undef, undef, 1, "Fireball hihi");
sleep 10;
$ssh->logger(undef, undef, 1, "Firewall problem5");
$ssh->logger(undef, undef, 1, "Fireball hihi");
sleep 10;
$ssh->logger(undef, undef, 1, "Firewall problem6");
$ssh->logger(undef, undef, 1, "Fireball hihi");
$ssh->logger(undef, undef, 1, "Firewall problem7");
sleep 10;
$cl->run();
diag("now there should be up to 6 criticals");
diag($cl->has_result());
diag($cl->{exitmessage}.'|'.$cl->{perfdata});
#ok($cl->expect_result(0, 0, 6, 0, 2));
$cl->{exitmessage} =~ /.*problem(\d+).*/;
my $problem = $1;
$cl->{perfdata} =~ /.*ssh_criticals=(\d+).*/;
my $found = $1;
diag(sprintf "reported %d errors so far. %d to come", $found, 6 - $found);
ok($cl->{exitmessage} =~ /CRITICAL/); #4
ok($problem == $found + 1);

# 3 now find the two criticals and the two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 5);
$cl->reset();
sleep 65;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage}.'|'.$cl->{perfdata});
if ($found == 6) {
  ok($cl->expect_result(0, 0, 0, 0, 0));
} else {
  ok($cl->expect_result(0, 0, 6 - $found, 0, 2));
}

$ssh->trace(sprintf "+----------------------- test %d ------------------", 6);
$cl->reset();
$ssh->logger(undef, undef, 1, "Firewall problem2");
$ssh->set_option('eventlogformat', '%w id:%i so:%s ca:%c msg:%m');
sleep 20;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage}.'|'.$cl->{perfdata});
ok($cl->{exitmessage} =~ /id:.*so:.*ca:.*/); #6

