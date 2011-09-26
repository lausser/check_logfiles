#!/usr/bin/perl -w
#
# ~/check_logfiles/test/075winwarncrit.t
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
              #criticalpatterns => ["Adobe", "Firewall" ],
              options => "winwarncrit",
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
sleep_until_next_minute();
$ssh->trace("initial run");
$cl->run(); # cleanup
diag("1st run");
$cl->reset();
diag("cleanup");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 2 now find the two criticals
$ssh->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
sleep 30;
$ssh->logger(undef, undef, 1, "Firewall problem1", undef, {
  EventType => 'Error',
  EventID => '12',
  Source => 'checkpoint',
});
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));

# 3 now find the 10 criticals and 3 warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
sleep 30;
$ssh->logger(undef, undef, 10, "Firewall problem1", undef, {
  EventType => 'Error',
  EventID => '12',
  Source => 'checkpoint',
});
$ssh->logger(undef, undef, 3, "Firewall problem1", undef, {
  EventType => 'Warning',
  EventID => '11',
  Source => 'checkpoint',
});
$ssh->logger(undef, undef, 3, "Firewall problem1", undef, {
  EventType => 'Information',
  EventID => '10',
  Source => 'checkpoint',
});
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 3, 10, 0, 2));
diag($cl->{perfdata});
ok($cl->{perfdata} =~ /ssh_lines=16/);

# 4 now find the them with the command line
$ssh->trace(sprintf "+----------------------- test %d ------------------", 4);
sleep 30;
$ssh->logger(undef, undef, 10, "Firewall problem1", undef, {
  EventType => 'Error',
  EventID => '12',
  Source => 'checkpoint',
});
$ssh->logger(undef, undef, 3, "Firewall problem1", undef, {
  EventType => 'Warning',
  EventID => '11',
  Source => 'checkpoint',
});
$ssh->logger(undef, undef, 3, "Firewall problem1", undef, {
  EventType => 'Information',
  EventID => '10',
  Source => 'checkpoint',
});
sleep 2;
my $perlpath = "";
chomp $perlpath;
if ($^O =~ /MSWin/) {
 if (-x '../plugins-scripts/check_logfiles.exe') {
  $perlpath = '';
 } elsif (-f 'C:\strawberry\perl\bin\perl.exe') {
  $perlpath = 'C:\strawberry\perl\bin\perl ';
 } else {
  $perlpath = 'C:\Perl\bin\perl ';
 }
  $ssh->{logfile} =~ s/\//\\/g;
}
my $command = sprintf $perlpath.'../plugins-scripts/check_logfiles --seekfilesdir "%s" --tag %s --type eventlog:eventlog=application --winwarncrit',
    TESTDIR."/var/tmp",
    $ssh->{tag}, $ssh->{patterns}->{CRITICAL}->[0],
    $ssh->{patterns}->{WARNING}->[0],
    $ssh->{rotation}, $ssh->{logfile};

diag($command);
my $output = `$command`;
ok($output =~ /10 errors, 3 warnings.*ssh_lines=16/);

# 5 now find the them with the command line
$ssh->trace(sprintf "+----------------------- test %d ------------------", 5);
sleep 30;
$ssh->logger(undef, undef, 10, "Firewall problem1", undef, {
  EventType => 'Error',
  EventID => '12',
  Source => 'checkpoint',
});
$ssh->logger(undef, undef, 1, "Firewall problem10", undef, {
  EventType => 'Warning',
  EventID => '11',
  Source => 'checkpoint',
});
$ssh->logger(undef, undef, 1, "Firewall problem11", undef, {
  EventType => 'Warning',
  EventID => '11',
  Source => 'checkpoint',
});
$ssh->logger(undef, undef, 1, "Firewall problem12", undef, {
  EventType => 'Warning',
  EventID => '11',
  Source => 'checkpoint',
});
$ssh->logger(undef, undef, 1, "Feuerwall problem1", undef, {
  EventType => 'Warning',
  EventID => '11',
  Source => 'checkpoint',
});
$ssh->logger(undef, undef, 1, "Feuerwall problem2", undef, {
  EventType => 'Warning',
  EventID => '11',
  Source => 'checkpoint',
});
$ssh->logger(undef, undef, 1, "Feuerwall problem3", undef, {
  EventType => 'Warning',
  EventID => '11',
  Source => 'checkpoint',
});
$ssh->logger(undef, undef, 3, "Feuerwall problem0", undef, {
  EventType => 'Information',
  EventID => '10',
  Source => 'checkpoint',
});
sleep 2;
$command = sprintf $perlpath.'../plugins-scripts/check_logfiles --seekfilesdir "%s" --tag %s --type eventlog:eventlog=application --winwarncrit --criticalpattern "Hilfaeaeaeae" --warningpattern "Feurio|problem0" --report long',
    TESTDIR."/var/tmp",
    $ssh->{tag}, $ssh->{patterns}->{CRITICAL}->[0],
    $ssh->{patterns}->{WARNING}->[0],
    $ssh->{rotation}, $ssh->{logfile};
# Feuerwall problem1-3 werden doppelt gezählt, 1. wegen warning, 2. wegen pattern
diag($command);
$output = `$command`;
diag($output);
ok($output =~ /10 errors, 9 warnings.*ssh_lines=19/);

