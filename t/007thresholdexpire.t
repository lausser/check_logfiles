#!/usr/bin/perl -w
#
# ~/check_logfiles/test/007thresholdexpire.t
#
#  Test that all the Perl modules we require are available.
#  Simulate a portscan. Connections to port 80 are ok.
#

use strict;
use Test::More tests => 21;
use Cwd;
use Data::Dumper;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


#
# Count the hits, but reset the counter to 0 if an okpattern was found
# Hit counts have a lifetime of 5s
#
# Case 1: nosavethresholdcount
#         reset
#         9 criticals, 2 warnings
#         run: OK
#         sleep 2
#         19 criticals, 12 warnings
#         run: CRITICAL
#         sleep 2
#         19 criticals, ok, 9 criticals
#         run: OK
#         sleep 2
#         19 criticals, ok, 19 criticals
#         run: CRITICAL (19)
# 
my $cl = Nagios::CheckLogfiles::Test->new({
  protocolsdir => TESTDIR."/var/tmp",
  seekfilesdir => TESTDIR."/var/tmp",
  searches => [{
    tag => "nmap",
    logfile => TESTDIR."/var/adm/messages",
    criticalpatterns => [ 
        'connection refused', 
        'connection on port\s+\d+',
        'session aborted'
    ], 
    criticalexceptions => 'connection on port\s+80[^\d]*',
    criticalthreshold => 10,
    warningpatterns => [ 
        '.*total size is 0 .*', 
        'connection on port\s+80[^\d]*', 
    ],
    warningthreshold => 3,
    okpatterns => [
        'sshd restarted',
    ],
    options => 'criticalthreshold=10,warningthreshold=3,thresholdexpiry=5',
  }]
});
my $nmap = $cl->get_search_by_tag("nmap");
$nmap->delete_seekfile();
$cl->reset();
$cl->run();
diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
diag(Data::Dumper::Dumper($nmap->{newstate}->{thresholdtimes}));

foreach my $cnt (1..3) {
  $cl->reset();
  $nmap->logger(undef, undef, 2, "connection refused");  # skip 9 -> 0
  $cl->run();
  ok($cl->expect_result(0, 0, 0, 0, 0));
  sleep 1;
}
# 2-2-2-
diag("now another critical");
$cl->reset();
$nmap->logger(undef, undef, 1, "connection refused");  # skip 9 -> 0
$cl->run();
# 2-2-2-1
diag("must have 7c");
diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
ok($cl->expect_result(0, 0, 0, 0, 0));
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 7) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 0));
sleep 2;
# 2-2-2-1--
diag("now expire critical");
$cl->reset();
$nmap->logger(undef, undef, 1, "connection refused");  # skip 9 -> 0
# 2-2-2-1--1
$cl->run();
diag("must have 1c");
diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
ok($cl->expect_result(0, 0, 0, 0, 0));
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 8) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 0));
diag("");
sleep 2;
# 2-2-2-1--1--
$cl->reset();
$cl->run();
diag("must have 4c");
diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
ok($cl->expect_result(0, 0, 0, 0, 0));
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 4) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 0));
# x-x-2-1--1--
sleep 1;
$cl->reset();
$cl->run();
diag("must have 2c");
diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
ok($cl->expect_result(0, 0, 0, 0, 0));
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 2) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 0));

sleep 3;
$cl->reset();
$cl->run();
diag("must have 0c");
diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
ok($cl->expect_result(0, 0, 0, 0, 0));
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 0) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 0));


foreach my $cnt (1..3) {
  $cl->reset();
  $nmap->logger(undef, undef, 5, "connection refused");  # skip 9 -> 0
  $cl->run();
  #ok($cl->expect_result(0, 0, 0, 0, 0));
  diag("loop ".$cnt." now ".$cl->has_result());
  sleep 1;
  # die ersten beiden 5 werden zu einem critical
  # 5- bleibt
}
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 5) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 0));
# 5-
$cl->reset();
$cl->run();
diag("must have 5c");
ok($cl->expect_result(0, 0, 0, 0, 0));
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 5) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 0));

sleep 4;
$nmap->logger(undef, undef, 6, "connection refused");  # skip 9 -> 0
$cl->reset();
$cl->run();
diag("must have 1c");
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 1) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 0));
ok($cl->expect_result(0, 0, 1, 0, 2));

$nmap->logger(undef, undef, 9, "connection refused");  # skip 9 -> 0
$cl->reset();
$cl->run();
sleep 6;
$cl->reset();
$cl->run();
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 0) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 0));
ok($cl->expect_result(0, 0, 0, 0, 0));
