#!/usr/bin/perl -w
#
# ~/check_logfiles/test/009maxage.t
#

use strict;
use Test::More tests => 4;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $cl = Nagios::CheckLogfiles::Test->new({
        protocolsdir => TESTDIR."/var/tmp",
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user",
              options => "maxage=1m"
            }
        ]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
sleep 2;
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$cl->reset();
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2...");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

sleep 65; # no writes, file completely inactive
$cl->reset();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));

$cl->reset();
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2...");
$ssh->loggercrap(undef, undef, 10);
sleep 65; # writes, but then no activity for 65s
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 3, 0, 2));

