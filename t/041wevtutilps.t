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
use Nagios::CheckLogfiles::Search::Eventlog;
use constant TESTDIR => ".";

if (($^O ne "cygwin") and ($^O !~ /MSWin/)) {
  diag("this is not a windows machine");
  plan skip_all => 'Test only relevant on Windows';
} else {
  plan tests => 7;
}

######################################################
# 
# powershell -Command "echo hihi"
# leaves 
# "PowerShell-Konsole wird gestartet."
# and
# "Windows PowerShell hat einen IPC-Listeningthread für den Prozess 7204 in AppDomain DefaultAppDomain gestartet" ( this seems to be new since some win 10 creators? update
# and
# "PowerShell-Konsole ist für Benutzereingaben bereit."
# in
# Microsoft-Windows-PowerShell/Operational

my $cl = Nagios::CheckLogfiles::Test->new({
        protocolsdir => TESTDIR."/var/tmp",
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "msps",
              type => "wevtutil",
              criticalpatterns => ["Microsoft", "PowerShell.*(ready|bereit)" ],
              warningpatterns => ["PowerShell.*(started|gestartet)" ],
              warningexceptions => ["PowerShell.*DefaultAppDomain.*(started|gestartet)" ],
              wevtutil => {
                eventlog => "Microsoft-Windows-PowerShell/Operational",
              }
            }
        ]    });
$cl->make_windows_plugin();
my $msps = $cl->get_search_by_tag("msps");
$msps->delete_seekfile();
$msps->trace("deleted seekfile");
$msps->trace("initial run");
$cl->run(); # cleanup
$cl->reset();
diag("cleanup");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));
# 2 now find the two criticals
$msps->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
sleep 30;
system('powershell -Command "echo hihi"');
sleep 5;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 1, 0, 2));
diag("---------------------------------------");
$cl->reset();
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));

diag("---------------------------------------");
$cl->reset();
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 11, 11, 0, 2));

diag("---------------------------------------");
$cl->reset();
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
sleep int(1 + 10 * rand);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));

diag("---------------------------------------");
$cl->reset();
system('powershell -Command "echo hihi"');
sleep int(1 + 10 * rand);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 1, 0, 2));

diag("---------------------------------------");
$cl->reset();
system('powershell -Command "echo hihi"');
sleep int(1 + 10 * rand);
system('powershell -Command "echo hihi"');
sleep int(1 + 10 * rand);
system('powershell -Command "echo hihi"');
sleep int(1 + 10 * rand);
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
sleep int(1 + 10 * rand);
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
system('powershell -Command "echo hihi"');
sleep int(1 + 10 * rand);
system('powershell -Command "echo hihi"');
sleep int(1 + 10 * rand);
system('powershell -Command "echo hihi"');
sleep int(1 + 10 * rand);
system('powershell -Command "echo hihi"');
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 11, 11, 0, 2));

$cl->remove_windows_plugin();
