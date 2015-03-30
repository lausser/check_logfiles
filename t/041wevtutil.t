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
  plan tests => 6;
}

my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "app",
	      type => "wevtutil",
              criticalpatterns => ["Adobe", "Photoshop" ],
              warningpatterns => ["Battery low" ],
              wevtutil => {
              	eventlog => "application",
              }
	    }
	]    });
my $app = $cl->get_search_by_tag("app");
$app->delete_seekfile();
$app->trace("deleted seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$app->trace(sprintf "+----------------------- test %d ------------------", 1);
sleep 2;
$app->trace("initial run");
$cl->run(); # cleanup
$cl->reset();
diag("cleanup");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 2 now find the two criticals
$app->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
sleep 30;
$app->logger(undef, undef, 1, "Photoshop problem");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 3 now find the two criticals and the two warnings
$app->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
sleep 120;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));

# 2 now find the two criticals
$app->trace(sprintf "+----------------------- test %d ------------------", 4);
$cl->reset();
$app->logger(undef, undef, 1, "Photoshop problem");
sleep 10;
$app->logger(undef, undef, 1, "Photoshop problem");
sleep 10;
$app->logger(undef, undef, 1, "Photoshop problem");
sleep 10;
$app->logger(undef, undef, 1, "Photoshop problem");
sleep 10;
$app->logger(undef, undef, 1, "Photoshop problem2");
$app->logger(undef, undef, 1, "Photoshop problem");
sleep 10;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
#ok($cl->expect_result(0, 0, 6, 0, 2));
$cl->{perfdata} =~ /.*app_criticals=(\d+).*/;
my $found = $1;
diag(sprintf "reported %d errors so far. %d to come", $found, 6 - $found);
ok($cl->{exitmessage} =~ /CRITICAL/);

# 3 now find the two criticals and the two warnings
$app->trace(sprintf "+----------------------- test %d ------------------", 5);
$cl->reset();
sleep 65;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
if ($found == 6) {
ok($cl->expect_result(0, 0, 0, 0, 0));
} else {
ok($cl->expect_result(0, 0, 6 - $found, 0, 2));
}
$app->logger(undef, undef, 2, "Alert: Battery low");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 0, 0, 1));

######################################################
# lem");
$cl->reset();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 3 now find the two criticals and the two warnings
$app->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
sleep 120;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));

# 2 now find the two criticals
$app->trace(sprintf "+----------------------- test %d ------------------", 4);
$cl->reset();
$app->logger(undef, undef, 1, "Photoshop problem");
sleep 10;
$app->logger(undef, undef, 1, "Photoshop problem");
sleep 10;
$app->logger(undef, undef, 1, "Photoshop problem");
sleep 10;
$app->logger(undef, undef, 1, "Photoshop problem");
sleep 10;
$app->logger(undef, undef, 1, "Photoshop problem2");
$app->logger(undef, undef, 1, "Photoshop problem");
sleep 10;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
#ok($cl->expect_result(0, 0, 6, 0, 2));
$cl->{perfdata} =~ /.*app_criticals=(\d+).*/;
$found = $1;
diag(sprintf "reported %d errors so far. %d to come", $found, 6 - $found);
ok($cl->{exitmessage} =~ /CRITICAL/);

# 3 now find the two criticals and the two warnings
$app->trace(sprintf "+----------------------- test %d ------------------", 5);
$cl->reset();
sleep 65;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
if ($found == 6) {
ok($cl->expect_result(0, 0, 0, 0, 0));
} else {
ok($cl->expect_result(0, 0, 6 - $found, 0, 2));
}
$app->logger(undef, undef, 2, "Alert: Battery low");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 0, 0, 1));

######################################################
# 
# powershell -Command "echo hihi"
# leaves 
# "PowerShell-Konsole wird gestartet."
# and
# "PowerShell-Konsole ist für Benutzereingaben bereit."
# in
# Microsoft-Windows-PowerShell/Operational

$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "msps",
              type => "wevtutil",
              criticalpatterns => ["Microsoft", "Powershell.*(ready|bereit)" ],
              warningpatterns => ["Powershell.*(started|gestartet)" ],
              wevtutil => {
                eventlog => "Microsoft-Windows-PowerShell/Operational",
              }
            }
        ]    });
my $msps = $cl->get_search_by_tag("msps");
$msps->delete_seekfile();
$msps->trace("deleted seekfile");
$app->trace("initial run");
$cl->run(); # cleanup
$cl->reset();
diag("cleanup");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));
# 2 now find the two criticals
$app->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
sleep 30;
system('powershell -Command "echo hihi"');
sleep 5;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 2, 0, 2));

