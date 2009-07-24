#!/usr/bin/perl -w
#
# ~/check_logfiles/test/001simple.t
#
#  Test that all the Perl modules we require are available.
#

# vielen Dank für die Info. Mein Problem wäre jetzt in diesem Fall, das sich die Logdateien jeden Tag bzw. jedes mal anders nennen. Einige Logdateien tragen den Namen LOGBUCH20060801230000{b] und andere [B]LOGFILE_200631. Also einmal mit Jahr, Monat, Tag, Stunde, Minute, Sekunde und das andere Logfile mit Jahr, Kalenderwoche. Habe das zur Zeit mit Platzhaltern gelöst. Also wenn ich in einem Skript LOGFILE_JJJJKW stehen habe, wird der Dateiname durch das aktuelle Jahr und die aktuelle Kalenderwoche ersetzt.


use strict;
use Test::More tests => 2;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my($sec, $min, $hour, $mday, $mon, $year) = (localtime(time -86400))[0, 1, 2, 3, 4, 5];
$year += 1900; $mon += 1;
my $sauvegarde = sprintf "sauvegarde%02d-%02d-%04d.log", $mday, $mon, $year;

my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	macros => { VARDIR => '/var/adm', EVILUSER => 'lausser/2'},
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR.'$VARDIR$/'.$sauvegarde,
	      criticalpatterns => ["Failed password", 'evil user $EVILUSER$ logged in'],
	      warningpatterns => "Unknown user"
	    }
	]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
#
# BUT!!!! these might be one-shot logfiles. they must be searched from pos 0
#
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
sleep 1;
$ssh->trace(sprintf "initial run for file %s", $ssh->{logfile});
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find the two criticals
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2...");
$ssh->logger(undef, undef, 1, "alert! evil user lausser/2 logged in");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 3, 0, 2));
