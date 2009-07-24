#!/usr/bin/perl -w
#
# ~/check_logfiles/test/061maxlength.t
#
#  Test the maxlength option
#

use strict;
use Test::More tests => 5;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Bedrohung gefunden",
	      warningpatterns => "Unknown user",
              options => 'maxlength=150',
	    }
	]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->trace(sprintf "+----------------------- test %d ------------------", 1);
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "2009-02-19 09:21:47,Erzwungene proaktive TruScan-Bedrohung gefunden,Computer-Name: r0764,Erkennungstyp: Heuristisch,Anwendungsname: Java(TM) Platform SE 6 U11,Anwendungstyp: Trojaner-Wurm,Anwendungsversion: 6.0.110.3,Hash-Typ: SHA-1,Anwendungs-Hash: a6abbadf4a7d0be5c45ec25be328b0d9eee601d9,Firmenname: Sun Microsystems\~ Inc.,Dateigröße (Byte): 144792,Empfindlichkeit: 0,Erkennungsergebnis: 0,Übertragungsempfehlung: 0,Grund für Anwendungszulassung: 0,Quelle: Heuristic Scan,Risikoname: ,Vorkommnisse2009-02-19 11:31:50,Erzwungene proaktive TruScan-Bedrohung erkannt,Computer-Name: r0764,Erkennungstyp: Heuristisch,Anwendungsname: Java(TM) Platform SE 6 U11,Anwendungstyp: Trojaner-Wurm,Anwendungsversion: 6.0.110.3,Hash-Typ: SHA-1,Anwendungs-Hash: a6abbadf4a7d0be5c45ec25be328b0d9eee601d9,Firmenname: Sun Microsystems\~ Inc.,Dateigröße (Byte): 144792,Empfindlichkeit: 0,Erkennungsergebnis: 0,Übertragungsempfehlung: 0,Grund für Anwendungszulassung: 0,Quelle: Heuristic Scan,Risikoname: ,Vorkommnisse: 1,c:/windows/system32");
sleep 2;
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 2 now find the two criticals
$ssh->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "2009-02-19 09:21:47,Erzwungene proaktive TruScan-Bedrohung gefunden,Computer-Name: r0764,Erkennungstyp: Heuristisch,Anwendungsname: Java(TM) Platform SE 6 U11,Anwendungstyp: Trojaner-Wurm,Anwendungsversion: 6.0.110.3,Hash-Typ: SHA-1,Anwendungs-Hash: a6abbadf4a7d0be5c45ec25be328b0d9eee601d9,Firmenname: Sun Microsystems\~ Inc.,Dateigröße (Byte): 144792,Empfindlichkeit: 0,Erkennungsergebnis: 0,Übertragungsempfehlung: 0,Grund für Anwendungszulassung: 0,Quelle: Heuristic Scan,Risikoname: ,Vorkommnisse2009-02-19 11:31:50,Erzwungene proaktive TruScan-Bedrohung erkannt,Computer-Name: r0764,Erkennungstyp: Heuristisch,Anwendungsname: Java(TM) Platform SE 6 U11,Anwendungstyp: Trojaner-Wurm,Anwendungsversion: 6.0.110.3,Hash-Typ: SHA-1,Anwendungs-Hash: a6abbadf4a7d0be5c45ec25be328b0d9eee601d9,Firmenname: Sun Microsystems\~ Inc.,Dateigröße (Byte): 144792,Empfindlichkeit: 0,Erkennungsergebnis: 0,Übertragungsempfehlung: 0,Grund für Anwendungszulassung: 0,Quelle: Heuristic Scan,Risikoname: ,Vorkommnisse: 1,c:/windows/system32");
$ssh->logger(undef, undef, 2, "Failed password for invalid user2...");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));
ok(length $cl->{lastmsg}->{CRITICAL} == 150);
#printf "%s\n", Data::Dumper::Dumper($cl);

my $perlpath = `which perl`;
chomp $perlpath;
if ($^O =~ /MSWin/) {
 if (-f 'C:\strawberry\perl\bin\perl.exe') {
  $perlpath = 'C:\strawberry\perl\bin\perl';
 } else {
  $perlpath = 'C:\Perl\bin\perl';
 }
  $ssh->{logfile} =~ s/\//\\/g;
}

my $command = sprintf $perlpath.' ../plugins-scripts/check_logfiles --tag=%s --criticalpattern="%s" --warningpattern="%s" --maxlength=120 --logfile=%s --seekfilesdir %s',
    $ssh->{tag}, $ssh->{patterns}->{CRITICAL}->[0],
    $ssh->{patterns}->{WARNING}->[0],
    $ssh->{logfile}, $cl->{seekfilesdir};

$ssh->trace("executing %s", $command);
$ssh->trace("deleting logfile and seekfile");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->trace("==== 1 ====");
$ssh->logger(undef, undef, 2, "Failed password for invalid user1");
my $output = `$command`;
diag($output);
ok(($output =~ /OK - no errors or warnings/) && (($? >> 8) == 0));
$ssh->logger(undef, undef, 2, "2009-02-19 09:21:47,Erzwungene proaktive TruScan-Bedrohung gefunden,Computer-Name: r0764,Erkennungstyp: Heuristisch,Anwendungsname: Java(TM) Platform SE 6 U11,Anwendungstyp: Trojaner-Wurm,Anwendungsversion: 6.0.110.3,Hash-Typ: SHA-1,Anwendungs-Hash: a6abbadf4a7d0be5c45ec25be328b0d9eee601d9,Firmenname: Sun Microsystems\~ Inc.,Dateigröße (Byte): 144792,Empfindlichkeit: 0,Erkennungsergebnis: 0,Übertragungsempfehlung: 0,Grund für Anwendungszulassung: 0,Quelle: Heuristic Scan,Risikoname: ,Vorkommnisse2009-02-19 11:31:50,Erzwungene proaktive TruScan-Bedrohung erkannt,Computer-Name: r0764,Erkennungstyp: Heuristisch,Anwendungsname: Java(TM) Platform SE 6 U11,Anwendungstyp: Trojaner-Wurm,Anwendungsversion: 6.0.110.3,Hash-Typ: SHA-1,Anwendungs-Hash: a6abbadf4a7d0be5c45ec25be328b0d9eee601d9,Firmenname: Sun Microsystems\~ Inc.,Dateigröße (Byte): 144792,Empfindlichkeit: 0,Erkennungsergebnis: 0,Übertragungsempfehlung: 0,Grund für Anwendungszulassung: 0,Quelle: Heuristic Scan,Risikoname: ,Vorkommnisse: 1,c:/windows/system32");

$output = `$command`;
diag($output);
#CRITICAL - (2 errors in check_logfiles.protocol-2009-02-19-13-46-49) - Feb 19 13:46:48 localhost check_logfiles[3751] 2009-02-19 09:21:47,Erzwungene proaktive TruScan-Bedrohung gefunden,Compu ...|ssh_lines=2 ssh_warnings=0 ssh_criticals=2 ssh_unknowns=0
$output =~ / \- ([a-zA-Z]{3}.*) \.\.\./;
ok(length $1 == 120);
diag($1);
diag(length $1);
