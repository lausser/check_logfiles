#!/usr/bin/perl -w
#
# ~/check_logfiles/test/078critfirst.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 2;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $configfile = <<'EOCFG';
@searches = ({
  tag => 'critfirst',
  logfile => 'var/tmp/eventlog',
  #type => 'eventlog',
  #eventlog => {
  #  eventlog => 'application',
  #  include => {
  #    eventtype => 'error,warning',
  #  },
  #},
  # 'winwarncrit' mappt windows Kritikalitaet auf Nagios: ERROR->CRITICAL, WARNING->WARNING
  options => 'supersmartscript,winwarncrit,noperfdata,noprotocol,preferredlevel=critical,eventlogformat="(id:%i/so:%s) - %m"',
  script => \&reformat_output,
  criticalpatterns => [
      # hier stehen die Events (die im Eventlog vom Typ Warning oder Error sein koennen)
      # bei deren Auftauchen sofort gehandelt werden muss, die also Nagios-seitig
      # als CRITICAL eingestuft werden sollen.
      'id:1069 so:ClusSvc .* msg:Cluster Resource .* in Ressourcengruppe .* ist fehlgeschlagen',
  ],
	# TODO: Dies ist nur ein Beispiel, wie man ein durch winwarncrit kritisches Event
	# wieder auf Warning zurueckstufen kann:
	criticalexceptions => [
	'id:.* so:.* ca:.* msg:.*Faulting application.*',
	'id:.* so:.* ca:.* msg:.*Tivoli\\\TSM\\\baclient\\\jvm60\\\jre\\\bin\\\unpack.dll.*',
	'id:.* so:.* ca:.* msg:.*Tivoli\\\TSM\\\baclient\\\jvm60\\\jre\\\bin\\\unpack200.exe.*',
	'id:.* so:AdsmClientService ca:.* msg:.*',
	'id:.* so:Perflib ca:.* msg:.*',
	'id:.* so:Userenv ca:.* msg:.*',
	'id:0010 so:.* ca:.* msg:.*',
	'id:0020 so:OCS_INVENTORY_SERVICE ca:.* msg:.*',
	'id:0033 so:SideBySide ca:.* msg:.*',
	'id:0050 so:ProIsam ca:.* msg:.*',
	'id:0109 so:.* ca:.* msg:.*',
	'id:0215 so:.* ca:.* msg:.*',
	'id:0502 so:Folder Redirection ca:.* msg:.*',
	'id:1000 so:.* ca:.* msg:.*',
	'id:1002 so:.* ca:.* msg:.*',
	'id:1026 so:.* ca:.* msg:.*',
	'id:1306 so:BCAAA ca:.* msg:.*',
	'id:1308 so:BCAAA ca:.* msg:.*',
	'id:1313 so:BCAAA ca:.* msg:.*',
	'id:1325 so:.* ca:.* msg:.*',
	'id:1529 so:Microsoft-Windows-User_Profiles_Service ca:.* msg:Roaming user profiles across forests are disabled.*',
	'id:4096 so:.* ca:.* msg:.*',
	'id:4187 so:mgmtagnt ca:2 msg:.*',
	],
	warningexceptions => [
	# die hier aufgeführten Events, sollen nicht weiter beachtet werden. 
	# \ mit \\\ angeben sonst gibt es Fehlermeldungen
	# '.* .* .* msg:.*\\\Registry\\\User.*',
	'id:.* so:.* ca:.* msg:.*Tivoli\\\TSM\\\baclient\\\jvm60\\\jre\\\bin\\\unpack.dll.*',
	'id:.* so:.* ca:.* msg:.*Tivoli\\\TSM\\\baclient\\\jvm60\\\jre\\\bin\\\unpack200.exe.*',
	'id:.* so:TCLINKLN  ca:.* msg:.*',
	'id:.* so:TCLINKSC  ca:.* msg:.*',
	'id:.* so:TCLINKSCT  ca:.* msg:.*',
	'id:0010 so:.* ca:.* msg:.*',
	'id:0020 so:OCS_INVENTORY_SERVICE  ca:.* msg:.*',
	'id:0033 so:SideBySide ca:.* msg:',
	'id:0050 so:ProIsam  ca:.* msg:.*',
	'id:0502 so:ERA_SERVER  ca:.* msg:.*',
	'id:0502 so:Folder Redirection  ca:.* msg:.*',
	'id:1000 so:.* ca:.* msg:.*',
	'id:1002 so:.* ca:.* msg:.*',
	'id:1026 so:.* ca:.* msg:.*',
	'id:1030 so:Userenv  ca:.* msg:.*',
	'id:1055 so:Userenv  ca:.* msg:.*',
	'id:1058 so:Userenv  ca:.* msg:.*',
	'id:1109 so:Userenv  ca:.* msg:.*',
	'id:11312 so:FSPeripheryApplication  ca:.* msg:.*',
	'id:1306 so:BCAAA ca:.* msg:.*',
	'id:1309 so:ASP.Net_xxx  ca:.* msg:.*',
	'id:1313 so:BCAAA ca:.* msg:.*',
	'id:1325 so:.* ca:.* msg:.*',
	'id:1516 so:Userenv  ca:.* msg:.*',
	'id:1517 so:Userenv  ca:.* msg:.*',
	'id:1524 so:Userenv  ca:.* msg:.*',
	'id:1529 so:Microsoft-Windows-User_Profiles_Service ca:.* msg:Roaming user profiles across forests are disabled.*',
	'id:1529 so:Userenv  ca:.* msg:.*',
	'id:1530 so:User Profile Service  ca:.* msg:.*',
	'id:16022 so:TCOSS  ca:.* msg:.*',
	'id:2003 so:Perflib  ca:.* msg:.*',
	'id:4096 so:Server_Intelligence_Agent  ca:.* msg:.*',
	'id:4097 so:AdsmClientService  ca:.* msg:.*',
	'id:4099 so:AdsmClientService  ca:.* msg:.*',
	'id:4100 so:AdsmClientService  ca:.* msg:.*',
	'id:4101 so:AdsmClientService  ca:.* msg:.*',
	'id:4103 so:AdsmClientService  ca:.* msg:.*',
	'id:4187 so:mgmtagnt ca:2 msg:.*',
	],
	# saemtliche anderen Events (auch solche, die noch niemals vorgekommen sind)
	# erscheinen in Nagios als WARNING.
	warningpatterns => [
	  '.*',
	],
},);

sub reformat_output{
	(my $out = $ENV{CHECK_LOGFILES_SERVICEOUTPUT}) =~ s/.*id:(.*)?so:(.*)?/ID:$1 SO:$2/;
	print $out;
	return $ENV{CHECK_LOGFILES_SERVICESTATEID};
}

$options = 'report=long';

EOCFG
my $testdir = TESTDIR;
$configfile =~ s/TESTDIR/"$testdir"/g;
open CCC, ">./etc/check_critfirst.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_critfirst.cfg" });
my $critfirst = $cl->get_search_by_tag("critfirst");

$critfirst->delete_logfile();
$critfirst->delete_seekfile();
$critfirst->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$critfirst->trace(sprintf "+----------------------- test %d ------------------", 1);
$critfirst->logger(undef, undef, 2, "Failed password for invalid user1...");
sleep 2;
$critfirst->loggercrap(undef, undef, 100);
sleep 1;
$critfirst->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 2 now find the two criticals
$critfirst->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
#$critfirst->loggercrap(undef, undef, 10);
$critfirst->logger(undef, undef, 2, "EE_WW_TTid:1111 so:test msg:WinWarn");
$critfirst->logger(undef, undef, 2, "EE_CC_TTid:2222 so:test msg:WinCrit");
$critfirst->logger(undef, undef, 2, "EE_CC_TTid:1069 so:ClusSvc alarm msg:Cluster Resource CL1 in Ressourcengruppe CL ist fehlgeschlagen");
$critfirst->logger(undef, undef, 2, "EE_WW_TTid:1111 so:test msg:WinWarn");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{long_exitmessage});
ok($cl->expect_result(0, 6, 2, 0, 2));

