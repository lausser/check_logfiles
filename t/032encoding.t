#!/usr/bin/perl -w
#
# ~/check_logfiles/test/032encoding.t
#
#  Test everything using windows encoding.
#

use strict;
use Test::More;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

if (($^O ne "cygwin") and ($^O !~ /MSWin/)) {
  diag("this is not a windows machine");
  plan skip_all => 'Test only relevant on Windows';
} else {
  plan tests => 2;
}


my $cl = Nagios::CheckLogfiles::Test->new({
options => "supersmartpostscript",
postscript => sub {
 printf "doooooof\n"; 
 return $ENV{CHECK_LOGFILES_SERVICESTATEID}; 
},
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "enc",
	      type => 'simple',
              logfile => -f 'c:\Windows\Tasks\SchedLgU.txt' ?
                'c:\Windows\Tasks\SchedLgU.txt' : 'C:\WINDOWS\SchedLgU.txt',
	      #criticalpatterns => "MpCmdRun\.exe",
# sollte immer drinstehen wegen was auch immer
              criticalpatterns => ['Ergebnis', 'Gestartet'],
	      options => 'encoding=ucs-2'
	    }
	]    });
my $enc = $cl->get_search_by_tag("enc");
$enc->delete_seekfile();
$enc->trace("deleted seekfile");


$enc->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$enc->{newstate}->{logoffset} = 0;
$enc->{newstate}->{logtime} = 0;
$enc->savestate();
# now find the two criticals
$enc->trace("==== 2 ====");
$cl->reset();
sleep 1;
$cl->run();
#printf "%s\n", Data::Dumper::Dumper($enc->{matchlines});
#printf "%s\n", Data::Dumper::Dumper($cl);
diag($cl->has_result());
diag($cl->{exitmessage});
#ok($cl->expect_result(0, 0, 2, 0, 2)); # genaue  zahl kann variieren
ok($cl->{exitcode} == 2);

