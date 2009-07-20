#!/usr/bin/perl -w
#
# ~/check_logfiles/test/007threshold.t
#
#  Test that all the Perl modules we require are available.
#  Simulate a portscan. Connections to port 80 are ok.
#

use strict;
use Test::More tests => 36;
use Cwd;
use Data::Dumper;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
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
          warningthreshold => 3
	    }
	]    });
my $nmap = $cl->get_search_by_tag("nmap");
$cl->reset();
$nmap->delete_logfile();
$nmap->delete_seekfile();
diag("deleted logfile and seekfile");
$nmap->trace("deleted logfile and seekfile");
$nmap->logger(undef, undef, 100, "connection refused");  # 100 C
diag("wrote 100 messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); # 1

$cl->reset();
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 100, "connection refused");  # 100 C
$nmap->loggercrap(undef, undef, 100);
foreach my $port (1..70) {
  $nmap->logger(undef, undef, 1, "connection on port $port");  # 70 C
}
sleep 1;
$cl->run();
#diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
#diag(Data::Dumper::Dumper($nmap->{laststate}));
#diag(Data::Dumper::Dumper($nmap->{newstate}));
$nmap->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 17, 0, 2));  # 170 C insges. / 10    # 2

$cl->reset();
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 100, "connection refused");   # 100 C
$nmap->loggercrap(undef, undef, 100);
foreach my $port (1..100) {
  $nmap->logger(undef, undef, 1, "connection on port $port"); # 99 C  1 W
}
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 30, "connection on port 80");  # 30 W
$nmap->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
$nmap->dump_protocol();
#diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
#diag(Data::Dumper::Dumper($nmap->{laststate}));
#diag(Data::Dumper::Dumper($nmap->{newstate}));
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 10, 19, 0, 2)); # 199 C  31 W    # 3
# 199 = 19 * _10_ + 9, 31 = 10 * _3_ + 1
# rest 9 C  1 W

$cl->reset();
$cl->run(); # logfile did not change. do nothing
ok($cl->expect_result(0, 0, 0, 0, 0));   # 4

sleep 10;
$cl->reset();
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 12, "connection refused"); # 9 waren uebrig, + 12 = 21
# es ist auch noch eine warning uebrig. diese ist aber erst dann wieder relevant, wenn noch weitere neue warnings dazukommen und die schwelle ueberschreiten
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));   # 5
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 1) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 1));    # 6

$cl->reset();
$nmap->logger(undef, undef, 9, "connection refused"); # 1 C uebrig, + 9 = 10
$nmap->logger(undef, undef, 5, "connection on port 80");  # 1 W uebrig + 5 = 6
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 1, 0, 2));   # 7
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 0) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 0));   # 8

$cl = undef;
$nmap = undef;

$cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
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
          options => "nosavethresholdcount",
	    }
	]    });
$nmap = $cl->get_search_by_tag("nmap");
$cl->reset();
$nmap->delete_logfile();
$nmap->delete_seekfile();
diag(Data::Dumper::Dumper($nmap->{options}));
diag("deleted logfile and seekfile");
$nmap->trace("deleted logfile and seekfile");
$nmap->logger(undef, undef, 100, "connection refused");
diag("wrote 100 messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); ## reset run 9

$cl->reset();
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 100, "connection refused");  # 100 C
$nmap->loggercrap(undef, undef, 100);
foreach my $port (1..70) {
  $nmap->logger(undef, undef, 1, "connection on port $port"); #  70 C
}
sleep 1;
$cl->run();
#diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
#diag(Data::Dumper::Dumper($nmap->{laststate}));
#diag(Data::Dumper::Dumper($nmap->{newstate}));
$nmap->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 17, 0, 2)); # 10

$cl->reset();
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 100, "connection refused");  # 100 C
$nmap->loggercrap(undef, undef, 100);
foreach my $port (1..100) {
  $nmap->logger(undef, undef, 1, "connection on port $port"); # 99C  1 W
}
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 30, "connection on port 80");  # 30 W
$nmap->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
$nmap->dump_protocol();
diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
#diag(Data::Dumper::Dumper($nmap->{laststate}));
#diag(Data::Dumper::Dumper($nmap->{newstate}));
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 10, 19, 0, 2)); # 11

$cl->reset();
$cl->run();
ok($cl->expect_result(0, 0, 0, 0, 0)); # 12

$cl->reset();
diag("thresholdcnt must be 0");
diag(Data::Dumper::Dumper($cl->{allerrors}));
diag(Data::Dumper::Dumper($nmap->{threshold}));
diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 12, "connection refused hihi"); # 12 C
$cl->run();
diag("now it is");
diag(Data::Dumper::Dumper($nmap->{matchlines}));
diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
diag(Data::Dumper::Dumper($cl->{allerrors}));
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 13


$cl->reset();
$nmap->logger(undef, undef, 9, "connection refused hoho");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); # 14
ok($nmap->{thresholdcnt}->{CRITICAL} == 9);

$cl->reset();
$nmap->logger(undef, undef, 15, "connection refused haha");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 16
ok($nmap->{thresholdcnt}->{CRITICAL} == 5);

####################################################################
# now the same but with the new method
# options => 'criticalthreshold=x,warningthreshold=y

$cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [ {
	      tag => "nmap",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => [ 
              'connection refused', 
              'connection on port\s+\d+',
              'session aborted'
          ], 
          criticalexceptions => 'connection on port\s+80[^\d]*',
          warningpatterns => [ 
              '.*total size is 0 .*', 
              'connection on port\s+80[^\d]*', 
          ],
          options => 'criticalthreshold=10,warningthreshold=3',
    } ]    });
$nmap = $cl->get_search_by_tag("nmap");
$cl->reset();
$nmap->delete_logfile();
$nmap->delete_seekfile();
diag("deleted logfile and seekfile");
$nmap->trace("deleted logfile and seekfile");
$nmap->logger(undef, undef, 100, "connection refused");  # 100 C
diag("wrote 100 messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); # 1

$cl->reset();
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 100, "connection refused");  # 100 C
$nmap->loggercrap(undef, undef, 100);
foreach my $port (1..70) {
  $nmap->logger(undef, undef, 1, "connection on port $port");  # 70 C
}
sleep 1;
$cl->run();
#diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
#diag(Data::Dumper::Dumper($nmap->{laststate}));
#diag(Data::Dumper::Dumper($nmap->{newstate}));
$nmap->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 17, 0, 2));  # 170 C insges. / 10    # 2

$cl->reset();
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 100, "connection refused");   # 100 C
$nmap->loggercrap(undef, undef, 100);
foreach my $port (1..100) {
  $nmap->logger(undef, undef, 1, "connection on port $port"); # 99 C  1 W
}
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 30, "connection on port 80");  # 30 W
$nmap->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
$nmap->dump_protocol();
#diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
#diag(Data::Dumper::Dumper($nmap->{laststate}));
#diag(Data::Dumper::Dumper($nmap->{newstate}));
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 10, 19, 0, 2)); # 199 C  31 W    # 3
# 199 = 19 * _10_ + 9, 31 = 10 * _3_ + 1
# rest 9 C  1 W

$cl->reset();
$cl->run(); # logfile did not change. do nothing
ok($cl->expect_result(0, 0, 0, 0, 0));   # 4

sleep 10;
$cl->reset();
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 12, "connection refused"); # 9 waren uebrig, + 12 = 21
# es ist auch noch eine warning uebrig. diese ist aber erst dann wieder relevant, wenn noch weitere neue warnings dazukommen und die schwelle ueberschreiten
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));   # 5
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 1) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 1));    # 6

$cl->reset();
$nmap->logger(undef, undef, 9, "connection refused"); # 1 C uebrig, + 9 = 10
$nmap->logger(undef, undef, 5, "connection on port 80");  # 1 W uebrig + 5 = 6
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 1, 0, 2));   # 7
ok(($nmap->{newstate}->{thresholdcnt}->{CRITICAL} == 0) &&
    ($nmap->{newstate}->{thresholdcnt}->{WARNING} == 0));   # 8

$cl = undef;
$nmap = undef;

$cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "nmap",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => [ 
              'connection refused', 
              'connection on port\s+\d+',
              'session aborted'
          ], 
          criticalexceptions => 'connection on port\s+80[^\d]*',
          warningpatterns => [ 
              '.*total size is 0 .*', 
              'connection on port\s+80[^\d]*', 
          ],
          options => 'criticalthreshold=10,warningthreshold=3,nosavethresholdcount',
	    }
	]    });
$nmap = $cl->get_search_by_tag("nmap");
$cl->reset();
$nmap->delete_logfile();
$nmap->delete_seekfile();
diag(Data::Dumper::Dumper($nmap->{options}));
diag("deleted logfile and seekfile");
$nmap->trace("deleted logfile and seekfile");
$nmap->logger(undef, undef, 100, "connection refused");
diag("wrote 100 messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); ## reset run 9

$cl->reset();
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 100, "connection refused");  # 100 C
$nmap->loggercrap(undef, undef, 100);
foreach my $port (1..70) {
  $nmap->logger(undef, undef, 1, "connection on port $port"); #  70 C
}
sleep 1;
$cl->run();
#diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
#diag(Data::Dumper::Dumper($nmap->{laststate}));
#diag(Data::Dumper::Dumper($nmap->{newstate}));
$nmap->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 17, 0, 2)); # 10

$cl->reset();
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 100, "connection refused");  # 100 C
$nmap->loggercrap(undef, undef, 100);
foreach my $port (1..100) {
  $nmap->logger(undef, undef, 1, "connection on port $port"); # 99C  1 W
}
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 30, "connection on port 80");  # 30 W
$nmap->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
$nmap->dump_protocol();
diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
#diag(Data::Dumper::Dumper($nmap->{laststate}));
#diag(Data::Dumper::Dumper($nmap->{newstate}));
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 10, 19, 0, 2)); # 11

$cl->reset();
$cl->run();
ok($cl->expect_result(0, 0, 0, 0, 0)); # 12

$cl->reset();
diag("thresholdcnt must be 0");
diag(Data::Dumper::Dumper($cl->{allerrors}));
diag(Data::Dumper::Dumper($nmap->{threshold}));
diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 12, "connection refused hihi"); # 12 C
$cl->run();
diag("now it is");
diag(Data::Dumper::Dumper($nmap->{matchlines}));
diag(Data::Dumper::Dumper($nmap->{thresholdcnt}));
diag(Data::Dumper::Dumper($cl->{allerrors}));
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 13


$cl->reset();
$nmap->logger(undef, undef, 9, "connection refused hoho");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); # 14
ok($nmap->{thresholdcnt}->{CRITICAL} == 9);

$cl->reset();
$nmap->logger(undef, undef, 15, "connection refused haha");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 16
ok($nmap->{thresholdcnt}->{CRITICAL} == 5);


###### now with --criticalthreshold --warningtheshold


$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "nmap",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => [
              'connection refused',
              'connection on port\s+\d+',
              'session aborted'
          ],
          criticalexceptions => 'connection on port\s+80[^\d]*',
          warningpatterns => [
              '.*total size is 0 .*',
              'connection on port\s+80[^\d]*',
          ],
          options => 'criticalthreshold=10,warningthreshold=3,nosavethresholdcount',
            }
        ]    });
$nmap = $cl->get_search_by_tag("nmap");
$cl->reset();
$nmap->delete_logfile();
$nmap->delete_seekfile();
diag(Data::Dumper::Dumper($nmap->{options}));
diag("deleted logfile and seekfile");
$nmap->trace("deleted logfile and seekfile");
$nmap->logger(undef, undef, 100, "connection refused");
diag("wrote 100 messages");
sleep 1;

# dummy command
my $perlpath = `which perl`;
chomp $perlpath;
if ($^O =~ /MSWin/) {
 if (-f 'C:\strawberry\perl\bin\perl.exe') {
  $perlpath = 'C:\strawberry\perl\bin\perl';
 } else {
  $perlpath = 'C:\Perl\bin\perl';
 }
  $nmap->{logfile} =~ s/\//\\/g;
}

my $command = sprintf $perlpath.' ../plugins-scripts/check_logfiles --tag=nmap --criticalpattern="(connection refused)|(connection on port\\s+\\d+)|(session aborted)" --warningpattern="(.*total size is 0 .*)|(connection on port\\s+80[^\\d]*)" --logfile %s --warningthreshold 3 --criticalthreshold 10 --seekfilesdir "%s"',
     $nmap->{logfile}, $nmap->{seekfilesdir};
diag("now run a dummy commandline");
my $output = `$command`;
diag($output);
ok(($output =~ /OK - no errors or warnings/) && (($? >> 8) == 0));


$cl->reset();
$nmap->loggercrap(undef, undef, 100);
$nmap->logger(undef, undef, 100, "connection refused");  # 100 C
$nmap->loggercrap(undef, undef, 100);
foreach my $port (1..70) {
  $nmap->logger(undef, undef, 1, "connection on port $port"); #  70 C
}
sleep 1;
$nmap->trace("executing %s", $command);
diag("now run the real commandline which expects 17 criticals");
$output = `$command`;
diag($output);
ok(($output =~ /CRITICAL - \(17 errors/) && (($? >> 8) == 2));



