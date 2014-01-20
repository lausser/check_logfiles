#!/usr/bin/perl -w
#
# ~/check_logfiles/test/100flooddetect.t
#
#  Test that all the Perl modules we require are available.
#  Events need not exceed a certain rate. Timestamps need to be taken into account.
#  A short history of events needs to be saved after every run.
#  With the advent of a critical pattern, the rate of events needs to be calculated.
#

#  Test 1:
#  Maximum of 10 event per minute can be tolerated
#  Simulate a check_period of 5 minutes
#  Start - within the first minute create an event every 2 seconds
#

use strict;
use Test::More tests => 36;
use Cwd;
use Data::Dumper;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $configfile = <<'EOCFG';

sub timestamp {
  my $string = shift;
  my($sec, $min, $hour, $mday, $mon, $year) =
      (localtime)[0, 1, 2, 3, 4, 5];
  # Oct 31 15:49:21
  $string =~ /^(\w+) (\d+) (\d+):(\d+):(\d+)/;
  my $time = POSIX::mktime($5, $4, $3, $2, {
      "Jan" => 0, "Feb" => 1, "Mar" => 2, "Apr" => 3, "May" => 4, "Jun" => 5, 
      "Jul" => 6, "Aug" => 7, "Sep" => 8, "Oct" => 9, "Nov" => 10, "Dec" => 11
  }->{$1}, $year);
  return $time;
}

sub flood_check
{
  my $fc = shift; # max flood events count
  my $fp = shift; # max flood time period for $fc events
  my $en = shift; # event name (key) which identifies flood check data

  $FLOOD{ $en } ||= [];   # make empty flood array for this event name
  my $ar = $FLOOD{ $en }; # get array ref for event's flood array
  my $ec = @$ar;          # events count in the flood array
  
  if( $ec >= $fc ) 
    {
    # flood array has enough events to do real flood check
    my $ot = $$ar[0];      # oldest event timestamp in the flood array
    my $tp = time() - $ot; # time period between current and oldest event
    
    # now calculate time in seconds until next allowed event
    my $wait = int( ( $ot + ( $ec * $fp / $fc ) ) - time() );
    if( $wait > 0 )
      {
      # positive number of seconds means flood in progress
      # event should be rejected or postponed
      return $wait;
      }
    # negative or 0 seconds means that event should be accepted
    # oldest event is removed from the flood array
    shift @$ar;
    }
  # flood array is not full or oldest event is already removed
  # so current event has to be added
  push  @$ar, time();
  # event is ok
  return 0;
}

sub is_flood {
  my $events = shift;
  my $event_time = shift;
  my $flood_events = shift; # max flood events count
  my $flood_period = shift; # max flood time period for $fc events
  my $num_events = scalar(@{$events});
  if ($num_events >= $flood_events) {
printf STDERR "num_events %d  flood_events %d\n", $num_events, $flood_events;
    # enough elements to make a reliable calculation
    my $oldest_event_time = $$events[0];
    my $period = $event_time - $oldest_event_time; 
printf STDERR "oldest %s ... period %d\n", scalar localtime $oldest_event_time, $period;
    my $wait = int( ( $oldest_event_time + ( $num_events * $flood_period / $flood_events ) ) - $event_time );
    if ($wait > 0) {
      return $wait;
    } else {
      shift @{$events};
      return 0;
    }
  } else {
    push(@{$events}, $event_time);
    return 0;
  }
}

$seekfilesdir = "./var/tmp";
$scriptpath = "./bin";
@searches = ({
    tag => "flood",
    logfile => "./var/adm/messages",
    criticalpatterns => [ 
        'connection refused', 
        'connection on port\s+\d+',
        'session aborted'
    ], 
    options => "supersmartscript",
    script => sub {
      my $line = $ENV{CHECK_LOGFILES_SERVICEOUTPUT};
      if (! exists $CHECK_LOGFILES_PRIVATESTATE->{eventhistory}) {
        $CHECK_LOGFILES_PRIVATESTATE->{eventhistory} = [];
        printf STDERR "initialized eventhistory\n";
      }
      my $flood = is_flood($CHECK_LOGFILES_PRIVATESTATE->{eventhistory}, timestamp($line), 5, 10);
      if ($flood) {
        printf "floot reached %.3f at %s\n", $flood, scalar localtime timestamp($line);
        return 2;
      } else {
        return 0;
      }
    },
});

#$options = "supersmartpostscript";
$postscript = sub {
  my $state = $CHECK_LOGFILES_PRIVATESTATE;
  #printf STDERR "%s\n", Data::Dumper::Dumper($state);
  return 0;
};

EOCFG
open CCC, ">./etc/check_flood.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_flood.cfg" });
my $flood = $cl->get_search_by_tag("flood");
$cl->reset();
$flood->delete_logfile();
$flood->delete_seekfile();
diag("deleted logfile and seekfile");
$flood->trace("deleted logfile and seekfile");
$flood->logger(undef, undef, 100, "connection refused");  # 100 C
diag("wrote 100 messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); # 1
diag("now write an event every two seconds. duration is 2 minutes");
my $tic = time;
#foreach my $sec (1..120) {
foreach my $sec (1..20) {
  $flood->loggercrap(undef, undef, 10);
  $flood->logger(undef, undef, 1, "connection refused");
  printf STDERR "write event at %s\n", scalar localtime time;
  $flood->loggercrap(undef, undef, 10);
  sleep 1;
}
foreach my $sec (1..40) {
  $flood->loggercrap(undef, undef, 10);
  sleep 1;
}
my $tac = time;
printf "elapsed %d\n", $tac - $tic;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(15, 0, 5, 0, 2));

# write 4 events in 10 sec
# write crap in 10 sec
# repeat until a minute
$tic = time;
foreach my $loop (1..10) {
foreach my $sec (1..3) {
  $flood->loggercrap(undef, undef, 10);
  $flood->logger(undef, undef, 1, "connection refused");
  printf STDERR "write event at %s\n", scalar localtime time;
  sleep 1;
}
diag("---");
foreach my $sec (1..7) {
  $flood->loggercrap(undef, undef, 10);
  sleep 1;
}
diag("...");
}
$tac = time;
printf "4/10 sequence elapsed %d\n", $tac - $tic;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(15, 0, 5, 0, 0)); # 1

exit;

$cl->reset();
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 100, "connection refused");  # 100 C
$flood->loggercrap(undef, undef, 100);
foreach my $port (1..70) {
  $flood->logger(undef, undef, 1, "connection on port $port");  # 70 C
}
sleep 1;
$cl->run();
#diag(Data::Dumper::Dumper($flood->{thresholdcnt}));
#diag(Data::Dumper::Dumper($flood->{laststate}));
#diag(Data::Dumper::Dumper($flood->{newstate}));
$flood->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 17, 0, 2));  # 170 C insges. / 10    # 2

$cl->reset();
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 100, "connection refused");   # 100 C
$flood->loggercrap(undef, undef, 100);
foreach my $port (1..100) {
  $flood->logger(undef, undef, 1, "connection on port $port"); # 99 C  1 W
}
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 30, "connection on port 80");  # 30 W
$flood->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
$flood->dump_protocol();
#diag(Data::Dumper::Dumper($flood->{thresholdcnt}));
#diag(Data::Dumper::Dumper($flood->{laststate}));
#diag(Data::Dumper::Dumper($flood->{newstate}));
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
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 12, "connection refused"); # 9 waren uebrig, + 12 = 21
# es ist auch noch eine warning uebrig. diese ist aber erst dann wieder relevant, wenn noch weitere neue warnings dazukommen und die schwelle ueberschreiten
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));   # 5
ok(($flood->{newstate}->{thresholdcnt}->{CRITICAL} == 1) &&
    ($flood->{newstate}->{thresholdcnt}->{WARNING} == 1));    # 6

$cl->reset();
$flood->logger(undef, undef, 9, "connection refused"); # 1 C uebrig, + 9 = 10
$flood->logger(undef, undef, 5, "connection on port 80");  # 1 W uebrig + 5 = 6
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 1, 0, 2));   # 7
ok(($flood->{newstate}->{thresholdcnt}->{CRITICAL} == 0) &&
    ($flood->{newstate}->{thresholdcnt}->{WARNING} == 0));   # 8

$cl = undef;
$flood = undef;

$cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "flood",
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
$flood = $cl->get_search_by_tag("flood");
$cl->reset();
$flood->delete_logfile();
$flood->delete_seekfile();
diag(Data::Dumper::Dumper($flood->{options}));
diag("deleted logfile and seekfile");
$flood->trace("deleted logfile and seekfile");
$flood->logger(undef, undef, 100, "connection refused");
diag("wrote 100 messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); ## reset run 9

$cl->reset();
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 100, "connection refused");  # 100 C
$flood->loggercrap(undef, undef, 100);
foreach my $port (1..70) {
  $flood->logger(undef, undef, 1, "connection on port $port"); #  70 C
}
sleep 1;
$cl->run();
#diag(Data::Dumper::Dumper($flood->{thresholdcnt}));
#diag(Data::Dumper::Dumper($flood->{laststate}));
#diag(Data::Dumper::Dumper($flood->{newstate}));
$flood->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 17, 0, 2)); # 10

$cl->reset();
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 100, "connection refused");  # 100 C
$flood->loggercrap(undef, undef, 100);
foreach my $port (1..100) {
  $flood->logger(undef, undef, 1, "connection on port $port"); # 99C  1 W
}
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 30, "connection on port 80");  # 30 W
$flood->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
$flood->dump_protocol();
diag(Data::Dumper::Dumper($flood->{thresholdcnt}));
#diag(Data::Dumper::Dumper($flood->{laststate}));
#diag(Data::Dumper::Dumper($flood->{newstate}));
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 10, 19, 0, 2)); # 11

$cl->reset();
$cl->run();
ok($cl->expect_result(0, 0, 0, 0, 0)); # 12

$cl->reset();
diag("thresholdcnt must be 0");
diag(Data::Dumper::Dumper($cl->{allerrors}));
diag(Data::Dumper::Dumper($flood->{threshold}));
diag(Data::Dumper::Dumper($flood->{thresholdcnt}));
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 12, "connection refused hihi"); # 12 C
$cl->run();
diag("now it is");
diag(Data::Dumper::Dumper($flood->{matchlines}));
diag(Data::Dumper::Dumper($flood->{thresholdcnt}));
diag(Data::Dumper::Dumper($cl->{allerrors}));
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 13


$cl->reset();
$flood->logger(undef, undef, 9, "connection refused hoho");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); # 14
ok($flood->{thresholdcnt}->{CRITICAL} == 9);

$cl->reset();
$flood->logger(undef, undef, 15, "connection refused haha");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 16
ok($flood->{thresholdcnt}->{CRITICAL} == 5);

####################################################################
# now the same but with the new method
# options => 'criticalthreshold=x,warningthreshold=y

$cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [ {
	      tag => "flood",
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
$flood = $cl->get_search_by_tag("flood");
$cl->reset();
$flood->delete_logfile();
$flood->delete_seekfile();
diag("deleted logfile and seekfile");
$flood->trace("deleted logfile and seekfile");
$flood->logger(undef, undef, 100, "connection refused");  # 100 C
diag("wrote 100 messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); # 1

$cl->reset();
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 100, "connection refused");  # 100 C
$flood->loggercrap(undef, undef, 100);
foreach my $port (1..70) {
  $flood->logger(undef, undef, 1, "connection on port $port");  # 70 C
}
sleep 1;
$cl->run();
#diag(Data::Dumper::Dumper($flood->{thresholdcnt}));
#diag(Data::Dumper::Dumper($flood->{laststate}));
#diag(Data::Dumper::Dumper($flood->{newstate}));
$flood->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 17, 0, 2));  # 170 C insges. / 10    # 2

$cl->reset();
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 100, "connection refused");   # 100 C
$flood->loggercrap(undef, undef, 100);
foreach my $port (1..100) {
  $flood->logger(undef, undef, 1, "connection on port $port"); # 99 C  1 W
}
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 30, "connection on port 80");  # 30 W
$flood->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
$flood->dump_protocol();
#diag(Data::Dumper::Dumper($flood->{thresholdcnt}));
#diag(Data::Dumper::Dumper($flood->{laststate}));
#diag(Data::Dumper::Dumper($flood->{newstate}));
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
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 12, "connection refused"); # 9 waren uebrig, + 12 = 21
# es ist auch noch eine warning uebrig. diese ist aber erst dann wieder relevant, wenn noch weitere neue warnings dazukommen und die schwelle ueberschreiten
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));   # 5
ok(($flood->{newstate}->{thresholdcnt}->{CRITICAL} == 1) &&
    ($flood->{newstate}->{thresholdcnt}->{WARNING} == 1));    # 6

$cl->reset();
$flood->logger(undef, undef, 9, "connection refused"); # 1 C uebrig, + 9 = 10
$flood->logger(undef, undef, 5, "connection on port 80");  # 1 W uebrig + 5 = 6
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 1, 0, 2));   # 7
ok(($flood->{newstate}->{thresholdcnt}->{CRITICAL} == 0) &&
    ($flood->{newstate}->{thresholdcnt}->{WARNING} == 0));   # 8

$cl = undef;
$flood = undef;

$cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "flood",
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
$flood = $cl->get_search_by_tag("flood");
$cl->reset();
$flood->delete_logfile();
$flood->delete_seekfile();
diag(Data::Dumper::Dumper($flood->{options}));
diag("deleted logfile and seekfile");
$flood->trace("deleted logfile and seekfile");
$flood->logger(undef, undef, 100, "connection refused");
diag("wrote 100 messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); ## reset run 9

$cl->reset();
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 100, "connection refused");  # 100 C
$flood->loggercrap(undef, undef, 100);
foreach my $port (1..70) {
  $flood->logger(undef, undef, 1, "connection on port $port"); #  70 C
}
sleep 1;
$cl->run();
#diag(Data::Dumper::Dumper($flood->{thresholdcnt}));
#diag(Data::Dumper::Dumper($flood->{laststate}));
#diag(Data::Dumper::Dumper($flood->{newstate}));
$flood->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 17, 0, 2)); # 10

$cl->reset();
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 100, "connection refused");  # 100 C
$flood->loggercrap(undef, undef, 100);
foreach my $port (1..100) {
  $flood->logger(undef, undef, 1, "connection on port $port"); # 99C  1 W
}
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 30, "connection on port 80");  # 30 W
$flood->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
$flood->dump_protocol();
diag(Data::Dumper::Dumper($flood->{thresholdcnt}));
#diag(Data::Dumper::Dumper($flood->{laststate}));
#diag(Data::Dumper::Dumper($flood->{newstate}));
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 10, 19, 0, 2)); # 11

$cl->reset();
$cl->run();
ok($cl->expect_result(0, 0, 0, 0, 0)); # 12

$cl->reset();
diag("thresholdcnt must be 0");
diag(Data::Dumper::Dumper($cl->{allerrors}));
diag(Data::Dumper::Dumper($flood->{threshold}));
diag(Data::Dumper::Dumper($flood->{thresholdcnt}));
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 12, "connection refused hihi"); # 12 C
$cl->run();
diag("now it is");
diag(Data::Dumper::Dumper($flood->{matchlines}));
diag(Data::Dumper::Dumper($flood->{thresholdcnt}));
diag(Data::Dumper::Dumper($cl->{allerrors}));
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 13


$cl->reset();
$flood->logger(undef, undef, 9, "connection refused hoho");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); # 14
ok($flood->{thresholdcnt}->{CRITICAL} == 9);

$cl->reset();
$flood->logger(undef, undef, 15, "connection refused haha");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 16
ok($flood->{thresholdcnt}->{CRITICAL} == 5);


###### now with --criticalthreshold --warningtheshold


$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "flood",
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
$flood = $cl->get_search_by_tag("flood");
$cl->reset();
$flood->delete_logfile();
$flood->delete_seekfile();
diag(Data::Dumper::Dumper($flood->{options}));
diag("deleted logfile and seekfile");
$flood->trace("deleted logfile and seekfile");
$flood->logger(undef, undef, 100, "connection refused");
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
  $flood->{logfile} =~ s/\//\\/g;
}

my $command = sprintf $perlpath.' ../plugins-scripts/check_logfiles --tag=flood --criticalpattern="(connection refused)|(connection on port\\s+\\d+)|(session aborted)" --warningpattern="(.*total size is 0 .*)|(connection on port\\s+80[^\\d]*)" --logfile %s --warningthreshold 3 --criticalthreshold 10 --seekfilesdir "%s"',
     $flood->{logfile}, $flood->{seekfilesdir};
diag("now run a dummy commandline");
my $output = `$command`;
diag($output);
ok(($output =~ /OK - no errors or warnings/) && (($? >> 8) == 0));


$cl->reset();
$flood->loggercrap(undef, undef, 100);
$flood->logger(undef, undef, 100, "connection refused");  # 100 C
$flood->loggercrap(undef, undef, 100);
foreach my $port (1..70) {
  $flood->logger(undef, undef, 1, "connection on port $port"); #  70 C
}
sleep 1;
$flood->trace("executing %s", $command);
diag("now run the real commandline which expects 17 criticals");
$output = `$command`;
diag($output);
ok(($output =~ /CRITICAL - \(17 errors/) && (($? >> 8) == 2));



