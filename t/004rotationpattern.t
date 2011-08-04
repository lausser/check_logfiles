#!/usr/bin/perl -w
#
# ~/check_logfiles/test/004rotation.t
#
#  Test the capability of finding rotated logfiles.
#  moving archive files
# /pfad/YYYYMM/xxx-YYYYMMDDHH.log
#
# /archive/201005
# ....
# /archive/201005/2010053100.log
# /archive/201005/2010053101.log
# /archive/201005/2010053100.log
# ... hourly creation of a new logfile
# /archive/201005/2010053123.log
# /archive/201005
# ... new month, new archive
# /archive/201006/2010060000.log
# /archive/201006/2010060100.log

# logfile => '/archive/$CL_DATE_MM$$CL_DATE_DD$/$CL_DATE_HH$00.log'
# rotation => '\d{4}\.log'
# archivedir => '/archive/\d{4}'
# options = 'archivedirregexp=1'



use strict;
use Test::More tests => 6;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant DIR => ".";

my $logdir;
my $logfile;
my $cl;
my $ssh;
my ($year, $mon, $day, $hour);

sub log_to_file {
  my $logdir = shift;
  my $day = shift;
  my $hour = shift;
  my $errors = shift;
  my $message = shift;
  $logdir =~ /.*(\d{4})(\d{2})/;
  my ($year, $mon) = ($1, $2);
  my $cl = Nagios::CheckLogfiles::Test->new({
      seekfilesdir => './var/tmp',
      searches => [{
        tag => "unused",
	logfile => sprintf("%s/%04d%02d%02d%02d.log", $logdir, $year, $mon, $day, $hour),
	criticalpatterns => '.*',
      }]
  });
  my $dummy = $cl->get_search_by_tag("unused"); 
  printf STDERR "i will log to %s\n", $dummy->{logfile};
  $dummy->logger(undef, undef, $errors, $message);
  $dummy->loggercrap(undef, undef, 100);
}

if ($^O =~ /MSWin/) {
  system ('rd /S /Q .\var\rot');
  system ('md var\rot');
} else {
  system("rm -rf ./var/rot");
  mkdir "./var/rot";
}

#################### 31.5. 00:00
($year, $mon, $day, $hour) = (2010, 05, 31, 00);
$logdir = sprintf "./var/rot/%04d%02d", $year, $mon;
mkdir $logdir;

#################### 31.5. 12:20
($year, $mon, $day, $hour) = (2010, 05, 31, 12);
log_to_file($logdir, $day, $hour, 2, "Failed password for invalid user1");
sleep 1;

$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => './var/tmp',
	searches => [{
	  tag => "ssh",
	  type => 'rotating::uniform',
	  logfile => $logdir.'/dummy',
	  archivedir => './var/rot/\d{6}',
	  criticalpatterns => "Failed password",
	  rotation => '\d{10}\.log',
          options => 'archivedirregexp=1',
	}]
      });
$ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_seekfile();

$cl->trace("is it now 31.5. 12:20");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0)); # 1
$cl->trace("that was the initial run");

#################### 31.5. 12:25
$cl->trace("is it now 31.5. 12:25");
($year, $mon, $day, $hour) = (2010, 05, 31, 12);
log_to_file($logdir, $day, $hour, 2, "Failed password for invalid user1");
sleep 1;

$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => './var/tmp',
        searches => [{
          tag => "ssh",
          type => 'rotating::uniform',
          logfile => $logdir.'/dummy',
          archivedir => './var/rot/\d{6}',
          criticalpatterns => "Failed password",
          rotation => '\d{10}\.log',
          options => 'archivedirregexp=1',
        }]    
      });
$ssh = $cl->get_search_by_tag("ssh");

$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2)); # 2

#################### 31.5. 13:00
$cl->trace("is it now 31.5. 13:00");
($year, $mon, $day, $hour) = (2010, 05, 31, 13);
log_to_file($logdir, $day, $hour, 3, "Failed password for invalid user1");
sleep 1;

$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => './var/tmp',
        searches => [{
          tag => "ssh",
          type => 'rotating::uniform',
          logfile => $logdir.'/dummy',
          archivedir => './var/rot/\d{6}',
          criticalpatterns => "Failed password",
          rotation => '\d{10}\.log',
          options => 'archivedirregexp=1',
        }]
      });
$ssh = $cl->get_search_by_tag("ssh");

$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 3, 0, 2)); # 3

log_to_file($logdir, $day, $hour, 4, "Failed password for invalid user1");
sleep 1;

#################### 31.5. 14:05
$cl->trace("is it now 31.5. 14:05");
($year, $mon, $day, $hour) = (2010, 05, 31, 14);
log_to_file($logdir, $day, $hour, 4, "Failed password for invalid user1");
sleep 1;

$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => './var/tmp',
        searches => [{
          tag => "ssh",
          type => 'rotating::uniform',
          logfile => $logdir.'/dummy',
          archivedir => './var/rot/\d{6}',
          criticalpatterns => "Failed password",
          rotation => '\d{10}\.log',
          options => 'archivedirregexp=1',
        }]
      });
$ssh = $cl->get_search_by_tag("ssh");

$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 8, 0, 2)); # 4


log_to_file($logdir, $day, $hour, 4, "Failed password for invalid user1");
sleep 1;

#################### 31.5. 15:00
$cl->trace("is it now 31.5. 15:00");
($year, $mon, $day, $hour) = (2010, 05, 31, 15);
log_to_file($logdir, $day, $hour, 1, "Failed password for invalid user1");
sleep 1;

#################### 31.5. 22:59
$cl->trace("is it now 31.5. 22:59");
($year, $mon, $day, $hour) = (2010, 05, 31, 22);
log_to_file($logdir, $day, $hour, 1, "Failed password for invalid user1");
sleep 1;

$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => './var/tmp',
        searches => [{
          tag => "ssh",
          type => 'rotating::uniform',
          logfile => $logdir.'/dummy',
          archivedir => './var/rot/\d{6}',
          criticalpatterns => "Failed password",
          rotation => '\d{10}\.log',
          options => 'archivedirregexp=1',
        }]
      });
$ssh = $cl->get_search_by_tag("ssh");

$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 6, 0, 2)); # 5

#################### 31.5. 23:59
$cl->trace("is it now 31.5. 23:59");
($year, $mon, $day, $hour) = (2010, 05, 31, 23);
log_to_file($logdir, $day, $hour, 1, "Failed password for invalid user1");
sleep 1;

#################### 01.06. 00:01
$cl->trace("is it now 1.6. 00:01");
($year, $mon, $day, $hour) = (2010, 06, 1, 00);
$logdir = sprintf "./var/rot/%04d%02d", $year, $mon;
mkdir $logdir;
log_to_file($logdir, $day, $hour, 1, "Failed password for invalid user1");
sleep 1;

$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => './var/tmp',
        searches => [{
          tag => "ssh",
          type => 'rotating::uniform',
          logfile => $logdir.'/dummy',
          archivedir => './var/rot/\d{6}',
          criticalpatterns => "Failed password",
          rotation => '\d{10}\.log',
          options => 'archivedirregexp=1',
        }]
      });
$ssh = $cl->get_search_by_tag("ssh");

$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2)); # 5












exit;

#################### 12.5. 13:00
#################### 12.5. 13:02
#################### 12.5. 13:07
#################### 12.5. 13:20
#################### 12.5. 23:00
#################### 12.5. 23:59


# now rotate and find the two new criticals
$ssh->trace("==== 3 ====");
$ssh->rotate();
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now rotate and create no new logfile
$ssh->trace("==== 4 ====");
$ssh->rotate();
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 1, 3));

# now write messages and find them
$ssh->trace("==== 5 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now write critical messages, rotate, write harmless messages, rotate, write warning, rotate, stop
#
#
# under cygwin rotation changes modification time!!!!!!!!!!!!!
#

$ssh->trace("==== 6 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user5");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 2, 1, 2));


# now write critical messages, rotate, write harmless stuff, rotate, write warning
$ssh->trace("==== 7 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user6");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 2, 1, 2));

# repeat but this time with nologfilenocry
$cl->reset();
$ssh = $cl->get_search_by_tag("ssh");
$ssh->{options}->{logfilenocry} = 0;
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->trace("==== 8 ====");
$ssh->logger(undef, undef, 2, "Failed password for invalid user1");
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find the two criticals
$ssh->trace("==== 9 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now rotate and find the two new criticals
$ssh->trace("==== 10 ====");
$ssh->rotate();
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now rotate and create no new logfile
$ssh->trace("==== 11 ====");
$ssh->rotate();
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now write messages and find them
$ssh->trace("==== 12 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now write critical messages, rotate, write harmless messages, rotate, write warning, rotate, stop
#
#
# under cygwin rotation changes modification time!!!!!!!!!!!!!
#

$ssh->trace("==== 13 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user5");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 2, 0, 2));


# now write critical messages, rotate, write harmless stuff, rotate, write warning
$ssh->trace("==== 14 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user6");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 2, 0, 2));
