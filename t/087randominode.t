#!/usr/bin/perl -w
#
# ~/check_logfiles/test/087randominode.t
#
#  Test the capability of finding rotated logfiles by ignoring inodes.
#
# writing a logline causes the inode to change
# log 1W 2C
# check_logfiles -> initial
# log 1W 3C
# check_logfiles -> thinks it is new. starts and finds 1W 3C
# log
# check_logfiles -> thinks it is new. starts and finds 1W 3C
# log 1C
# check_logfiles -> thinks it is new. starts and finds 1W 4C

use strict;
use Test::More;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

if ($^O =~ /MSWin/) {
  diag("this is not a windows machine");
  plan skip_all => 'Test not relevant on Windows';
} else {
  plan tests => 8;
}

my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      rotation => "SOLARIS",
	    }
	]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->logger(undef, undef, 2, "Failed password for invalid user1");
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now 1W 3C
$ssh->trace("==== 2 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user hihi");
$ssh->logger(undef, undef, 3, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
system("cp ./var/adm/messages temptemptemp");
system("mv temptemptemp ./var/adm/messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 5, 0, 2)); # 2C aus dem initial run

# now nothing
$ssh->trace("==== 3 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->loggercrap(undef, undef, 100);
system("cp ./var/adm/messages temptemptemp");
system("mv temptemptemp ./var/adm/messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 5, 0, 2));

# now 1C
$ssh->trace("==== 4 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
system("cp ./var/adm/messages temptemptemp");
system("mv temptemptemp ./var/adm/messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 6, 0, 2));




$cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      rotation => "SOLARIS",
              options => 'randominode',
	    }
	]    });
$ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->logger(undef, undef, 2, "Failed password for invalid user1");
sleep 1;
$ssh->trace("2nd initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now 1W 3C
$ssh->trace("==== 6 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user hihi");
$ssh->logger(undef, undef, 3, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
system("cp ./var/adm/messages temptemptemp");
system("mv temptemptemp ./var/adm/messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 3, 0, 2)); 

# now nothing
$ssh->trace("==== 7 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->loggercrap(undef, undef, 100);
system("cp ./var/adm/messages temptemptemp");
system("mv temptemptemp ./var/adm/messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now 1C
$ssh->trace("==== 8 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
system("cp ./var/adm/messages temptemptemp");
system("mv temptemptemp ./var/adm/messages");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));




