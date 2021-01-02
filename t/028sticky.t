#!/usr/bin/perl -w
#
# ~/check_logfiles/test/028sticky.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 39;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $now = time;
my $cl = Nagios::CheckLogfiles::Test->new({
	protocolsdir => TESTDIR."/var/tmp",
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "door",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => ["door open", "window open"],
	      warningpatterns => ["door unlocked", "window unlocked"],
	      okpatterns => ["door closed", "window closed"],
	      options => "sticky",
	    }
	]    });
my $door = $cl->get_search_by_tag("door");
$door->delete_logfile();
$door->delete_seekfile();
$door->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$door->trace(sprintf "+----------------------- test %d ------------------", 1);
$door->logger(undef, undef, 2, "Failed password for invalid user1...");
sleep 2;
$door->loggercrap(undef, undef, 100);
sleep 1;
$door->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 2 now find the two criticals
$door->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 2, "the door open");
$door->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# 3 no error messages but still critical (inherited the previous counters)
$door->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
$door->loggercrap(undef, undef, 100);
$door->logger(undef, undef, 2, "Failed password for invalid user3");
$door->loggercrap(undef, undef, 100);
$door->logger(undef, undef, 2, "Unknown user sepp");
$door->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
#printf "%s\n", Data::Dumper::Dumper($door->{newstate});
ok($cl->expect_result(0, 0, 2, 0, 2));

# 4 nothing happens but the error sticks like shit
$door->trace(sprintf "+----------------------- test %d ------------------", 4);
$cl->reset();
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
#printf "%s\n", Data::Dumper::Dumper($door->{newstate});
ok($cl->expect_result(0, 0, 2, 0, 2));

# 5 a new error appears
$door->trace(sprintf "+----------------------- test %d ------------------", 5);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window open");
$door->loggercrap(undef, undef, 10);
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 3, 0, 2));

# 6 one more time. still critical
$door->trace(sprintf "+----------------------- test %d ------------------", 6);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->loggercrap(undef, undef, 10);
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 3, 0, 2));

# 7 enough. send a remedy pattern
$door->trace(sprintf "+----------------------- test %d ------------------", 7);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 2, "door closed");
$door->loggercrap(undef, undef, 10);
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 8 really over?
$door->trace(sprintf "+----------------------- test %d ------------------", 8);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->loggercrap(undef, undef, 10);
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 9 stick again
$door->trace(sprintf "+----------------------- test %d ------------------", 9);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window open");
$door->loggercrap(undef, undef, 10);
$door->{maxstickytime} = 15;
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 15 left

# 10 still stick. 5 seconds pass.
$door->trace(sprintf "+----------------------- test %d ------------------", 10);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window broken");
$door->loggercrap(undef, undef, 10);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 10 left

# 11 still sticky. let 11 seconds pass.
$door->trace(sprintf "+----------------------- test %d ------------------", 11);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window broken");
$door->loggercrap(undef, undef, 10);
sleep 11;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 3 left

# 12 still sticky. let 5 seconds pass. now it expires
$door->trace(sprintf "+----------------------- test %d ------------------", 12);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window broken");
$door->loggercrap(undef, undef, 10);
sleep 5;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));


########### next test is the same, but one time a new error message prolongs the stickytime
# maxsticky still 15
# 13 enough. send a remedy pattern
$door->trace(sprintf "+----------------------- test %d ------------------", 13);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 2, "door closed");
$door->loggercrap(undef, undef, 10);
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 14 really over?
$door->trace(sprintf "+----------------------- test %d ------------------", 14);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->loggercrap(undef, undef, 10);
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 15 stick 
$door->trace(sprintf "+---------------------- test %d ------------------", 15);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window open");
$door->loggercrap(undef, undef, 10);
$door->{maxstickytime} = 15;
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # sticking starts. 15 seconds left.

# 16 still stick. 
$door->trace(sprintf "+----------------------- test %d ------------------", 16);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window broken");
$door->loggercrap(undef, undef, 10);
sleep 10;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 5 seconds left

# 17 prolong for another 15 secs
$door->trace(sprintf "+----------------------- test %d ------------------", 15);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window open");
$door->loggercrap(undef, undef, 10);
sleep 2; 
$cl->run(); # again 15 seconds
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2)); #the sticky + the new error

# 18 still sticky. let 5 seconds pass. 
$door->trace(sprintf "+----------------------- test %d ------------------", 18);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window broken");
$door->loggercrap(undef, undef, 10);
sleep 5;
$cl->run(); # still 10
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2)); #the sticky error

# 19 still sticky. let 12 seconds pass. now it expires
$door->trace(sprintf "+----------------------- test %d ------------------", 19);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window broken");
$door->loggercrap(undef, undef, 10);
sleep 12;
$cl->run(); 
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));













$cl = undef;
$door = undef;


#
##
#   repeat the stuff with maxstickytime, but this time initialize cl with sticky=15
#

$cl = Nagios::CheckLogfiles::Test->new({
	protocolsdir => TESTDIR."/var/tmp",
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "door",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => ["door open", "window open"],
	      warningpatterns => ["door unlocked", "window unlocked"],
	      okpatterns => ["door closed", "window closed"],
	      options => "sticky=15",
	    }
	]    });
my $x = @{$cl->{searches}}[0];
diag(sprintf "1 optsticky %d / maxsticky %d", $x->{options}->{sticky}, $x->{maxstickytime});
$door = $cl->get_search_by_tag("door");
diag(sprintf "2 optsticky %d / maxsticky %d", $door->{options}->{sticky}, $door->{maxstickytime});
$door->delete_logfile();
$door->delete_seekfile();
diag(sprintf "3 optsticky %d / maxsticky %d", $door->{options}->{sticky}, $door->{maxstickytime});
$door->trace("deleted logfile and seekfile");
diag(sprintf "MAXMAX %d" ,$door->{maxstickytime});
ok($door->{maxstickytime} == 15); # 20
ok($door->{options}->{sticky} == 1);


# 30 enough. send a remedy pattern
$door->trace(sprintf "+----------------------- test %d ------------------", 30);
$cl->reset();
diag("send remedy");
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 2, "door closed");
$door->loggercrap(undef, undef, 10);
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 31 really over?
$door->trace(sprintf "+----------------------- test %d ------------------", 31);
$cl->reset();
diag("send nothing");
$door->loggercrap(undef, undef, 10);
$door->loggercrap(undef, undef, 10);
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 32 stick again
$door->trace(sprintf "+----------------------- test %d ------------------", 32);
$cl->reset();
diag("send 1 warning");
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window open");
$door->loggercrap(undef, undef, 10);
sleep 2;
$now = time;
diag(sprintf "%d seconds from %d passed", time - $now, $door->{maxstickytime});
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 15 left

# 33 still stick. 5 seconds pass.
$door->trace(sprintf "+----------------------- test %d ------------------", 33);
$cl->reset();
diag("send 1 not relevant");
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window broken");
$door->loggercrap(undef, undef, 10);
diag(sprintf "it is %s", scalar localtime);
diag(sprintf "sleep until %s  (%d s)", scalar localtime ($now + 5), ($now + 5) - time);
sleep (($now + 5) - time);
diag(sprintf "%d seconds from %d passed", time - $now, $door->{maxstickytime});
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 10 left

# 34 still sticky. let 5 seconds pass.
$door->trace(sprintf "+----------------------- test %d ------------------", 34);
$cl->reset();
diag("send 1 not relevant");
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window broken");
$door->loggercrap(undef, undef, 10);
diag(sprintf "it is %s", scalar localtime);
diag(sprintf "sleep until %s  (%d s)", scalar localtime ($now + 10), ($now + 10) - time);
sleep (($now + 10) - time);
diag(sprintf "%d seconds from %d passed", time - $now, $door->{maxstickytime});
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 5 left

# 35 still sticky. let 5 seconds pass. now it expires
$door->trace(sprintf "+----------------------- test %d ------------------", 35);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window broken");
$door->loggercrap(undef, undef, 10);
diag(sprintf "it is %s", scalar localtime);
diag(sprintf "sleep until %s  (%d s)", scalar localtime ($now + 15), ($now + 15) - time);
sleep (($now + 15) - time + 1);
diag(sprintf "%d seconds from %d passed", time - $now, $door->{maxstickytime});
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 36 new sticky error
$door->trace(sprintf "+----------------------- test %d ------------------", 36);
$cl->reset();
diag("send 1 critical go");
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window open");
$door->loggercrap(undef, undef, 10);
sleep 2;
diag(sprintf "%d seconds from %d passed", time - $now, $door->{maxstickytime});
$cl->run();
diag(sprintf "sticky is %d", $door->{options}->{sticky});
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 15 left

# 37 relief 
$door->trace(sprintf "+----------------------- test %d ------------------", 37);
$cl->reset();
diag("send 3 relief");
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window closed");
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window closed");
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window closed");
$door->loggercrap(undef, undef, 10);
sleep 2;
diag(sprintf "%d seconds from %d passed", time - $now, $door->{maxstickytime});
$cl->run();
diag(sprintf "sticky is %d", $door->{options}->{sticky});
diag($cl->has_result());
diag($cl->{exitmessage});
ok($door->{options}->{sticky} == 4);
ok($cl->expect_result(0, 0, 0, 0, 0)); #







diag("test block 3");
#
# critical sticky
# then comes a warning
# and the result must still be sticky critical with the critical message

$cl = Nagios::CheckLogfiles::Test->new({
        protocolsdir => TESTDIR."/var/tmp",
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "door",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => ["door open", "window open"],
              warningpatterns => ["door unlocked", "window unlocked"],
              okpatterns => ["door closed", "window closed"],
              options => "sticky",
            }
        ]    });
$door = $cl->get_search_by_tag("door");
diag(sprintf "2 optsticky %d / maxsticky %d", $door->{options}->{sticky}, $door->{maxstickytime});
$door->delete_logfile();
$door->delete_seekfile();
diag(sprintf "3 optsticky %d / maxsticky %d", $door->{options}->{sticky}, $door->{maxstickytime});
$door->trace("deleted logfile and seekfile");
ok($door->{options}->{sticky} == 1);

#
# first initialize
#
$cl->reset();
$door->loggercrap(undef, undef, 10);
$cl->run();
diag(sprintf "sticky is %d", $door->{options}->{sticky});
diag($cl->has_result());
diag($cl->{exitmessage});
ok($door->{options}->{sticky} == 1);
ok($cl->expect_result(0, 0, 0, 0, 0)); #



#
# first a critical
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window open");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); #

#
# then an empty run
$cl->reset();
$door->loggercrap(undef, undef, 10);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); #

#
# now the warning
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window unlocked");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 1, 0, 2)); #

#
# then an empty run and we should see the 1 warning and 1 critical
$cl->reset();
$door->loggercrap(undef, undef, 10);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 1, 0, 2)); #

#
# another warning and another critical
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window unlocked");
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the window open");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2)); #

#
# then we should still see 2 warnings and 2 criticals
$cl->reset();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2)); #














