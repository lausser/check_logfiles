#!/usr/bin/perl -w
#
# ~/check_logfiles/test/001simple.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 21;
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
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user"
	    }
	]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->trace(sprintf "+----------------------- test %d ------------------", 1);
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
$ssh->trace(sprintf "in 1: ctime %s",
    scalar localtime ((stat TESTDIR."/var/adm/messages")[10]));
$ssh->trace(sprintf "in 1: mtime %s",
    scalar localtime ((stat TESTDIR."/var/adm/messages")[9]));
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
$ssh->logger(undef, undef, 2, "Failed password for invalid user2...");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# 3 now find the two criticals and the two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));

# 4 nothing happened in the meantime
$ssh->trace(sprintf "+----------------------- test %d ------------------", 4);
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 5 the logfile was deleted and a new one has still not been created
$ssh->trace(sprintf "+----------------------- test %d ------------------", 5);
$ssh->delete_logfile();
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
diag(-f TESTDIR.'/var/adm/messages' ? "messages exists" : "messages missing");
ok($cl->expect_result(0, 0, 0, 1, 3));

# 6 now find the two criticals and the two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 6);
$cl->reset();
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));

# 7 the logfile was deleted and messages have been written
$ssh->trace(sprintf "+----------------------- test %d ------------------", 7);
$ssh->delete_logfile();
$cl->reset();
$ssh->loggercrap(undef, undef, 1);
$ssh->loggercrap(undef, undef, 1);
$ssh->logger(undef, undef, 2, "Failed password for invalid user5");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# 8 the logfile is not readable
$ssh->trace(sprintf "+----------------------- test %d ------------------", 8);
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user5");
$ssh->loggercrap(undef, undef, 100);
diag(sprintf "locking logfile %s", $ssh->{logfile});
$ssh->restrict_logfile();
diag(`/bin/ls -l $ssh->{logfile}`);
$ssh->restrict_logfile();
sleep 1;
$cl->run();
$ssh->unrestrict_logfile();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));

# 9 readable again now find the two + two criticals and the two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 9);
$cl->reset();
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 4, 0, 2));

# 10 the logfile was truncated and no messages have been written
$ssh->trace(sprintf "+----------------------- test %d ------------------", 10);
$ssh->truncate_logfile();
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 11 finally two criticals and two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 11);
$cl->reset();
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));

########################################################
# now with nologfilenocry
#
$cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
              options => "nologfilenocry"
	    }
	]    });
$ssh = $cl->get_search_by_tag("ssh");
$cl->reset();
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# 12 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->trace(sprintf "+----------------------- test %d ------------------", 12);
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
$ssh->trace(sprintf "in 1: ctime %s",
    scalar localtime ((stat TESTDIR."/var/adm/messages")[10]));
$ssh->trace(sprintf "in 1: mtime %s",
    scalar localtime ((stat TESTDIR."/var/adm/messages")[9]));
sleep 2;
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$ssh->trace("initial run");
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 13 now find the two criticals
$ssh->trace(sprintf "+----------------------- test %d ------------------", 13);
$cl->reset();
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2...");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# 14 now find the two criticals and the two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 14);
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));

# 15 nothing happened in the meantime
$ssh->trace(sprintf "+----------------------- test %d ------------------", 15);
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 16 the logfile was deleted and a new one has still not been created
$ssh->trace(sprintf "+----------------------- test %d ------------------", 16);
$ssh->delete_logfile();
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 17 now find the two criticals and the two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 17);
$cl->reset();
$ssh->logger(undef, undef, 1, "Failed password for invalid user14");
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 1, "Failed password for invalid user14");
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));

# 18 the logfile was deleted and messages have been written
$ssh->trace(sprintf "+----------------------- test %d ------------------", 18);
$ssh->delete_logfile();
$cl->reset();
$ssh->logger(undef, undef, 1, "Failed password for invalid user15");
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Failed password for invalid user15");
$ssh->loggercrap(undef, undef, 100);
$ssh->loggercrap(undef, undef, 100);
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# 19 new messages have been written
$ssh->trace(sprintf "+----------------------- test %d ------------------", 19);
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user16");
$ssh->loggercrap(undef, undef, 100);
$ssh->loggercrap(undef, undef, 100);
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2)); 

# 20 delete logfile and write beyond the length of the last logfile
# this is detected because of the new inode number. if the same number is used
# then the firstline-compare-code must be re-implemented
$ssh->trace(sprintf "+----------------------- test %d ------------------", 20);
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Failed password for invalid user17");
$ssh->loggercrap(undef, undef, 1000);
$ssh->loggercrap(undef, undef, 1000);
$ssh->loggercrap(undef, undef, 1000);
$ssh->loggercrap(undef, undef, 1000);
$ssh->loggercrap(undef, undef, 1000);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));


# 21 the logfile is not readable
$ssh->trace(sprintf "+----------------------- test %d ------------------", 21);
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user18");
$ssh->loggercrap(undef, undef, 100);
diag(sprintf "locking logfile %s", $ssh->{logfile});
$ssh->restrict_logfile();
diag(`/bin/ls -l $ssh->{logfile}`);
sleep 1;
$cl->run();
$ssh->unrestrict_logfile();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));

$ssh->delete_logfile();
$ssh->delete_seekfile();

