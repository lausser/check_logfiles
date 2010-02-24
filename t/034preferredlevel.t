#!/usr/bin/perl -w
#
# ~/check_logfiles/test/001simple.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 11;
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
	      criticalpatterns => ["Failed password", "user3"],
	      warningpatterns => '.*',
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
# and 2 warnings, because of the .*
$ssh->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
$ssh->logger(undef, undef, 2, "Failed password for invalid user2...");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));

# set the new preferredlevel option
$ssh->set_option('preferredlevel', 'critical');
#
# 3 now find the two criticals 
# do not match the warningpatterns, prefer critical
$ssh->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
$ssh->logger(undef, undef, 2, "Failed password for invalid user2");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# 4 now find the four criticals 
# do not match the warningpatterns, prefer critical
$ssh->trace(sprintf "+----------------------- test %d ------------------", 4);
$cl->reset();
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 4, 0, 2));

# set the new preferredlevel option
$ssh->set_option('preferredlevel', 'warning');
#
# 5 now find the two warnings
# do not match the (4) criticalpatterns, prefer warning
$ssh->trace(sprintf "+----------------------- test %d ------------------", 5);
$cl->reset();
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 0, 0, 1));

undef $cl;
undef $ssh;

$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => ["Failed password", "user3"],
              warningpatterns => '.*',
              options => 'preferredlevel=critical',
            }
        ]    });
$ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# 6 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->trace(sprintf "+----------------------- test %d ------------------", 6);
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

#
# 7 now find the two criticals
# do not match the warningpatterns, prefer critical
$ssh->trace(sprintf "+----------------------- test %d ------------------", 7);
$cl->reset();
$ssh->logger(undef, undef, 2, "Failed password for invalid user2");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

#
# 8 now find the two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 8);
$cl->reset();
$ssh->logger(undef, undef, 2, "schnorch! orch! ksorch!");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 0, 0, 1));

undef $cl;
undef $ssh;

$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => ["Failed password", "user3"],
              warningpatterns => '.*',
              options => 'preferredlevel=warning',
            }
        ]    });
$ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# 9 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->trace(sprintf "+----------------------- test %d ------------------", 9);
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

#
# 10 now find the two warnings
# do not match the (4) criticals
$ssh->trace(sprintf "+----------------------- test %d ------------------", 10);
$cl->reset();
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 0, 0, 1));

#
# 11 now find the two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 11);
$cl->reset();
$ssh->logger(undef, undef, 2, "schnorch! orch! ksorch!");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 0, 0, 1));


