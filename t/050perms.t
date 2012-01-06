#!/usr/bin/perl -w
#
# ~/check_logfiles/test/050perms.t
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
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$ssh->restrict_logfile();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));
ok(-e $ssh->{logfile}, "logfile exists");
ok(-f $ssh->{logfile}, "logfile is a file");
ok($^O =~/MSWin/ ? -r $ssh->{logfile} : ! -r $ssh->{logfile}, "logfile is readable");
ok(! $ssh->getfileisreadable($ssh->{logfile}), "logfile is unreadable");
my $fh = new IO::File;
ok(($^O eq "cygwin" ? 1 : ! $fh->open($ssh->{logfile}, "r")), "can be opened");
$ssh->unrestrict_logfile();
$ssh->delete_logfile();


diag("now be less strict. no permission = warning only");
$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user",
              options => "logfileerror=warning",
            }
        ]    });
$ssh = $cl->get_search_by_tag("ssh");
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
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$ssh->restrict_logfile();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 0, 0, 1));
printf "%s\n", Data::Dumper::Dumper($cl->{options});
printf "%s\n", Data::Dumper::Dumper($ssh->{options});
ok(-e $ssh->{logfile}, "logfile exists");
ok(-f $ssh->{logfile}, "logfile is a file");
ok($^O =~/MSWin/ ? -r $ssh->{logfile} : ! -r $ssh->{logfile}, "logfile is readable");
ok(! $ssh->getfileisreadable($ssh->{logfile}), "logfile is unreadable");
$fh = new IO::File;
ok(($^O eq "cygwin" ? 1 : ! $fh->open($ssh->{logfile}, "r")), "can be opened");
$ssh->unrestrict_logfile();
$ssh->delete_logfile();


diag("now be less strict. no permission = warning only");
diag("and we use logfileerror global, which is the preferred way");
$cl = Nagios::CheckLogfiles::Test->new({
        options => "logfileerror=warning",
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user",
            }
        ]    });
$ssh = $cl->get_search_by_tag("ssh");
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
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$ssh->restrict_logfile();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 0, 0, 1));
ok(-e $ssh->{logfile}, "logfile exists");
ok(-f $ssh->{logfile}, "logfile is a file");
ok($^O =~/MSWin/ ? -r $ssh->{logfile} : ! -r $ssh->{logfile}, "logfile is readable");
ok(! $ssh->getfileisreadable($ssh->{logfile}), "logfile is unreadable");
$fh = new IO::File;
ok(($^O eq "cygwin" ? 1 : ! $fh->open($ssh->{logfile}, "r")), "can be opened");
$ssh->unrestrict_logfile();
$ssh->delete_logfile();


