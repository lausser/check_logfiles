#!/usr/bin/perl -w
#
# ~/check_logfiles/test/004rotation.t
#
#  Test the capability of finding rotated logfiles with similar names
#

use strict;
use Test::More tests => 6;
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
	      warningpatterns => "Unknown user",
	      rotation => "loglog0log1",
	    },
	    {
	      tag => "ssh2",
	      logfile => TESTDIR."/var/adm/messages-with-some-text",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      rotation => "loglog0log1",
	    },
	    {
	      tag => "ssh3",
	      logfile => TESTDIR."/var/adm/moremessages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      rotation => "loglog0log1",
	    },
	    {
	      tag => "ssh4",
	      logfile => TESTDIR."/var/adm/more-messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      rotation => "loglog0log1",
	    }
	]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
my $ssh2 = $cl->get_search_by_tag("ssh2");
$ssh2->delete_logfile();
$ssh2->delete_seekfile();
$ssh2->trace("deleted logfile and seekfile");
my $ssh3 = $cl->get_search_by_tag("ssh3");
$ssh3->delete_logfile();
$ssh3->delete_seekfile();
$ssh3->trace("deleted logfile and seekfile");
my $ssh4 = $cl->get_search_by_tag("ssh4");
$ssh4->delete_logfile();
$ssh4->delete_seekfile();
$ssh4->trace("deleted logfile and seekfile");

# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->logger(undef, undef, 2, "Failed password for invalid user1");
$ssh2->logger(undef, undef, 2, "Failed password for invalid user1");
$ssh3->logger(undef, undef, 2, "Failed password for invalid user1");
$ssh4->logger(undef, undef, 2, "Failed password for invalid user1");
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find the two criticals
$ssh->trace("==== 2 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
$ssh2->loggercrap(undef, undef, 100);
$ssh2->logger(undef, undef, 2, "Failed password for invalid user2");
$ssh2->loggercrap(undef, undef, 100);
$ssh3->loggercrap(undef, undef, 100);
$ssh3->logger(undef, undef, 2, "Failed password for invalid user2");
$ssh3->loggercrap(undef, undef, 100);
$ssh4->loggercrap(undef, undef, 100);
$ssh4->logger(undef, undef, 2, "Failed password for invalid user2");
$ssh4->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 8, 0, 2));

# now rotate and find the two new criticals
$ssh->trace("==== 3 ====");
$ssh->rotate();
$ssh2->rotate();
$ssh3->rotate();
$ssh4->rotate();
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh->loggercrap(undef, undef, 100);
$ssh2->loggercrap(undef, undef, 100);
$ssh2->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh2->loggercrap(undef, undef, 100);
$ssh3->loggercrap(undef, undef, 100);
$ssh3->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh3->loggercrap(undef, undef, 100);
$ssh4->loggercrap(undef, undef, 100);
$ssh4->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh4->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 8, 0, 2));

# now rotate and create no new logfile
$ssh->trace("==== 4 ====");
$ssh->rotate();
$ssh2->rotate();
$ssh3->rotate();
$ssh4->rotate();
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 4, 3));

# now write messages and find them
$ssh->trace("==== 5 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh->loggercrap(undef, undef, 100);
$ssh2->loggercrap(undef, undef, 100);
$ssh2->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh2->loggercrap(undef, undef, 100);
$ssh3->loggercrap(undef, undef, 100);
$ssh3->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh3->loggercrap(undef, undef, 100);
$ssh4->loggercrap(undef, undef, 100);
$ssh4->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh4->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 8, 0, 2));

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
$ssh2->loggercrap(undef, undef, 100);
$ssh2->logger(undef, undef, 2, "Failed password for invalid user5");
$ssh2->loggercrap(undef, undef, 100);
$ssh3->loggercrap(undef, undef, 100);
$ssh3->logger(undef, undef, 2, "Failed password for invalid user5");
$ssh3->loggercrap(undef, undef, 100);
$ssh4->loggercrap(undef, undef, 100);
$ssh4->logger(undef, undef, 2, "Failed password for invalid user5");
$ssh4->loggercrap(undef, undef, 100);
$ssh->rotate();
$ssh2->rotate();
$ssh3->rotate();
$ssh4->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh2->loggercrap(undef, undef, 100);
$ssh3->loggercrap(undef, undef, 100);
$ssh4->loggercrap(undef, undef, 100);
$ssh->rotate();
$ssh2->rotate();
$ssh3->rotate();
$ssh4->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh2->loggercrap(undef, undef, 100);
$ssh2->logger(undef, undef, 1, "Unknown user sepp");
$ssh2->loggercrap(undef, undef, 100);
$ssh3->loggercrap(undef, undef, 100);
$ssh3->logger(undef, undef, 1, "Unknown user sepp");
$ssh3->loggercrap(undef, undef, 100);
$ssh4->loggercrap(undef, undef, 100);
$ssh4->logger(undef, undef, 1, "Unknown user sepp");
$ssh4->loggercrap(undef, undef, 100);
$ssh->rotate();
$ssh2->rotate();
$ssh3->rotate();
$ssh4->rotate();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 4, 8, 4, 2));

