#!/usr/bin/perl -w
#
# ~/check_logfiles/test/002exceptions.t
#
#  Simple warnings and criticals and their anullation with exceptions.
#

use strict;
use Test::More tests => 4;
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
	      criticalexceptions => "Failed password for invalid user (lausser|seppl)",
	      warningpatterns => ["Unknown user", "Failed password for invalid user seppl"],
	      warningexceptions => "Unknown user lausser"
	    }
	]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->logger(undef, undef, 2, "Failed password for invalid user user1...");
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find the four criticals and two warnings
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user user2");
$ssh->logger(undef, undef, 2, "Failed password for invalid user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Unknown user hiasl");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 4, 0, 2));

# now find the four criticals and one warnings
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user user2");
$ssh->logger(undef, undef, 2, "Failed password for invalid user sepp");
$ssh->logger(undef, undef, 2, "Failed password for invalid user lausser");
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user lausser");
$ssh->logger(undef, undef, 1, "Unknown user hiasl");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 4, 0, 2));

# now find the two criticals and three warnings
# user seppl will be critical, then revoked, then warning
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user user2");   #c
$ssh->logger(undef, undef, 2, "Failed password for invalid user seppl");   #c ex, w
$ssh->logger(undef, undef, 2, "Failed password for invalid user lausser"); #c ex
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user lausser");                     #w ex, w
$ssh->logger(undef, undef, 1, "Unknown user hiasl");                       #w
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 3, 2, 0, 2));
