#!/usr/bin/perl -w
#
# ~/check_logfiles/test/002cryornot.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 16;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $cl = Nagios::CheckLogfiles::Test->new({
        options => "perfdata",
        protocolsdir => TESTDIR."/var/tmp",
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user",
              options => "perfdata"
            }
        ]    });
my $ssh = $cl->get_search_by_tag("ssh");
$cl->reset();
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# init
$ssh->trace("initial run");
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find an error
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now the logfile disappeared, resulting in UNKNOWN
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
$ssh->delete_logfile();
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 0, 1, 3));


$cl = Nagios::CheckLogfiles::Test->new({
        options => "perfdata",
	protocolsdir => TESTDIR."/var/tmp",
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
              options => "nologfilenocry,perfdata"
	    }
	]    });
$ssh = $cl->get_search_by_tag("ssh");
$cl->reset();
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# init
$ssh->trace("initial run");
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find an error
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now the logfile disappeared but we don't care
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
$ssh->delete_logfile();
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 0, 0, 0));

$cl = Nagios::CheckLogfiles::Test->new({
        options => "perfdata",
	protocolsdir => TESTDIR."/var/tmp",
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
              options => "logfilemissing=warning,perfdata"
	    }
	]    });
$ssh = $cl->get_search_by_tag("ssh");
$cl->reset();
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# init
$ssh->trace("initial run");
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find an error
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now the logfile disappeared and we do care.
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
$ssh->delete_logfile();
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 1, 0, 0, 1));

$cl = Nagios::CheckLogfiles::Test->new({
        options => "perfdata",
        protocolsdir => TESTDIR."/var/tmp",
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user",
              options => "logfilemissing=critical,perfdata"
            }
        ]    });
$ssh = $cl->get_search_by_tag("ssh");
$cl->reset();
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# init
$ssh->trace("initial run");
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find an error
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now the logfile disappeared and we do care.
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
$ssh->delete_logfile();
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 1, 0, 2));

$cl = Nagios::CheckLogfiles::Test->new({
        options => "perfdata",
        protocolsdir => TESTDIR."/var/tmp",
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user",
              options => "logfilemissing=ok,perfdata"
            }
        ]    });
$ssh = $cl->get_search_by_tag("ssh");
$cl->reset();
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# init
$ssh->trace("initial run");
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find an error
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now the logfile disappeared and we do care.
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
$ssh->delete_logfile();
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(1, 0, 0, 0, 0));

# now find another error
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
#$ssh->loggercrap(undef, undef, 100);
diag(`/bin/ls -li $ssh->{logfile}`);
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{perfdata});
ok($cl->expect_result(0, 0, 2, 0, 2));

