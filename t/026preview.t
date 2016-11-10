#!/usr/bin/perl -w
#
# ~/check_logfiles/test/026preview.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 1;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $cl = Nagios::CheckLogfiles::Test->new({
        options => "preview=5",
	protocolsdir => TESTDIR."/var/tmp",
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages1",
	      criticalpatterns => ["_CRIT_" ],
	      warningpatterns => "_WARN_",
	      options => "noprotocol"
	    },
	    {
	      tag => "nop",
	      logfile => TESTDIR."/var/adm/messages2",
	      criticalpatterns => ["_CRIT_" ],
	      warningpatterns => "_WARN_",
	      options => "noprotocol"
	    }
	]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
$ssh->loggercrap(undef, undef, 100);

my $nop = $cl->get_search_by_tag("nop");
$nop->delete_logfile();
$nop->delete_seekfile();
$nop->trace("deleted logfile and seekfile");
$nop->loggercrap(undef, undef, 100);

$nop->trace("initial run");
$cl->run();

$ssh->trace(sprintf "+----------------------- test %d ------------------", 1);
$ssh->logger(undef, undef, 1, "_CRIT_err1", 1);
$ssh->logger(undef, undef, 1, "_CRIT_err2", 1);
$ssh->logger(undef, undef, 1, "_CRIT_err3", 1);
$ssh->logger(undef, undef, 1, "_CRIT_err4", 1);
$ssh->logger(undef, undef, 1, "_CRIT_err5", 1);
$ssh->logger(undef, undef, 1, "_CRIT_err6", 1);
sleep 2;
$ssh->loggercrap(undef, undef, 100);
$nop->trace(sprintf "+----------------------- test %d ------------------", 1);
$nop->logger(undef, undef, 1, "_CRIT_Err1", 1);
$nop->logger(undef, undef, 1, "_CRIT_Err2", 1);
$nop->logger(undef, undef, 1, "_CRIT_Err3", 1);
$nop->logger(undef, undef, 1, "_WARN_War1", 1);
$nop->logger(undef, undef, 1, "_WARN_War2", 1);
sleep 2;
$nop->loggercrap(undef, undef, 100);
sleep 1;

$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 9, 0, 2));
ok($cl->{exitmessage} eq "CRITICAL - (9 errors, 2 warnings) - _CRIT_Err3, _CRIT_Err2, _CRIT_Err1, _CRIT_err6, _CRIT_err5 ");

$nop->logger(undef, undef, 1, "_ZOIGS_", 1);
$cl->reset();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->trace(sprintf "+----------------------- test %d ------------------", 1);
$ssh->logger(undef, undef, 1, "_CRIT_err1", 1);
$ssh->logger(undef, undef, 1, "_CRIT_err2", 1);
$ssh->logger(undef, undef, 1, "_CRIT_err3", 1);
$ssh->logger(undef, undef, 1, "_CRIT_err4", 1);
$ssh->logger(undef, undef, 1, "_CRIT_err5", 1);
$ssh->logger(undef, undef, 1, "_CRIT_err6", 1);
sleep 2;
$ssh->loggercrap(undef, undef, 100);
$nop->trace(sprintf "+----------------------- test %d ------------------", 1);
$nop->logger(undef, undef, 1, "_CRIT_Err1", 1);
$nop->logger(undef, undef, 1, "_CRIT_Err2", 1);
$nop->logger(undef, undef, 1, "_CRIT_Err3", 1);
$nop->logger(undef, undef, 1, "_WARN_War1", 1);
$nop->logger(undef, undef, 1, "_WARN_War2", 1);
sleep 2;
$nop->loggercrap(undef, undef, 100);
sleep 1;

$ssh->trace("only 4");
$cl->set_option("preview", 4);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 9, 0, 2));
ok($cl->{exitmessage} eq "CRITICAL - (9 errors, 2 warnings) - _CRIT_Err3, _CRIT_Err2, _CRIT_Err1, _CRIT_err6 ");




