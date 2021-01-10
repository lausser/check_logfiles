#!/usr/bin/perl -w
#

use strict;
use Test::More tests => 5;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


########################################################
# now with nologfilenocry
#
my $cl = Nagios::CheckLogfiles::Test->new({
	protocolsdir => TESTDIR."/var/tmp",
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
              options => "nologfilenocry,sticky=4,allyoucaneat"
	    }
	]    });
my $ssh = $cl->get_search_by_tag("ssh");
$cl->reset();
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

$ssh->logger(undef, undef, 2, "bla");

$cl->trace("now run 1");
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->logger(undef, undef, 2, "Failed password");

$cl->trace("now run 2");
$cl->reset();
$cl->run();
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));
diag($ssh->{seekfile});

$cl->trace("now run 3");
diag("now run 3");
$cl->reset();
$cl->run();
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

$ssh->logger(undef, undef, 2, "bla");
sleep 5;
$ssh->trace("should be unsticked now");
$cl->reset();
$cl->run();
ok($cl->expect_result(0, 0, 0, 0, 0));

delete $ssh->{newstate}->{logtime};
$ssh->delete_logfile();

$cl->reset();
$cl->run();
printf STDERR "%s\n", Data::Dumper::Dumper($ssh->{newstate});
diag(`/bin/ls -li $ssh->{logfile}`);
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

