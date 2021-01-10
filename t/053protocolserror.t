#!/usr/bin/perl -w
#
# ~/check_logfiles/test/053pathswithblanks.t
#
#  Test the capability of finding files, scripts etc with blanks in the pathname
#

use strict;
use Test::More tests => 10;
use Cwd 'abs_path';
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use File::Path;
use constant TESTDIR => ".";

rmtree TESTDIR."/prots";
mkdir TESTDIR."/prots";
diag("tick");
my $cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => TESTDIR."/var/tmp",
	#protocolsdir => TESTDIR."/mich/gibt/es/nicht",
	protocolsdir => TESTDIR."/prots",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      rotation => "loglog0log1",
	    }
	]    });
diag("tick");
#printf "%s\n", Data::Dumper::Dumper($cl);
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
diag("tick");

# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->logger(undef, undef, 2, "Failed password for invalid user1");
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));
diag("tick");

# now find the two criticals
$ssh->trace("==== 2 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

my @prots = glob(TESTDIR."/prots/check_logfiles.protocol*");
ok(scalar(@prots) == 1);

$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => TESTDIR."/var/tmp",
        #protocolsdir => TESTDIR."/mich/gibt/es/nicht",
        protocolsdir => TESTDIR."/prots",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user",
              rotation => "loglog0log1",
              options => "noprotocol",
            }
        ]    });
mkdir TESTDIR."/prots";
#printf "%s\n", Data::Dumper::Dumper($cl);
$ssh = $cl->get_search_by_tag("ssh");
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

# now find the two criticals
$ssh->trace("==== 2 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
sleep 2;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

@prots = glob(TESTDIR."/prots/check_logfiles.protocol*");
ok(scalar(@prots) == 1);


rmtree TESTDIR."/prots";
$cl = Nagios::CheckLogfiles::Test->new({
        options => "protocolfileerror=unknown",
        seekfilesdir => TESTDIR."/var/tmp",
        #protocolsdir => TESTDIR."/mich/gibt/es/nicht",
        protocolsdir => TESTDIR."/prots",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user",
              rotation => "loglog0log1",
            }
        ]    });
####################mkdir TESTDIR."/prots";
diag("tick");
#printf "%s\n", Data::Dumper::Dumper($cl);
$ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
diag("tick");

# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->logger(undef, undef, 2, "Failed password for invalid user1");
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 1, 3));
diag("tick");

# now find the two criticals
$ssh->trace("==== 2 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
diag(Data::Dumper::Dumper($ssh->{matchlines}));
diag(Data::Dumper::Dumper($ssh->{lastmsg}));
ok($cl->expect_result(0, 0, 2, 1, 2));
ok($ssh->{matchlines}->{UNKNOWN}->[0]->[1] =~ /cannot write protocol file/);

@prots = glob(TESTDIR."/prots/check_logfiles.protocol*");
ok(scalar(@prots) == 0);

