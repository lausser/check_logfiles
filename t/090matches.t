#!/usr/bin/perl -w
#
# ~/check_logfiles/test/016smartaction.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 2;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $configfile = <<EOCFG;
\$protocolsdir = "./var/tmp";
\$seekfilesdir = "./var/tmp";
\$options = "smartprescript,smartpostscript";
\@searches = (
    {
      tag => "smart",
      logfile => "./var/adm/messages",
      criticalpatterns => [
          'bla ((pat1) blub (pat2.*)) bla',
      ],
      options => 'smartscript,capturegroups,noprotocol',
      script => "script.sh"
});

EOCFG
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_action.cfg" });
my $action = $cl->get_search_by_tag("smart");
$action->{script} = sub {
    my $num = $ENV{CHECK_LOGFILES_CAPTURE_GROUPS};
    printf "%d:pat1(%s)pat2(%s)pat3(%s)", 
        $ENV{CHECK_LOGFILES_CAPTURE_GROUPS},
        $ENV{CHECK_LOGFILES_CAPTURE_GROUP1},
        $ENV{CHECK_LOGFILES_CAPTURE_GROUP2},
        $ENV{CHECK_LOGFILES_CAPTURE_GROUP3};
    return 2;
};
$action->{options}->{supersmartscript} = 1;
$action->{options}->{smartscript} = 1;
$action->{options}->{script} = 1;
$cl->run(); #init
$cl->reset();
$cl->run();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "bla pat1 blub pat2kaas bla");
$action->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
#$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});

ok($cl->{exitmessage} eq "CRITICAL - (1 errors) - 3:pat1(pat1 blub pat2kaas)pat2(pat1)pat3(pat2kaas) ");
ok($cl->expect_result(0, 0, 1, 0, 2));

