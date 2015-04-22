#!/usr/bin/perl -w
#
# ~/check_logfiles/test/005negative.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 1;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $configfile = <<EOCFG;
\$seekfilesdir = "./var/tmp";
\$scriptpath = "./bin";
\@searches = (
    {
      tag => "action",
      logfile => "./var/adm/messages",
      criticalpatterns => [ 
             '.*ERROR.*',
         ], 
         options => 'script',
         script => "send_snmptrap"
    },
    {
      tag => "action2",
      logfile => "./var/adm/messages",
      criticalpatterns => [ 
             '.*ERROR.*',
         ], 
         options => 'script',
         script => "send_snmptrap"
    },
);
EOCFG
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_action.cfg" });
my $action = $cl->get_search_by_tag("action");
my $action2 = $cl->get_search_by_tag("action2");
$cl->reset();
$action->{script} = sub {
  sleep 5;
  return 3;
};
$action2->{script} = sub {
  sleep 1;
  return 3;
};
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 10, " ERROR ");
$action->loggercrap(undef, undef, 100);
sleep 1;
$cl->{timeout} = 10;
my $now = time;
$cl->run();
my $elapsed = time - $now;
diag(sprintf "aborted after %d seconds", $elapsed);
ok($elapsed > 16 && $elapsed < 20);
