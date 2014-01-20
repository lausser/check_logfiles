#!/usr/bin/perl -w
#
# ~/check_logfiles/test/011searches.t
#
#  Test logfiles which will be deleted and recreated instead of rotated.
#

use strict;
use Test::More tests => 10;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $configfile =<<EOCFG;
        \$seekfilesdir = "./var/tmp";
        \@searches = (
            {
              tag => "ssh",
              logfile => "./var/adm/messages",
              criticalpatterns => "Failed password for invalid user8",
              warningpatterns => "Unknown user",
              options => "perfdata,nologfilenocry"
            },
            {
              tag => "test",
              logfile => "./var/adm/messages",
              criticalpatterns => "Failed password for invalid user9",
              warningpatterns => "Unknown user",
              options => "noperfdata,nologfilenocry"
            },
            {
              tag => "null",
              logfile => "./var/adm/messages",
              criticalpatterns => ".*nonsense.*",
              warningpatterns => "crap",
              options => "perfdata,nologfilenocry"
            },
            {
              tag => "doppelnull",
              logfile => "./var/adm/messages",
              criticalpatterns => ".*nonsense.*",
              warningpatterns => "crap",
              options => "perfdata,nologfilenocry"
            },
  );
EOCFG

open CCC, ">./etc/searches.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/searches.cfg", selectedsearches => ['ssh', 'null'] });

ok(scalar @{$cl->{searches}} == 2);
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
#my $test = $cl->get_search_by_tag("test");
#$test->delete_logfile();
#$test->delete_seekfile();
#$test->trace("deleted logfile and seekfile");
my $null = $cl->get_search_by_tag("null");
$null->delete_logfile();
$null->delete_seekfile();
$null->trace("deleted logfile and seekfile");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$ssh->trace("==== 3-4 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 2);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 2);
# ssh logs instead of test
$ssh->loggercrap(undef, undef, 2);
$ssh->logger(undef, undef, 2, "Failed password for invalid user9");
$ssh->loggercrap(undef, undef, 2);
$null->loggercrap(undef, undef, 2);
$null->logger(undef, undef, 2, "Failed password is nonsense");
$null->loggercrap(undef, undef, 2);
printf "calling run for 3, 4\n";
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 4, 0, 2));
ok($cl->{exitmessage} =~ /CRITICAL - \(4 errors\) - .* Failed password is nonsense /);

$ssh->trace("==== 5 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 20);
$ssh->logger(undef, undef, 3, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 20);
# ssh logs instead of test
$ssh->loggercrap(undef, undef, 20);
$ssh->logger(undef, undef, 200, "Failed password for invalid user9");
$ssh->loggercrap(undef, undef, 20);
$null->loggercrap(undef, undef, 20);
$null->logger(undef, undef, 4, "Failed password is nonsense");
$null->loggercrap(undef, undef, 20);

my $command = sprintf 'perl ../plugins-scripts/check_logfiles -f ./etc/searches.cfg --searches=ssh,null';

$ssh->trace("executing %s", $command);
my $output = `$command`;
diag($output);
diag($? >> 8);
ok(($? >> 8) == 2);
ok($output =~ /CRITICAL - \(7 errors .* Failed password is nonsense /);

diag("only searches with .*null.*");
$command = sprintf 'perl ../plugins-scripts/check_logfiles -f ./etc/searches.cfg --searches=\'.*null.*\'';

diag(sprintf "executing %s", $command);
$ssh->trace("executing %s", $command);
$output = `$command`;
diag($output);
diag($? >> 8);
#ok(($? >> 8) == 2);
ok($output =~ / null_warnings=/);
ok($output =~ / doppelnull_warnings=/);

diag("only searches with null");
# doppelnull wird nicht ausgefuehrt, da 'null' keine * und ? enthaelt und daher
# nicht als regexp zaehlt
$command = sprintf 'perl ../plugins-scripts/check_logfiles -f ./etc/searches.cfg --searches=\'null\'';

diag(sprintf "executing %s", $command);
$ssh->trace("executing %s", $command);
$output = `$command`;
diag($output);
diag($? >> 8);
#ok(($? >> 8) == 2);
ok($output =~ / null_warnings=/);
ok($output !~ / doppelnull_warnings=/);



