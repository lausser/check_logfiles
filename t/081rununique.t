#!/usr/bin/perl -w
#
# ~/check_logfiles/test/050perms.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 5;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $configfile = <<EOCFG;
\$options = "rununique";
\$protocolsdir = "./var/tmp";
\$seekfilesdir = "./var/tmp";
\@searches = (
    {
      tag => "unique",
      logfile => "./var/adm/messages",
      criticalpatterns => [
          'blabla',
      ],
});

EOCFG
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_action.cfg" });
my $pidfile = $cl->construct_pidfile();
diag($pidfile);

my $perlpath = `which perl`;
chomp $perlpath;
if ($^O =~ /MSWin/) {
 if (-f 'C:\strawberry\perl\bin\perl.exe') {
  $perlpath = 'C:\strawberry\perl\bin\perl';
 } else {
  $perlpath = 'C:\Perl\bin\perl';
 }
}
my $command = $perlpath.' ../plugins-scripts/check_logfiles --config ./etc/check_action.cfg --rununique';
if ($^O =~ /MSWin/) {
 $command =~ s/\//\\/g;
}
my $output = `$command`;
diag($command);
diag($output);
ok(($output =~ /OK - no errors or warnings/) && (($? >> 8) == 0));

open PID, ">$pidfile";
close PID;
ok(-e $pidfile, "pidfile exists");
$output = `$command`;
diag($output);
ok(($output =~ /Exiting because another check is already running/), "aborts correctly");
ok(($output =~ /Exiting because another check is already running/) && (($? >> 8) == 3));

unlink $pidfile;
$output = `$command`;
diag($output);
ok(($output =~ /OK - no errors or warnings/) && (($? >> 8) == 0));

