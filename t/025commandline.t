#!/usr/bin/perl -w
#
# ~/check_logfiles/test/025commandline.t
#
#  Test the capability of finding rotated logfiles with the commandline.
#

#
# problem: the test script is ran under cygwin, but the check_logfiles is
# a native active state perl script.
# once /tmp, then TEMP is used as seekfilesdir, so the seekfiles are 
# not deleted properly
#
use strict;
use Test::More tests => 5;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => ($^O =~/MSWin/) ? 'C:\TEMP' : '/tmp',
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user",
              rotation => "SOLARIS",
            }
        ]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->trace("starting.............%s", $cl->{seekfilesdir});
my $perlpath = `which perl`;
chomp $perlpath;
if ($^O =~ /MSWin/) {
 if (-f 'C:\strawberry\perl\bin\perl.exe') {
  $perlpath = 'C:\strawberry\perl\bin\perl';
 } else {
  $perlpath = 'C:\Perl\bin\perl';
 }
  $ssh->{logfile} =~ s/\//\\/g;
}
my $command = sprintf $perlpath.' ../plugins-scripts/check_logfiles --tag=%s --criticalpattern="%s" --warningpattern="%s" --rotation=%s --logfile=%s --seekfilesdir %s',
    $ssh->{tag}, $ssh->{patterns}->{CRITICAL}->[0], 
    $ssh->{patterns}->{WARNING}->[0],
    $ssh->{rotation}, $ssh->{logfile}, $cl->{seekfilesdir};
 
$ssh->trace("executing %s", $command);
$ssh->trace("deleting logfile and seekfile");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
 
# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->trace("==== 1 ====");
$ssh->logger(undef, undef, 2, "Failed password for invalid user1");
my $output = `$command`;
diag($output);
ok(($output =~ /OK - no errors or warnings/) && (($? >> 8) == 0));

# now find the two criticals
$ssh->trace("==== 2 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
$output = `$command`;
diag($output);
ok(($output =~ /CRITICAL - \(2 errors in/) && (($? >> 8) == 2));

# now find the two criticals without a protocol
$ssh->trace("==== 3 ====");
$cl->reset();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$output = `$command --noprotocol`;
diag($output);
ok(($output =~ /CRITICAL - \(2 errors\)/) && (($? >> 8) == 2));

 
# now rotate and find the two new criticals
$ssh->trace("==== 4 ====");
$ssh->rotate();
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh->loggercrap(undef, undef, 100);
$output = `$command`;
diag($output);
ok(($output =~ /CRITICAL - \(2 errors in/) && (($? >> 8) == 2));

# now rotate and find the two new criticals but without perfdata
$ssh->trace("==== 5 ====");
$ssh->rotate();
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user5");
$ssh->loggercrap(undef, undef, 100);
$output = `$command --noperfdata`;
diag($output);
ok(($output =~ /CRITICAL - \(2 errors in.*\.\.\./) && (($? >> 8) == 2));
$ssh->delete_logfile();
$ssh->delete_seekfile();
