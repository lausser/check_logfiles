#!/usr/bin/perl -w
#
# ~/check_logfiles/test/086macroinglobals.t
#
#  Test replacements of macros in seekfilesdir
#
use strict;
use Test::More tests => 3;
use Cwd;
use File::Path;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $protocolsdir = ($^O =~/MSWin/) ? 'C:\TEMP\$MACAMACA$' : '/tmp/$MACAMACA$';
my $seekfilesdir = ($^O =~/MSWin/) ? 'C:\TEMP\$MACAMACA$' : '/tmp/$MACAMACA$';
my $resolved_seekfilesdir = $seekfilesdir;
$resolved_seekfilesdir =~ s/\$MACAMACA\$/gsuhjch/;

my $configfile = <<EOCFG;
\$protocolsdir = \'$protocolsdir\';
\$seekfilesdir = \'$seekfilesdir\';
\@searches = ({
      tag => "ssh",
      logfile => "./var/adm/messages",
      criticalpatterns => "Failed password",
      warningpatterns => "Unknown user",
      rotation => "SOLARIS",
});
EOCFG

open CCC, ">./etc/check_macroseek.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({
        protocolsdir => $seekfilesdir,
        seekfilesdir => $seekfilesdir,
        searches => [
            {
              tag => "ssh",
              logfile => "./var/adm/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user"
            }
        ]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
File::Path::rmtree($resolved_seekfilesdir);
ok(! -d $resolved_seekfilesdir);


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
my $command = $perlpath.' ../plugins-scripts/check_logfiles --config ./etc/check_macroseek.cfg --macro MACAMACA=gsuhjch';
 
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
diag($seekfilesdir);
diag($resolved_seekfilesdir);
ok(($output =~ /OK - no errors or warnings/) && (($? >> 8) == 0));

ok(-d $resolved_seekfilesdir);
File::Path::rmtree($resolved_seekfilesdir);
