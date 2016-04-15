#!/usr/bin/perl -w
#
# ~/check_logfiles/test/036cl_warning.t
#
#  [check_logfiles] Some macros still broken in v3.7.1.1 (#7)
#

use strict;
use Test::More tests => 3;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $configfile = <<EOCFG;
\$protocolsdir = "./var/tmp";
\$seekfilesdir = "./var/tmp";
\@searches = ({
        tag                 => 'some_tag',
        logfile             => 'some_log',
        criticalpatterns    => [
            'some_string',
        ],
        options             => 'supersmartscript',
        script => sub {
              foreach my \$key (sort(keys \%ENV)) {
                    next unless \$key =~ /^CHECK/;
                     printf "%s=%s\n", \$key, \$ENV{\$key};
            }
            return 2;
        }
});
EOCFG

open CCC, ">./etc/check_warn.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_warn.cfg" });

my $some = $cl->get_search_by_tag("some_tag");


my $perlpath = `which perl`;
chomp $perlpath;
if ($^O =~ /MSWin/) {
 if (-f 'C:\strawberry\perl\bin\perl.exe') {
  $perlpath = 'C:\strawberry\perl\bin\perl';
 } else {
  $perlpath = 'C:\Perl\bin\perl';
 }
  $some->{logfile} =~ s/\//\\/g;
}

$some->delete_logfile();
$some->delete_seekfile();
$some->trace("deleted logfile and seekfile");
$some->loggercrap(undef, undef, 100);
my $command = sprintf $perlpath.' ../plugins-scripts/check_logfiles --config=etc/check_warn.cfg --warning 100 ';
my $output = `$command`;
diag($output);
ok(($output =~ /OK - no errors or warnings/) && (($? >> 8) == 0));

$some->logger(undef, undef, 1, "this is some_string");
$output = `$command`;
diag($output);
ok(($output =~ /CRITICAL - \(1 errors/) && (($? >> 8) == 2));
ok($output =~ /CHECK_LOGFILES_WARNING=100/);

