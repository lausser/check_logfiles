#!/usr/bin/perl -w
#
# ~/check_logfiles/test/001simple.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 4;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $configfile = <<EOCFG;
\$protocolsdir = "./var/tmp";
\$seekfilesdir = "./var/tmp";
\@searches = ({
      tag => "html",
      logfile => "./var/adm/messages",
      criticalpatterns => ["head.*body"],
});
EOCFG

open CCC, ">./etc/check_html.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({
        protocolsdir => "./var/tmp",
        seekfilesdir => "./var/tmp",
        searches => [
            {
              tag => "html",
              logfile => "./var/adm/messages",
              criticalpatterns => ["head.*body"],
            }
        ]    });
my $html = $cl->get_search_by_tag("html");


my $perlpath = `which perl`;
chomp $perlpath;
if ($^O =~ /MSWin/) {
 if (-f 'C:\strawberry\perl\bin\perl.exe') {
  $perlpath = 'C:\strawberry\perl\bin\perl';
 } else {
  $perlpath = 'C:\Perl\bin\perl';
 }
  $html->{logfile} =~ s/\//\\/g;
}

$cl->delete_file("./var/adm/messages");
$cl->delete_file("./var/tmp/check_html.._var_adm_messages.html");
$html->trace("deleted logfile and seekfile");
$html->logger(undef, undef, 1, "<head title=\"bled\">A&B</head><body title='bb'>");
my $command = sprintf $perlpath.' ../plugins-scripts/check_logfiles --config=etc/check_html.cfg ';
my $output = `$command`;
diag($output);
ok(($output =~ /OK - no errors or warnings/) && (($? >> 8) == 0));

# 1 critical
$html->trace(sprintf "+----------------------- test %d ------------------", 2);
$html->logger(undef, undef, 1, "<head title=\"bled\">A&B</head><body title='bb'>");
sleep 1;
$output = `$command`;
diag($output);
ok(($output =~ /<head title="bled">A&B<\/head><body title='bb'>/) && (($? >> 8) == 2));
sleep 1;
printf STDERR "now i add --htmlencode\n";
diag($command." --htmlencode");
$html->trace(sprintf "+----------------------- test %d ------------------", 2);
$html->logger(undef, undef, 1, "<head title=\"bled\">A&B</head><body title='bb'>");
sleep 1;

### zuletzt und command neu aufbauen ohne cfgfile nur options
$output = `$command --htmlencode`;
diag($output);
ok(($output =~ /<head title="bled">A&B<\/head><body title='bb'>/) && (($? >> 8) == 2));


printf STDERR "now i add options/htmlencode\n";
$configfile = <<EOCFG;
\$protocolsdir = "./var/tmp";
\$seekfilesdir = "./var/tmp";
\@searches = ({
      tag => "html",
      logfile => "./var/adm/messages",
      criticalpatterns => ["head.*body"],
});
\$options = "htmlencode";
EOCFG

open CCC, ">./etc/check_html.cfg";
print CCC $configfile;
close CCC;

# 1 critical
$html->trace(sprintf "+----------------------- test %d ------------------", 2);
$html->logger(undef, undef, 1, "<head title=\"bled\">A&B</head><body title='bb'>");
sleep 1;
diag($command);
$output = `$command`;
diag($output);
ok(($output =~ /&lthead title=&quotbled&quot&gtA&ampB&lt\/head&gt&ltbody title='bb'&gt/) && (($? >> 8) == 2));

