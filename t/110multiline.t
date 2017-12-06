#!/usr/bin/perl -w
#
#  110multiline.t
#
#  Test multiline parsing
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

\@searches = (
  {
    tag => 'multiline',
    options => 'allyoucaneat',
    multiline   => 1,
    multilinestartpattern => '\\d{4}\\-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} \\- ',
    logfile => './data/multiline.log',
    criticalpatterns => [ 'ERROR' ]
  },
);

EOCFG
open CCC, ">./etc/multiline.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/multiline.cfg" });
$cl->reset();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});

my ($protocolFile) = glob( "./var/tmp/multiline.protocol*" );
open( PROTOCOL, "<$protocolFile" ) || fail( "Could not open protocol file '$protocolFile': $!" );
my @content = <PROTOCOL>;
close( PROTOCOL );

my $expectedContent = qq|CRITICAL Errors in multiline.log (tag multiline)
2017-08-07 19:51:02 - ERROR
Test subject glitched through catcher
Cake reward will be reduced
2017-08-07 19:51:09 - ERROR
.....<bzzzt>.....>...\$\%\&...:!
<reboot initi.... cake...\%\%\&/(
2017-08-07 19:57:37 - ERROR - but only one line really
|;

is(join( "", @content ), $expectedContent ); 
like($cl->{exitmessage}, qr/CRITICAL - \(3 errors in multiline.protocol-.+\) - 2017-08-07 19:57:37 - ERROR - but only one line really .../ );
ok($cl->expect_result(0, 0, 3, 0, 2));

