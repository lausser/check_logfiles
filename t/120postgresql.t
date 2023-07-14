#!/usr/bin/perl -w
#
#  120postgresql.t
#
#  Test postgresql log checking
#

use strict;
use Test::More tests => 3;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

use Nagios::CheckLogfiles::Search::Postgresql;

my $configfile = q|
$protocolsdir = "./var/tmp";
$seekfilesdir = "./var/tmp";

$tag = 'postgresql';
$logfile = './data/postgresql.log';
$postgresLoglinePrefix='%t [%p-%l] (%e) %q%u@%d (%a) ';

@searches = Nagios::CheckLogfiles::Search::Postgresql->getSearch( $tag, $logfile, $postgresLoglinePrefix );

$searches[0]->{options} = $searches[0]->{options} . ",allyoucaneat";
|;

open CCC, ">./etc/postgresql.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/postgresql.cfg" });
$cl->reset();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});

my ($protocolFile) = glob( "./var/tmp/postgresql.protocol*" );
open( PROTOCOL, "<$protocolFile" ) || fail( "Could not open protocol file '$protocolFile': $!" );
my @content = <PROTOCOL>;
close( PROTOCOL );

my $expectedContent = q|CRITICAL Errors in postgresql.log (tag postgresql)
2017-10-13 09:27:27 CEST [16992-1] (00042) LOG:  automatic vacuum of table "template1.pg_catalog.pg_class": index scans: 1
        pages: 0 removed, 14 remain, 0 skipped due to pins, 0 skipped frozen
        tuples: 7 removed, 316 remain, 0 are dead but not yet removable
        buffer usage: 89 hits, 0 misses, 1 dirtied, 6 multilines
        avg read rate: 0.000 MB/s, avg write rate: 8.130 MB/s - and this is very bad!
        system usage: CPU 0.00s/0.00u sec elapsed 0.00 sec
2017-10-13 09:27:49 CEST [17075-1] (XFLR6) [unknown]@[unknown] ([unknown]) LOG:  connection received: host=[local] - destination "moon" is not reachable
2017-10-13 09:27:49 CEST [17075-2] (01337) instance3@instance3 ([unknown]) LOG:  connection authorized: user=instance3 database=instance3 - no way!
2017-10-13 09:29:39 CEST [29236-2] (MLLIA) instance3@instance3 ([unknown]) LOG:  connection authorized: user=instance3 database=instance3 - anagrams unsupported
2017-10-13 09:30:26 CEST [29445-1] (12345) [unknown]@[unknown] ([unknown]) LOG:  connection received: host=[local] - even the last line should be detected
|;

is(join( "", @content ), $expectedContent ); 
like($cl->{exitmessage}, qr/CRITICAL - \(5 errors in postgresql.protocol-.+\) - 2017-10-13 09:30:26 CEST/ );
ok($cl->expect_result(14, 0, 5, 0, 2));

