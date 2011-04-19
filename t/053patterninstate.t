#!/usr/bin/perl -w
#
# ~/check_logfiles/test/053reportlong.t
#
#  Test if the matching pattern appears in the privatestate
#

use strict;
use Test::More;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

plan tests => 3;


my @patterns = ();

my $configfile =<<EOCFG;
        \$seekfilesdir = "./var/tmp";
        \@searches = (
            {
              tag => "door",
              logfile => "./var/adm/messages",
              criticalpatterns => ["door open", "window open"],
              warningpatterns => ["door unlocked", "window unlocked"],
              okpatterns => ["door closed", "window closed"],
              options => "supersmartscript",
              script => sub {
                my \$pattern = \$CHECK_LOGFILES_PRIVATESTATE->{matchingpattern};
                printf "my pattern was (%s)\n", \$pattern;
                \$pattern =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord(\$1))/seg;
                printf STDERR "encoded pattern is %s\n", \$pattern;
                \$pattern =~ s/\%([A-Fa-f0-9]{2})/pack('C', hex(\$1))/seg;
                printf STDERR "decoded pattern is %s\n", \$pattern;
                return 2;
              }
            }
        );
EOCFG

open CCC, ">./etc/patterninstate.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/patterninstate.cfg"});
my $door = $cl->get_search_by_tag("door");
$door->delete_logfile();
$door->delete_seekfile();
$door->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$door->trace(sprintf "+----------------------- test %d ------------------", 1);
$door->loggercrap(undef, undef, 100);
sleep 1;
$door->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 2 now find the two criticals
$door->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the door openA");
$door->logger(undef, undef, 1, "the door openB");
$door->logger(undef, undef, 1, "the door openD");
$door->logger(undef, undef, 1, "the window openC");
$door->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 4, 0, 2));
ok($cl->{exitmessage} =~ /my pattern was \(window open\)/);

