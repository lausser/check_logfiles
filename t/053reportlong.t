#!/usr/bin/perl -w
#
# ~/check_logfiles/test/053reportlong.t
#
#  Test everything using windows encoding.
#

use strict;
use Test::More;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

plan tests => 2;


my $cl = Nagios::CheckLogfiles::Test->new({
  report => 'long',
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user"
            }
        ]    });

my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
diag(Data::Dumper::Dumper($cl->{options}));
diag(Data::Dumper::Dumper($ssh->{options}));

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->trace(sprintf "+----------------------- test %d ------------------", 1);
$ssh->logger(undef, undef, 2, "Failed password for invalid user1...");
$ssh->trace(sprintf "in 1: ctime %s",
    scalar localtime ((stat TESTDIR."/var/adm/messages")[10]));
$ssh->trace(sprintf "in 1: mtime %s",
    scalar localtime ((stat TESTDIR."/var/adm/messages")[9]));
sleep 2;
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 2 now find the two criticals
$ssh->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 1, "Failed password for invalid user2...");
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 1, "something with Unknown user");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 1, 0, 2));
diag($cl->{long_exitmessage});
ok($cl->{long_exitmessage} =~ /tag ssh CRITICAL\n.*user2.*\n.*Unknown/m);


# 3 now find the two criticals and the two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Failed password for invalid user3");
$ssh->logger(undef, undef, 1, "Failed password for invalid user4");
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));
ok($cl->{long_exitmessage} =~ /tag ssh CRITICAL\n.*user3\n.*user4\n.*sepp/m);


my $configfile =<<EOCFG;
        \$options = 'report="long"';
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
              logfile => "./var/adm/messages",
              criticalpatterns => "Failed password for invalid user9",
              warningpatterns => "Unknown user",
              options => "noperfdata,nologfilenocry"
            },
            {
              tag => "null",
              logfile => "./var/adm/messages",
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

$cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/searches.cfg", selectedsearches => ['ssh', 'null'] });
ok(scalar @{$cl->{searches}} == 2);
$ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
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
# 2 criticals for ssh
$ssh->loggercrap(undef, undef, 2);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->logger(undef, undef, 2, "Failed password for invalid user9");
$ssh->loggercrap(undef, undef, 2);
# 2 warnings for ssh
$ssh->logger(undef, undef, 2, "found Unknown user");
# ssh logs instead of test
# 2 warnings for null
$null->loggercrap(undef, undef, 2);
$null->logger(undef, undef, 2, "this is crappy");
$null->loggercrap(undef, undef, 2);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 4, 2, 0, 2));
ok($cl->{exitmessage} =~ /CRITICAL - \(2 errors, 4 warnings\) - .* Failed password .*user8 /);
diag($cl->{long_exitmessage});
ok($cl->{long_exitmessage} =~ /tag ssh CRITICAL\n.*user8.*\n.*user8.*\n.*Unknown.*\n.*Unknown.*\ntag null WARNING\n.*crap.*\n.*crap/);
