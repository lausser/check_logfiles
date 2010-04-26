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

plan tests => 35;


my $cl = Nagios::CheckLogfiles::Test->new({
  options => 'report=long',
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
ok($ssh->{options}->{report} eq "long");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

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
        \$options = 'report=long';
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
# --ok 10
ok($cl->{long_exitmessage} =~ /tag ssh CRITICAL\n.*user8.*\n.*user8.*\n.*Unknown.*\n.*Unknown.*\ntag null WARNING\n.*crap.*\n.*crap/);

$ssh->trace("==== very long output ====");
diag("==== very long output ====");
sleep 1;
$cl->reset();
# 2 criticals for ssh
$ssh->loggercrap(undef, undef, 2);
foreach (1..300) {
  $ssh->logger(undef, undef, 1, "Failed password for invalid user88");
}
$cl->run();
#diag($cl->{long_exitmessage});
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 300, 0, 2));
diag($cl->{exitmessage});
diag(length $cl->{long_exitmessage});
ok((length $cl->{long_exitmessage} <= 4096) && (length $cl->{long_exitmessage} > 3000));

$configfile =<<EOCFG;
        \$options = 'report=long,maxlength=8192';
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
printf STDERR "======================================================\n";
open CCC, ">./etc/searcheslong.cfg";
print CCC $configfile;
close CCC;

$cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/searcheslong.cfg", selectedsearches => ['ssh'] });
ok(scalar @{$cl->{searches}} == 1);
$ssh = $cl->get_search_by_tag("ssh");
$cl->run(); # init
$cl->reset();
#$ssh->loggercrap(undef, undef, 2);
foreach (1..700) {
  $ssh->logger(undef, undef, 1, "Failed password for invalid user8");
}
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 700, 0, 2));
diag(length $cl->{long_exitmessage});
ok((length $cl->{long_exitmessage} <= 8192) && (length $cl->{long_exitmessage} > 8000));


# zeilen mit returncode 0 sollen nur im longoutput auftauchen, wenn sie
# Treffer von okpattern waren.
# Return 0 aus einem Supersmartscript zaehlt nicht.

$cl = Nagios::CheckLogfiles::Test->new({
        options => 'report=long',
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "door",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => ["door open", "window open"],
              warningpatterns => ["door unlocked", "window unlocked"],
              okpatterns => ["door closed", "window closed"],
              options => "sticky",
            }
        ]    });
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
$door->logger(undef, undef, 1, "the door open1");
$door->logger(undef, undef, 1, "the door open2");
$door->logger(undef, undef, 1, "the door open3");
$door->logger(undef, undef, 1, "the door open4");
$door->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{long_exitmessage});
ok($cl->expect_result(0, 0, 4, 0, 2));

$cl->reset();
$door->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 4, 0, 2));

$cl->reset();
$door->loggercrap(undef, undef, 10);
$door->logger(undef, undef, 1, "the door open5");
$door->logger(undef, undef, 2, "the door closed");
$door->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
diag("longexit".$cl->{long_exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));
my $sum = 0;
map { $sum += $_ } map { scalar(@{$door->{matchlines}->{$_}}) } keys %{$door->{matchlines}};
ok($sum == 0);
diag("final".$cl->{long_exitmessage});
ok($cl->{long_exitmessage} eq "");


$cl = Nagios::CheckLogfiles::Test->new({
        options => 'report=long',
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "door",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => ["door open", "window open"],
              warningpatterns => ["door unlocked", "window unlocked"],
              okpatterns => ["door closed", "window closed"],
              options => "supersmartscript",
              script => sub {
                my $line = $ENV{CHECK_LOGFILES_SERVICEOUTPUT};
                $line =~ /open(\w+)/;
                print "kaas".$1;
                return 0 if $1 eq "D";
                return 2;
              },
            }
        ]    });
$door = $cl->get_search_by_tag("door");
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
$door->logger(undef, undef, 1, "the door openC");
$door->logger(undef, undef, 1, "the door openD");
$door->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
$sum = 0;
map { $sum += $_ } map { scalar(@{$door->{matchlines}->{$_}}) } keys %{$door->{matchlines}};
ok($sum == 4);
ok(scalar(@{$door->{matchlines}->{CRITICAL}}) == 3);
ok(scalar(@{$door->{matchlines}->{OK}}) == 1);
diag("final".$cl->{long_exitmessage});
my @x = split(/\n/, $cl->{long_exitmessage});
ok(scalar(@x) == 4);
ok($cl->{long_exitmessage} !~ /kaas4/);
ok($cl->expect_result(1, 0, 3, 0, 2));


# handle empty lines
$cl = Nagios::CheckLogfiles::Test->new({
        options => 'report=long',
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "door",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => '.*',
              okpatterns => 'schnorch!',
            }
        ]    });
$door = $cl->get_search_by_tag("door");
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
$door->logger(undef, undef, 10, "schnorch!");
$door->logger(undef, undef, 1, "the door open1");
$door->logger(undef, undef, 1, "the door open2");
$door->logger(undef, undef, 1, "the door open3");
$door->logger(undef, undef, 1, "the door open4");
my $logfh = IO::File->new();
$logfh->autoflush(1);
if ($logfh->open($door->{logfile}, "a")) {
  $logfh->printf("\n");
  $logfh->printf("\n");
  $logfh->printf("\n");
  $logfh->printf("\n");
  $logfh->close();
}
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
$sum = 0;
map { $sum += $_ } map { scalar(@{$door->{matchlines}->{$_}}) } keys %{$door->{matchlines}};
ok($sum == 8);
ok(scalar(@{$door->{matchlines}->{CRITICAL}}) == 8);
diag("final".$cl->{long_exitmessage}."final");
@x = split(/\n/, $cl->{long_exitmessage});
ok(scalar(@x) == 9);
printf "%s\n", Data::Dumper::Dumper(\@x);
ok($cl->{long_exitmessage} =~ /tag door CRITICAL\n.*open1\n.*open2\n.*open3\n.*open4\n_\(null\)_\n_\(null\)_\n_\(null\)_\n_\(null\)_\n/m);
ok($cl->expect_result(0, 0, 8, 0, 2));

