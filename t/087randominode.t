#!/usr/bin/perl -w
#
# ~/check_logfiles/test/087randominode.t

use strict;
use Test::More tests => 11;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

sub changeinode {
  my $file = shift;
  printf "%s:%s:%s .. ", (stat $file)[0], (stat $file)[1], (stat $file)[7];
  open TEMP1, ">temp1";
  open LOG, $file;
  while (<LOG>) {
    print TEMP1 $_;
  }
  close LOG;
  close TEMP1;
  open TEMP2, ">temp2";
  open TEMP1, "temp1";
  while (<TEMP1>) {
    print TEMP2 $_;
  }
  close TEMP1;
  close TEMP2;
  unlink $file;
  rename "temp2", $file;
  printf "%s:%s:%s\n", (stat $file)[0], (stat $file)[1], (stat $file)[7];
}

my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
              options => "randominode",
	    }
	]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

$ssh->trace("==== 1 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 500);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# ok this time don't touch the logfile

$ssh->trace("==== 2 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 20);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 20);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now the inode changes
#
changeinode(TESTDIR."/var/adm/messages");

$ssh->trace("==== 3 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 20);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now the inode changes once more
#
changeinode(TESTDIR."/var/adm/messages");

$ssh->trace("==== 4 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 200);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 200);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

$ssh->trace("==== 5 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 500);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

undef $cl;
undef $ssh;

$cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
              options => "randominode",
              rotation => 'loglog0log1',
	    }
	]    });
$ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

$ssh->trace("==== 1 ====");
sleep 1;
$cl->reset();
$ssh->delete_logfile();
$ssh->loggercrap(undef, undef, 500);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# ok this time don't touch the logfile

$ssh->trace("==== 2 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 20);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 20);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now the inode changes
#
changeinode(TESTDIR."/var/adm/messages");

$ssh->trace("==== 3 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 20);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now the inode changes once more
# and rotate
#
changeinode(TESTDIR."/var/adm/messages");
rename TESTDIR."/var/adm/messages", TESTDIR."/var/adm/messages.0";

$ssh->trace("==== 4 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 200);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 200);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));
changeinode(TESTDIR."/var/adm/messages");

$ssh->trace("==== 5 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 500);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));
changeinode(TESTDIR."/var/adm/messages");

$ssh->trace("==== 6 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 200);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 200);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));



