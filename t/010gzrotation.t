#!/usr/bin/perl -w
#
# ~/check_logfiles/test/010gzrotation.t
#
#  Test the capability of finding rotated logfiles.
#

use strict;
use Test::More tests => 14;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

if ($^O =~ /MSWin/) {
  $ENV{PATH} = $ENV{PATH}.';C:\Programme\cygwin\bin;C:\cygwin\bin';
}

my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
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
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->logger(undef, undef, 2, "Failed password for invalid user1");
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find the two criticals
$ssh->trace("==== 2 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now rotate and find the two new criticals
$ssh->trace("==== 3 ====");
$ssh->rotate_compress();
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now rotate and create no new logfile
$ssh->trace("==== 4 ====");
$ssh->rotate_compress();
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 1, 3));

# now write messages and find them
$ssh->trace("==== 5 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now write critical messages, rotate, write harmless messages, rotate, write warning, rotate, stop
#
#
# under cygwin rotation changes modification time!!!!!!!!!!!!!
#

$ssh->trace("==== 6 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user5");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate_compress();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate_compress();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate_compress();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 2, 1, 2));


# now write critical messages, rotate, write harmless stuff, rotate, write warning
$ssh->trace("==== 7 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user6");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate_compress();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate_compress();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate_compress();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 2, 1, 2));

# repeat but this time with nologfilenocry
$cl->reset();
$ssh = $cl->get_search_by_tag("ssh");
$ssh->{options}->{logfilenocry} = 0;
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->trace("==== 8 ====");
$ssh->logger(undef, undef, 2, "Failed password for invalid user1");
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find the two criticals
$ssh->trace("==== 9 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now rotate and find the two new criticals
$ssh->trace("==== 10 ====");
$ssh->rotate_compress();
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now rotate and create no new logfile
$ssh->trace("==== 11 ====");
$ssh->rotate_compress();
$cl->reset();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now write messages and find them
$ssh->trace("==== 12 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# now write critical messages, rotate, write harmless messages, rotate, write warning, rotate, stop
#
#
# under cygwin rotation changes modification time!!!!!!!!!!!!!
#

$ssh->trace("==== 13 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user5");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate_compress();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate_compress();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate_compress();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 2, 0, 2));


# now write critical messages, rotate, write harmless stuff, rotate, write warning
$ssh->trace("==== 14 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user6");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate_compress();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate_compress();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate_compress();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 2, 0, 2));
