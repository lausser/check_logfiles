#!/usr/bin/perl -w
#
# ~/check_logfiles/test/053pathswithblanks.t
#
#  Test the capability of finding files, scripts etc with blanks in the pathname
#

use strict;
use Test::More tests => 15;
use Cwd 'abs_path';
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => "./i have a lot of holes";

my $testdir = TESTDIR;
my $vardir = TESTDIR."/var";
my $tmpdir = TESTDIR."/var/tmp";
my $logdir = TESTDIR."/var/adm";
my $bindir = TESTDIR."/bin";
my $logfile = TESTDIR."/var/adm/holes holes holes.log";

foreach ($testdir, $vardir, $tmpdir, $logdir, $bindir) {
  mkdir $_;
}
open LOL, ">$logfile";
printf LOL "muss existieren, damit abs_path funktioniert";
close LOL;

printf "testdir %s\n", $testdir;
printf "logfile %s\n", $logfile;
$testdir = abs_path($testdir);
$tmpdir = abs_path($tmpdir);
$logdir = abs_path($logdir);
$logfile = abs_path($logfile);
if ($^O =~ /Win/) {
  $bindir = abs_path($bindir).';C:\Program Files\dummy';
} else {
  $bindir = abs_path($bindir).':/usr/so a kaas/ummy';
}
printf "testdir %s\n", $testdir;
printf "logfile %s\n", $logfile;
unlink $logfile;

my $cl = Nagios::CheckLogfiles::Test->new({
	protocolsdir => $tmpdir,
	seekfilesdir => $tmpdir,
	scriptpath => $bindir,
	searches => [
	    {
	      tag => "ssh",
	      logfile => $logfile,
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      rotation => "loglog0log1",
	    }
	]    });
#printf "%s\n", Data::Dumper::Dumper($cl);
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
$ssh->rotate();
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
$ssh->rotate();
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
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
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
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
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
$ssh->rotate();
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
$ssh->rotate();
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
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
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
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 2, 0, 2));



# now add a script, produce 20 criticals, rescript them to 20 warnings
# now write critical messages, rotate, write harmless stuff, rotate, write warning
$ssh->trace("==== 15 ====");
$ssh->{script} = "crit2warn.sh";
$ssh->{options}->{script} = 1;
$ssh->{options}->{smartscript} = 1;
$ssh->{options}->{supersmartscript} = 1;
$cl->reset();
if ($^O =~ /MSWin/) {
  $ssh->{script} = "crit2warn.bat";
  $cl->create_file((split(/;/, $bindir))[0]."/crit2warn.bat", 0755, "
\@echo off
echo status \"%CHECK_LOGFILES_SERVICESTATEID%\"
echo output \"%CHECK_LOGFILES_SERVICEOUTPUT%\"
exit 1
");
} else {
  $ssh->{script} = "crit2warn.sh";
  $cl->create_file((split(/:/, $bindir))[0]."/crit2warn.sh", 0755, "
echo status \"\$CHECK_LOGFILES_SERVICESTATEID\"
echo output \"\$CHECK_LOGFILES_SERVICEOUTPUT\"
exit 1
");
}
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 10, "Failed password for invalid user6");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 10, "Failed password for invalid user6");
$ssh->loggercrap(undef, undef, 100);
$ssh->rotate();
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 20, 0, 0, 1));

