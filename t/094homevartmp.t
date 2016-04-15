#!/usr/bin/perl -w
#
# ~/check_logfiles/test/094homevartmp.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 21;
use Cwd;
use File::Path;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $cl = Nagios::CheckLogfiles::Test->new({
	protocolsdir => TESTDIR."/var/tmp",
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
$ssh->logger(undef, undef, 2, "Failed password for invalid user2...");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# 3 now find the two criticals and the two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
diag("seek ".$ssh->{seekfile});
ok(-f "./var/tmp/check_logfiles.._var_adm_messages.ssh");

$ENV{OMD_ROOT} = "./omd_root";
$cl = Nagios::CheckLogfiles::Test->new({
	protocolsdir => "homevartmp:".TESTDIR."/var/tmp",
	seekfilesdir => "homevartmp:".TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user"
	    }
	]    
});
$ssh = $cl->get_search_by_tag("ssh");

$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));
diag("seek ".$ssh->{seekfile});
ok(! -f "./var/tmp/check_logfiles.._var_adm_messages.ssh");
ok(-f "./omd_root/var/tmp/check_logfiles/check_logfiles.._var_adm_messages.ssh");


$cl->trace("now test if the migration really worked");
# find the two criticals
$ssh->trace(sprintf "+----------------------- test %d ------------------", 12);
$cl->reset();
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2...");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));
diag("seek ".$ssh->{seekfile});
ok(! -f "./var/tmp/check_logfiles.._var_adm_messages.ssh");
ok(-f "./omd_root/var/tmp/check_logfiles/check_logfiles.._var_adm_messages.ssh");

rmtree("./omd_root");

diag("# with configfile ====================================================");
$cl->trace("# with configfile ====================================================");
my $configfile = <<EOCFG;
	\$protocolsdir = TESTDIR."/var/tmp";
	\$seekfilesdir = TESTDIR."/var/tmp";
	\@searches = (
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user"
	    }
	);
EOCFG
my $testdir = TESTDIR;
$configfile =~ s/TESTDIR/"$testdir"/g;
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;

$cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_action.cfg" });
$ssh = $cl->get_search_by_tag("ssh");
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
$ssh->logger(undef, undef, 2, "Failed password for invalid user2...");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# 3 now find the two criticals and the two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
sleep 1;

diag("seek ".$ssh->{seekfile});
ok(-f "./var/tmp/check_action.._var_adm_messages.ssh");

$ENV{OMD_ROOT} = "./omd_root";
$configfile = <<EOCFG;
	\$protocolsdir = "homevartmp:".TESTDIR."/var/tmp";
	\$seekfilesdir = "homevartmp:".TESTDIR."/var/tmp";
	\@searches = (
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user"
	    }
	);
EOCFG
unlink("./etc/check_action.cfg");
$testdir = TESTDIR;
$configfile =~ s/TESTDIR/"$testdir"/g;
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;
sleep 1;
$cl->trace("now create a new CheckLogfiles with homevartmp");
$cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_action.cfg" });
$ssh = $cl->get_search_by_tag("ssh");

$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));

diag("seek ".$ssh->{seekfile});
ok(! -f "./var/tmp/check_action.._var_adm_messages.ssh");
ok(-f "./omd_root/var/tmp/check_logfiles/check_action.._var_adm_messages.ssh");
rmtree("./omd_root");


diag("# now with string ============================================");
$configfile = <<EOCFG;
	\$protocolsdir = TESTDIR."/var/tmp";
	\$seekfilesdir = TESTDIR."/var/tmp";
	\@searches = (
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user"
	    }
	);
EOCFG
$testdir = TESTDIR;
$configfile =~ s/TESTDIR/"$testdir"/g;
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;

open (CFG,"./etc/check_action.cfg");
my $contents = "";
while (<CFG>) {$contents .= $_}
#print $contents."\n###\n";
$contents =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg;
close (CFG);
$cl = Nagios::CheckLogfiles::Test->new({ cfgfile => $contents });
$ssh = $cl->get_search_by_tag("ssh");
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
$ssh->logger(undef, undef, 2, "Failed password for invalid user2...");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

# 3 now find the two criticals and the two warnings
$ssh->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user3");
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 100);
sleep 1;

diag("seek ".$ssh->{seekfile});
ok(-f "./var/tmp/flatfile.._var_adm_messages.ssh");

$ENV{OMD_ROOT} = "./omd_root";
$configfile = <<EOCFG;
	\$protocolsdir = "homevartmp:".TESTDIR."/var/tmp";
	\$seekfilesdir = "homevartmp:".TESTDIR."/var/tmp";
	\@searches = (
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user"
	    }
	);
EOCFG
$testdir = TESTDIR;
$configfile =~ s/TESTDIR/"$testdir"/g;
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;
open (CFG,"./etc/check_action.cfg");
$contents = "";
while (<CFG>) {$contents .= $_}
#print $contents."\n###\n";
$contents =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg;
close (CFG);
$cl = Nagios::CheckLogfiles::Test->new({ cfgfile => $contents });
$ssh = $cl->get_search_by_tag("ssh");

$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));

diag("seek ".$ssh->{seekfile});
ok(! -f "./var/tmp/flatfile.._var_adm_messages.ssh");
ok(-f "./omd_root/var/tmp/check_logfiles/flatfile.._var_adm_messages.ssh");

rmtree("./omd_root");

