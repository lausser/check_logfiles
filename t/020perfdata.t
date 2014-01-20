#!/usr/bin/perl -w
#
# ~/check_logfiles/test/005norotation.t
#
#  Test logfiles which will be deleted and recreated instead of rotated.
#
#  fill a logfile with crap. run. must be ok
#  add criticals. run. must be critical
#  delete logfile. add crap. run. must be ok. tracefile must mention recreation
#  add errors. run .must be critical
#  delete logfile. run. must be critical
#  add 100 lines of crap. run. must be ok
#  delete logfile. add 10 lines of criticals. add 10 lines of crap. run. must be critical
#  delete logfile. run. must be critical
#  add 100 lines of crap. run. must be ok
#  delete logfile. add 10 lines of criticals. add 100 lines of crap. run. must be critical
#  delete logfile. touch logfile. run. must be ok.
#  the same with no_logfile_no_cry => 1

use strict;
use Test::More tests => 9;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "ssh",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
              options => "perfdata"
	    },
	    {
	      tag => "test",
	      logfile => TESTDIR."/var/adm/messages",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
              options => "noperfdata"
	    },
	    {
	      tag => "null",
	      logfile => TESTDIR."/var/adm/messages",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => "nonsense",
	      warningpatterns => "crap",
              options => "perfdata"
	    },

	]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
my $test = $cl->get_search_by_tag("test");
$test->delete_logfile();
$test->delete_seekfile();
$test->trace("deleted logfile and seekfile");
my $null = $cl->get_search_by_tag("null");
$null->delete_logfile();
$null->delete_seekfile();
$null->trace("deleted logfile and seekfile");
$cl->run();

$ssh->trace("==== 1 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 20);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 20);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 4, 0, 2));
ok($ssh->{perfdata} =~ /ssh_lines=\d+ ssh_warnings=0 ssh_criticals=2 ssh_unknowns=0/);
ok($test->{perfdata} eq "");
ok($null->{perfdata} =~ /null_lines=\d+ null_warnings=0 null_criticals=0 null_unknowns=0/);
ok($cl->{perfdata} =~ /ssh_lines=\d+ ssh_warnings=0 ssh_criticals=2 ssh_unknowns=0 null_lines=\d+ null_warnings=0 null_criticals=0 null_unknowns=0/);
ok($cl->{exitmessage} =~ /CRITICAL - \(4 errors\) - [\w: \[\]]+ Failed password for invalid user8 ...\s*$/);
diag(sprintf "((%s))", $cl->{exitmessage});


my $configfile = <<EOCFG;
\$seekfilesdir = "./var/tmp";
\$scriptpath = "./bin";
\$options = "supersmartpostscript";
\$postscript = sub {
	  my \$output = \$ENV{CHECK_LOGFILES_SERVICEOUTPUT};
	  my \$perfdata = \$ENV{CHECK_LOGFILES_SERVICEPERFDATA};
	  \$perfdata =~ s/ssh/xxl/g;
	  \$perfdata =~ s/null/zero/g;
	  printf "HURTZ! - das lamm schrie | %s\\n", \$perfdata;
	  return 0;
	};
\@searches = (
	    {
	      tag => "ssh",
	      logfile => "./var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
              options => "perfdata"
	    },
	    {
	      tag => "test",
	      logfile => "./var/adm/messages",
	      logfile => "./var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
              options => "noperfdata"
	    },
	    {
	      tag => "null",
	      logfile => "./var/adm/messages",
	      logfile => "./var/adm/messages",
	      criticalpatterns => "nonsense",
	      warningpatterns => "crap",
              options => "perfdata"
	    });

EOCFG
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;

$cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_action.cfg" });


my $postscript = $cl->get_search_by_tag("postscript");	
$postscript->{script} = sub {
	  my $output = $ENV{CHECK_LOGFILES_SERVICEOUTPUT};
	  my $perfdata = $ENV{CHECK_LOGFILES_SERVICEPERFDATA};
	  $perfdata =~ s/ssh/xxl/g;
	  $perfdata =~ s/null/zero/g;
	  printf "HURTZ! - das lamm schrie | %s\n", $perfdata;
	  return 0;
	};
$ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
$test = $cl->get_search_by_tag("test");
$test->delete_logfile();
$test->delete_seekfile();
$test->trace("deleted logfile and seekfile");
$null = $cl->get_search_by_tag("null");
$null->delete_logfile();
$null->delete_seekfile();
$null->trace("deleted logfile and seekfile");
$cl->run();
$ssh->trace("==== 1 ====");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 20);
$ssh->logger(undef, undef, 2, "Failed password for invalid user8");
$ssh->loggercrap(undef, undef, 20);
$cl->run();
diag("modified results");
diag("perf: ".$cl->{perfdata});
diag("exit: ".$cl->{exitmessage});

ok($cl->{perfdata} =~ /xxl_lines=\d+ xxl_warnings=0 xxl_criticals=2 xxl_unknowns=0 zero_lines=\d+ zero_warnings=0 zero_criticals=0 zero_unknowns=0/);
ok($cl->{exitmessage} =~ /^HURTZ! - das lamm schrie $/);
diag(sprintf "((%s))", $cl->{exitmessage});

SKIP:{
  skip 'no executable', 1 if (! -x "../plugins-scripts/check_logfiles");
  $ssh->loggercrap(undef, undef, 20);
  $ssh->logger(undef, undef, 2, "Failed password for invalid user8");
  $ssh->loggercrap(undef, undef, 20);
  my $output = `../plugins-scripts/check_logfiles -f ./etc/check_action.cfg`;
  diag($output);
  ok($output =~ /^HURTZ! - das lamm schrie |xxl_lines=\d+ xxl_warnings=0 xxl_criticals=2 xxl_unknowns=0 zero_lines=\d+ zero_warnings=0 zero_criticals=0 zero_unknowns=0/);
}

