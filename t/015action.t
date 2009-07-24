#!/usr/bin/perl -w
#
# ~/check_logfiles/test/005negative.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 14;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $configfile = <<EOCFG;
\$seekfilesdir = "./var/tmp";
\$scriptpath = "./bin";
\$MACROS = {
  CL_NSCA_HOST_ADDRESS => 'nagios.dierichs.de',
  CL_NSCA_PORT => 5555,
  SNMP_TRAP_SINK_HOST => 'nagios.dierichs.de',
  SNMP_TRAP_SINK_VERSION => 'snmpv1',
  SNMP_TRAP_SINK_COMMUNITY => 'public',
  SNMP_TRAP_SINK_PORT => 162,
  SNMP_TRAP_ENTERPRISE_OID => '1.3.6.1.4.1.20006.1.5.1',
};
\@searches = (
    {
      tag => "action",
      logfile => "./var/adm/messages",
      criticalpatterns => [ 
             '.*connection unexpectedly closed.*', 
             '.*rsync error.*', 
             'rsync:.*', 
             '!.*DEBUT.*', 
             '!.*FIN.*', 
             '!.*building file list.*', 
             '!.*files to consider.*', 
             '!.*sent .* bytes\\s+received .* bytes\\s+.* bytes/sec.*', 
             '!.*total size is .* \\s+speedup is .*' ,
         ], 
         warningpatterns => [ 
             '.*total size is 0 .*', 
             '.*sent 0 bytes.*', 
             '.*received 0 bytes.*' 
         ],
             options => 'script',
             script => "send_snmptrap"
    });
\$postscript = 'send_nsca';
\$postscriptparams = '-H \$CL_NSCA_HOST_ADDRESS\$ -p \$CL_NSCA_PORT\$ -to \$CL_NSCA_TO_SEC\$ -c \$CL_NSCA_CONFIG_FILE\$';
\$postscriptstdin = '\$CL_HOSTNAME\$\\t\$CL_SERVICEDESC\$\\t\$CL_SERVICESTATEID\$\\t\$CL_SERVICEOUTPUT\$\\n';

EOCFG
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_action.cfg" });
if ($^O =~ /MSWin/) {
  $cl->create_file("./bin/send_snmptrap.bat", 0755, "
echo off
rem echo i am the script
rem echo status %CHECK_LOGFILES_SERVICESTATEID%
echo output \"%CHECK_LOGFILES_SERVICEOUTPUT%\" >> ./var/tmp/scriptcounter
exit /B 3;
");
} else {
  $cl->create_file("./bin/send_snmptrap", 0755, "
echo i am the script \$CHECK_LOGFILES_SERVICESTATEID \$CHECK_LOGFILES_SERVICEOUTPUT
echo status \$CHECK_LOGFILES_SERVICESTATEID
echo output \"\$CHECK_LOGFILES_SERVICEOUTPUT\" >> ./var/tmp/scriptcounter
exit 3;
");
};
if ($^O =~ /MSWin/) {
  $cl->create_file("./bin/send_nsca.bat", 0755, "
echo off
echo i am the postscript 
echo status %CHECK_LOGFILES_SERVICESTATEID%
echo output \"%CHECK_LOGFILES_SERVICEOUTPUT%\"
echo output \"%CHECK_LOGFILES_SERVICEOUTPUT%\" >> ./var/tmp/scriptcounter
exit /B 0;
");
} else {
  $cl->create_file("./bin/send_nsca", 0755, "
echo i am the postscript with \"\$*\"
echo status \$CHECK_LOGFILES_SERVICESTATEID
echo output \$CHECK_LOGFILES_SERVICEOUTPUT
echo output \$CHECK_LOGFILES_SERVICEOUTPUT >> ./var/tmp/scriptcounter
exit 0;
");
}
my $action = $cl->get_search_by_tag("action");
my $postscript = $cl->get_search_by_tag("postscript");
if ($^O =~  /MSWin/) {
  $action->{script} = "send_snmptrap.bat";
  $postscript->{script} = "send_nsca.bat";
  delete $postscript->{scriptstdin};
}
$cl->reset();
$cl->delete_file("./var/tmp/scriptcounter");
$action->delete_logfile();
$action->delete_seekfile();
diag("deleted logfile and seekfile");
$action->trace("deleted logfile and seekfile");
$action->logger(undef, undef, 1, "Failed password for invalid user1...");
diag("wrote 1 message");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 6, 0, 2));
my $x = $cl->read_file("./var/tmp/scriptcounter");
my @lines = split(/\n/, $x);
diag(sprintf "script was called %d times", scalar(@lines));
ok(@lines == 7);


$cl->reset();
$cl->delete_file("./var/tmp/scriptcounter");
$action->delete_logfile();
$action->delete_seekfile();
$action->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 6, 0, 2));
$x = $cl->read_file("./var/tmp/scriptcounter");
@lines = split(/\n/, $x);
diag(sprintf "script was called %d times", scalar(@lines));
ok(@lines == 7);

$cl->reset();
$cl->delete_file("./var/tmp/scriptcounter");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 8, 0, 2));
$x = $cl->read_file("./var/tmp/scriptcounter");
@lines = split(/\n/, $x);
diag(sprintf "script was called %d times", scalar(@lines));
ok(@lines == 9);

# backup working perfectly
$cl->reset();
$cl->delete_file("./var/tmp/scriptcounter");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "DEBUT du backup");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "building file list ... done");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "files to consider:...");
$action->logger(undef, undef, 1, "file file file");
$action->logger(undef, undef, 1, "sent 871 bytes  received 26 bytes  163.09 bytes/sec");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "total size is 30053  speedup is 33.50");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "FIN du backup");
sleep 1;
$cl->run();
$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));
$x = $cl->read_file("./var/tmp/scriptcounter");
@lines = split(/\n/, $x);
diag(sprintf "script was called %d times", scalar(@lines));
ok(@lines == 1);

# backup with warning
$cl->reset();
$cl->delete_file("./var/tmp/scriptcounter");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "DEBUT du backup");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "building file list ... done");
$action->logger(undef, undef, 1, "files to consider:...");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "file file file");
$action->logger(undef, undef, 1, "sent 0 bytes  received 0 bytes  0 bytes/sec");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "total size is 0  speedup is 0");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "FIN du backup");
$action->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 3, 0, 0, 1));
$x = $cl->read_file("./var/tmp/scriptcounter");
@lines = split(/\n/, $x);
diag(sprintf "script was called %d times", scalar(@lines));
ok(@lines == 4);

#backup did not run at all
$cl->reset();
$cl->delete_file("./var/tmp/scriptcounter");
sleep 1;
$cl->run();
$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 6, 0, 2));
$x = $cl->read_file("./var/tmp/scriptcounter");
@lines = split(/\n/, $x);
diag(sprintf "script was called %d times", scalar(@lines));
ok(@lines == 7);

#mixed critical and missing errors. script is a piece of perl now.
$cl->reset();
$cl->delete_file("./var/tmp/scriptcounter");
$action->{script} = sub {
  printf "i am perl\n";
  open OOO, ">>./var/tmp/scriptcounter";
  printf OOO "%s\n", $ENV{CHECK_LOGFILES_SERVICEOUTPUT};
  close OOO;
  return 3;
};
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 8, 0, 2));
$x = $cl->read_file("./var/tmp/scriptcounter");
@lines = split(/\n/, $x);
diag(sprintf "script was called %d times", scalar(@lines));
ok(@lines == 9);
