#!/usr/bin/perl -w
#
# ~/check_logfiles/test/009simplemacros.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 12;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use Net::Domain qw(hostname hostdomain hostfqdn);
use Socket;
use constant TESTDIR => ".";

#
# some macros in patterns
# some search specific macros
# a dynamically named logfile
# test also an external config file
#
#
my $cl = Nagios::CheckLogfiles::Test->new({
	protocolsdir => TESTDIR."/var/tmp",
	seekfilesdir => TESTDIR."/var/tmp",
	macros => { CL_VG00 => '/dev/vg00', CL_VG => '/dev/vg' },
	searches => [
	    {
	      tag => "lvm",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => ["SCSI errors",
	          'the ipaddress macro: $CL_IPADDRESS$',
	          'the hostname macro: $CL_HOSTNAME$',
	          'the domain macro: $CL_DOMAIN$',
	          'the fqdn macro: $CL_FQDN$',
	          'the servicedesc macro: $CL_SERVICEDESC$',
	          'the year macro: $CL_DATE_YYYY$',
	          'the 2year macro: $CL_DATE_YY$',
	          'the month macro: $CL_DATE_MM$',
	      ],
	      warningpatterns => ["mpio: disk .* disappeared", "mpio: no light"],
	      criticalexceptions => '$CL_VG00$'
	    }
	]    });
my $lvm = $cl->get_search_by_tag("lvm");
$lvm->delete_logfile();
$lvm->delete_seekfile();
$lvm->trace("deleted logfile and seekfile");

# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$lvm->logger(undef, undef, 2, "Failed password for invalid user1...");
$lvm->logger(undef, undef, 200, "SCSI errors at device /dev/vg00");
sleep 1;
$lvm->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find the two criticals
$cl->reset();
$lvm->loggercrap(undef, undef, 100);
$lvm->logger(undef, undef, 2, "SCSI errors at device /dev/vg00");
$lvm->logger(undef, undef, 2, "mpio: no light");
$lvm->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 0, 0, 1));

# now find the two criticals and the two warnings
$cl->reset();
$lvm->loggercrap(undef, undef, 100);
$lvm->logger(undef, undef, 20, "SCSI errors at device /dev/vg00");
$lvm->logger(undef, undef, 2, "mpio: no light");
$lvm->logger(undef, undef, 20, "SCSI errors at device /dev/vg01");
$lvm->logger(undef, undef, 20, "SCSI errors at device /dev/vg04");
$lvm->loggercrap(undef, undef, 100);
$lvm->logger(undef, undef, 2, "SCSI errors at device /dev/vg01");
$lvm->logger(undef, undef, 20, "SCSI errors at device /dev/vg00");
$lvm->logger(undef, undef, 2, "mpio: no light");
$lvm->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 4, 42, 0, 2));

# now find our ip-address
$lvm->trace("==== 4 ====");
$cl->reset();
$lvm->loggercrap(undef, undef, 100);
diag(sprintf "setting ip address to %s", inet_ntoa(scalar gethostbyname(hostname())));
$lvm->logger(undef, undef, 2, sprintf "the hostname macro: %s", hostname());
$lvm->logger(undef, undef, 2, sprintf "the domain macro: %s", hostdomain());
$lvm->logger(undef, undef, 2, sprintf "the fqdn macro: %s", hostfqdn());
$lvm->logger(undef, undef, 2, sprintf "the ipaddress macro: %s", inet_ntoa(scalar gethostbyname(hostname())));
$lvm->logger(undef, undef, 2, sprintf "the servicedesc macro: %s", $cl->{cfgbase});
my($sec, $min, $hour, $mday, $mon, $year) = (localtime)[0, 1, 2, 3, 4, 5];
$lvm->logger(undef, undef, 2, sprintf "the year macro: %s", $year + 1900);
$lvm->logger(undef, undef, 2, sprintf "the 2year macro: %02s", $year - 100);
$lvm->logger(undef, undef, 2, sprintf "the month macro: %s", sprintf "%02d", $mon + 1);
$lvm->logger(undef, undef, 2, "mpio: no light");
$lvm->loggercrap(undef, undef, 100);
sleep 1;
system("ls -li ./var/adm/messages");
$cl->run();
$lvm->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 16, 0, 2));


$cl->trace("-----------------------phase2-----------------------");
my $configfile = <<EOCFG;
	\$protocolsdir = TESTDIR."/var/tmp";
	\$seekfilesdir = TESTDIR."/var/tmp";
	\@searches =(
	    {
	      tag => "lvm",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => ['the username macro: \$CL_USERNAME\$'],
	    }
	);
EOCFG
my $testdir = TESTDIR;
$configfile =~ s/TESTDIR/"$testdir"/g;
unlink "./etc/check_action.cfg" if -f "./etc/check_action.cfg";
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;
my $username = scalar getpwuid $>;
if ($^O =~ /(cygwin|MSWin)/ && $username =~ /(\w+)\+(\w+)/) {
  # hostname+username
  $username = $2;
}
diag("i am user $username");
$cl = Nagios::CheckLogfiles::Test->new({ cfgfile => './etc/check_action.cfg'});
$lvm = $cl->get_search_by_tag("lvm");
$cl->reset();
$lvm->logger(undef, undef, 2, "SCSI errors at device /dev/vg00");
sleep 1;
$lvm->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$cl->reset();
$lvm->loggercrap(undef, undef, 10);
$lvm->logger(undef, undef, 1, "the username macro: $username hohoho");
$lvm->loggercrap(undef, undef, 10);
sleep 1;
system("ls -li ./var/adm/messages");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));

$cl->trace("-----------------------phase3-----------------------");
diag("check macros in prescript");
$configfile = <<EOCFG;
\$prescript = sub {
  printf "i am user %s\\n", \$ENV{CHECK_LOGFILES_USERNAME};
  return 2;
};
\$options = "supersmartprescript";
        \$protocolsdir = TESTDIR."/var/tmp";
        \$seekfilesdir = TESTDIR."/var/tmp";
        \@searches =(
            {
              tag => "lvm",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => ['the username macro: \$CL_USERNAME\$'],
            }
        );
EOCFG
$testdir = TESTDIR;
$configfile =~ s/TESTDIR/"$testdir"/g;
unlink "./etc/check_action.cfg" if -f "./etc/check_action.cfg";
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;
$username = scalar getpwuid $>;
if ($^O =~ /(cygwin|MSWin)/ && $username =~ /(\w+)\+(\w+)/) {
  # hostname+username
  $username = $2;
}
diag("i am user $username");
$cl = Nagios::CheckLogfiles::Test->new({ cfgfile => './etc/check_action.cfg'});
$lvm = $cl->get_search_by_tag("lvm");
$cl->reset();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->{exitmessage} =~ /i am user $username/); # prescript sees macros
ok($cl->expect_result(0, 0, 1, 0, 2));

diag("check macros in postscript");
$configfile = <<EOCFG;
\$postscript = sub {
  printf "i am service %s\\n", \$ENV{CHECK_LOGFILES_SERVICEDESC};
  return 2;
};
\$options = "supersmartpostscript";
        \$protocolsdir = TESTDIR."/var/tmp";
        \$seekfilesdir = TESTDIR."/var/tmp";
        \@searches =(
            {
              tag => "lvm",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => ['the username macro: \$CL_USERNAME\$'],
            }
        );
EOCFG
$testdir = TESTDIR;
$configfile =~ s/TESTDIR/"$testdir"/g;
unlink "./etc/check_action.cfg" if -f "./etc/check_action.cfg";
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;
$cl = Nagios::CheckLogfiles::Test->new({ cfgfile => './etc/check_action.cfg'});
$lvm = $cl->get_search_by_tag("lvm");
$cl->reset();
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->{exitmessage} =~ /i am service check_action/); # postscript sees macros
ok($cl->expect_result(0, 0, 1, 0, 2));

diag("check macros in smartscript");
$configfile = <<EOCFG;
\$options = "";   #!!!!!!!!!!!!!!!!!!!!!! fehlt das, dann wird automatisch supersmartpostscript gesetzt, warum auch immer
        \$protocolsdir = TESTDIR."/var/tmp";
        \$seekfilesdir = TESTDIR."/var/tmp";
        \@searches =(
            {
              tag => "lvm",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => ['the username macro: \$CL_USERNAME\$'],
              options => 'supersmartscript',
              script => sub {
                printf "i send my hit via nsca and i use the desc %s\\n", 
                    \$ENV{CHECK_LOGFILES_NSCA_SERVICEDESC};
                return 2;
              },
            }
        );
EOCFG
$testdir = TESTDIR;
$configfile =~ s/TESTDIR/"$testdir"/g;
diag("./etc/check_action.cfg exists") if -f "./etc/check_action.cfg";
unlink "./etc/check_action.cfg" if -f "./etc/check_action.cfg";
diag("./etc/check_action.cfg deleted") if ! -f "./etc/check_action.cfg";
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;
$cl = undef;
$lvm = undef;
$cl = Nagios::CheckLogfiles::Test->new({ cfgfile => './etc/check_action.cfg'});
$lvm = $cl->get_search_by_tag("lvm");
$cl->reset();
$lvm->loggercrap(undef, undef, 10);
$lvm->logger(undef, undef, 1, "the username macro: $username hohoho");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->{exitmessage} =~ /i send my hit via nsca and i use the desc check_action/); # script sees macros
ok($cl->expect_result(0, 0, 1, 0, 2));

