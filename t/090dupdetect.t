#!/usr/bin/perl -w
#
# ~/check_logfiles/test/090dupdetect.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 6;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $configfile = <<EOCFG;
\$protocolsdir = "./var/tmp";
\$seekfilesdir = "./var/tmp";
\$options = "outputhitcount";
\@searches = ({
  tag => "ssh",
  logfile => "./var/adm/messages",
  criticalpatterns => "Failed password",
  warningpatterns => "Unknown user",
});

EOCFG
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_action.cfg" });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

$cl->reset();
$ssh->loggercrap(undef, undef, 10);
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

$cl->reset();
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));
ok($cl->{exitmessage} =~ /CRITICAL - \(2 errors, 2 warnings.* - \w{3}\s+\d+ \d{2}:\d{2}:\d{2}.*Failed.*user4/);

unlink("./etc/check_action.cfg");
$configfile = <<EOCFG;
\$protocolsdir = "./var/tmp";
\$seekfilesdir = "./var/tmp";
\$options = "nooutputhitcount";
\@searches = ({
  tag => "ssh",
  logfile => "./var/adm/messages",
  criticalpatterns => "Failed password",
  warningpatterns => "Unknown user",
});

EOCFG
sleep 1;
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;
my $cl2 = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_action.cfg" });
$cl2->set_option("outputhitcount", 0);
$ssh = $cl2->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

$cl2->reset();
$ssh->loggercrap(undef, undef, 10);
$cl2->run();
diag($cl2->has_result());
diag($cl2->{exitmessage});
ok($cl2->expect_result(0, 0, 0, 0, 0));

$cl2->reset();
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Failed password for invalid user4");
$ssh->loggercrap(undef, undef, 10);
$ssh->logger(undef, undef, 2, "Unknown user sepp");
$ssh->loggercrap(undef, undef, 10);
sleep 1;
$cl2->run();
diag($cl2->has_result());
diag($cl2->{exitmessage});
ok($cl2->expect_result(0, 2, 2, 0, 2));
ok($cl2->{exitmessage} =~ /CRITICAL - \w{3}\s+\d+ \d{2}:\d{2}:\d{2}.*Failed.*user4/);

exit;

##### nochmal mit dupdetect ohne zahlen
diag($cl2->{exitmessage});


