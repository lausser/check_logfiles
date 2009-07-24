#!/usr/bin/perl -w
#
# ~/check_logfiles/test/080configdir.t
#
#  like 011searches. Two configfiles with overlapping tags
#

use strict;
use Test::More tests => 8;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

if ($^O =~ /MSWin/) {
system ('rd .\etc\etc');
system ('md etc\etc');
system ('DEL /Q /S /F .\var\tmp\*');
} else {
system ("mkdir -p etc/etc");
system ("rm -rf etc/etc/*");
system ("rm -rf var/tmp/*");
}

my $configfile =<<EOCFG;
		\$options = "supersmartpostscript";
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
  \$postscript = sub {
  	printf "uiuiuiuiuiui\\n";
  	return 2;
  };
EOCFG

open CCC, ">./etc/etc/001searches.cfg";
print CCC $configfile;
close CCC;

$configfile =<<EOCFG;
        \$options = "supersmartpostscript";
        \$seekfilesdir = "./var/tmp";
        \@searches = (
            {
              # this is a patch for the user8-version
              tag => "ssh",
              logfile => "./var/adm/messages",
              criticalpatterns => "Failed password for invalid user18",
              warningpatterns => "Unknown user",
              options => "perfdata,nologfilenocry"
            },
            {
              tag => "rulzn",
              logfile => "./var/adm/messages",
              logfile => "./var/adm/messages",
              criticalpatterns => "Failed password for invalid user ruhland",
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
  \$postscript = sub {
  	printf "oioioioioioioi %s | %s\\n",
  	    \$ENV{CHECK_LOGFILES_SERVICEOUTPUT},
  	    \$ENV{CHECK_LOGFILES_SERVICEPERFDATA};
  	return \$ENV{CHECK_LOGFILES_SERVICESTATEID}; 
  };
EOCFG

open CCC, ">./etc/etc/002searches.cfg";
print CCC $configfile;
close CCC;
my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => ["./etc/etc/001searches.cfg", "./etc/etc/002searches.cfg"], selectedsearches => ['ssh', 'null', 'rulzn'] });

# ssh null rulzn postscript
diag("================================================================");
diag("reset run");
ok(scalar @{$cl->{searches}} == 4);
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
#my $test = $cl->get_search_by_tag("test");
#$test->delete_logfile();
#$test->delete_seekfile();
#$test->trace("deleted logfile and seekfile");
my $null = $cl->get_search_by_tag("null");
$null->delete_logfile();
$null->delete_seekfile();
$null->trace("deleted logfile and seekfile");
my $rulzn = $cl->get_search_by_tag("rulzn");
$rulzn->delete_logfile();
$rulzn->delete_seekfile();
$rulzn->trace("deleted logfile and seekfile");
printf "%s\n", Data::Dumper::Dumper($cl->{allerrors});
$cl->run();
diag($cl->has_result());
printf "%s\n", Data::Dumper::Dumper($cl->{allerrors});
diag($cl->{exitmessage});
ok($cl->expect_result(1, 0, 0, 0, 0)); # 1ok kommt vom postscript


$ssh->trace("==== 3-4 ====");
diag("================================================================");
diag("3 - 4");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 2);
$ssh->logger(undef, undef, 20, "Failed password for invalid user8");
$ssh->logger(undef, undef, 2, "Failed password for invalid user18");
$ssh->loggercrap(undef, undef, 2);
# ssh logs instead of test
$ssh->loggercrap(undef, undef, 2);
$ssh->logger(undef, undef, 2, "Failed password for invalid user9");
$ssh->loggercrap(undef, undef, 2);
$null->loggercrap(undef, undef, 2);
$null->logger(undef, undef, 2, "Failed password is nonsense");
$null->loggercrap(undef, undef, 2);
printf "calling run for 3, 4\n";
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2)); # 1 statt 4 wegen postscript (das resettet)
ok($cl->{exitmessage} =~ /.*CRITICAL - \(4 errors.* Failed password is nonsense /);


$ssh->trace("==== 5 - 6 ====");
diag("================================================================");
diag("5 - 6");
sleep 1;
$cl->reset();
$ssh->loggercrap(undef, undef, 20);
$rulzn->logger(undef, undef, 3, "Failed password for invalid user ruhland");
$ssh->logger(undef, undef, 30, "Failed password for invalid user8");
$ssh->logger(undef, undef, 3, "Failed password for invalid user18");
$ssh->loggercrap(undef, undef, 20);
# ssh logs instead of test
$ssh->loggercrap(undef, undef, 20);
$ssh->logger(undef, undef, 200, "Failed password for invalid user9");
$ssh->loggercrap(undef, undef, 20);
$null->loggercrap(undef, undef, 20);
$null->logger(undef, undef, 4, "Failed password is nonsense");
$null->loggercrap(undef, undef, 20);

my $command = sprintf 'perl ../plugins-scripts/check_logfiles -F ./etc/etc --searches=ssh,null,rulzn';

$ssh->trace("executing %s", $command);
my $output = `$command`;
diag($output);
diag("done");
diag($? >> 8);
ok(($? >> 8) == 2);
ok($output =~ /CRITICAL - \(10 errors .* Failed password is nonsense /);


$ssh->trace("==== 7 ====");
diag("================================================================");
diag("7 - ");
#
## 1 main configfile
#  etc/etc is a directory for many patch files
#  define test ssh in main
#  define ssh again in 001patch 002patch
##
if ($^O =~ /MSWin/) {
system ('rd /Q /S .\etc\etc');
system ('md etc\etc');
system ('DEL /Q /S /F etc\searches.cfg');
} else {
system ("rm -rf etc/etc/*");
system ("rm -f etc/searches.cfg");
}

$configfile =<<EOCFG;
        \$options = "supersmartpostscript";
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
  \$postscript = sub {
        printf "uiuiuiuiuiui\\n";
        return 2;
  };
EOCFG

open CCC, ">./etc/searches.cfg";
print CCC $configfile;
close CCC;

$configfile =<<EOCFG;
        \$options = "supersmartpostscript";
        \$seekfilesdir = "./var/tmp";
        \@searches = (
            {
              tag => "ssh",
              logfile => "./var/adm/messages",
              criticalpatterns => "Failed password for invalid user81",
              warningpatterns => "Unknown user",
              options => "perfdata,nologfilenocry"
            },
  );
  \$postscript = sub {
    printf "hundsglump varreckts nommol!!! %s | %s\\n",
    \$ENV{CHECK_LOGFILES_SERVICEOUTPUT},
    \$ENV{CHECK_LOGFILES_SERVICEPERFDATA};
    return \$ENV{CHECK_LOGFILES_SERVICESTATEID}; 
  };
EOCFG

open CCC, ">./etc/etc/001patch.cfg";
print CCC $configfile;
close CCC;

$configfile =<<EOCFG;
        \$options = "supersmartpostscript";
        \$seekfilesdir = "./var/tmp";
        \@searches = (
            {
              tag => "ssh",
              logfile => "./var/adm/messages",
              criticalpatterns => "Failed password for invalid user723",
              warningpatterns => "Unknown user",
              warningexceptions => ['Unknown user hiasl'],
              options => "perfdata,nologfilenocry"
            },
  );
  \$postscript = sub {
  	printf "hundsglump varreckts!!! %s | %s\\n",
  	    \$ENV{CHECK_LOGFILES_SERVICEOUTPUT},
  	    \$ENV{CHECK_LOGFILES_SERVICEPERFDATA};
  	return \$ENV{CHECK_LOGFILES_SERVICESTATEID}; 
  };
EOCFG

open CCC, ">./etc/etc/002patch.cfg";
print CCC $configfile;
close CCC;

sleep 10;
$cl->reset();
$ssh->loggercrap(undef, undef, 20);
$ssh->logger(undef, undef, 30, "Failed password for invalid user8");
$ssh->logger(undef, undef, 3, "Failed password for invalid user81");
$ssh->logger(undef, undef, 3, "Unknown user oash");
$ssh->logger(undef, undef, 3, "Unknown user hiasl");
$ssh->loggercrap(undef, undef, 20);
# ssh logs instead of test
$ssh->loggercrap(undef, undef, 20);
$ssh->logger(undef, undef, 200, "Failed password for invalid user9");
$ssh->loggercrap(undef, undef, 20);
$null->loggercrap(undef, undef, 20);
$null->logger(undef, undef, 4, "Failed password is nonsense");
$null->loggercrap(undef, undef, 20);

# 3 warnings wg unknown user oash
# criticals sind nicht betroffen user723 taucht nirgends auf.
# 4 wegen null: nonsense
#
$command = sprintf 'perl ../plugins-scripts/check_logfiles -f ./etc/searches.cfg -F ./etc/etc --searches=ssh,null,rulzn';

$ssh->trace("executing %s", $command);
$output = `$command`;
diag($output);
diag($? >> 8);
ok(($? >> 8) == 2);
ok($output =~ /CRITICAL - \(4 errors, 3 warnings .* Failed password is nonsense /);

exit;

sleep 1;

diag("now with only a file again");
$cl->reset();
$ssh->loggercrap(undef, undef, 20);
$ssh->logger(undef, undef, 30, "Failed password for invalid user8");
$ssh->logger(undef, undef, 3, "Failed password for invalid user81");
$ssh->logger(undef, undef, 3, "Unknown user oash");
$ssh->loggercrap(undef, undef, 20);
# ssh logs instead of test
$ssh->loggercrap(undef, undef, 20);
$ssh->logger(undef, undef, 200, "Failed password for invalid user9");
$ssh->loggercrap(undef, undef, 20);
$null->loggercrap(undef, undef, 20);
#$null->logger(undef, undef, 4, "Failed password is nonsense");
$null->loggercrap(undef, undef, 20);

# 30 crit wg user8
# 3  crit wg user 81
# 3 warn wgg unkn oash
# criticals sind nicht betroffen
#
$command = sprintf 'perl ../plugins-scripts/check_logfiles -f ./etc/searches.cfg --searches=ssh,null,rulzn';

$ssh->trace("executing %s", $command);
diag ("=====================================");
diag ("=====================================");
diag ("=====================================");
$output = `$command`;
diag($output);
diag($? >> 8);
ok(($? >> 8) == 2);
ok($output =~ /CRITICAL - \(30 errors .* Failed password is nonsense /);

