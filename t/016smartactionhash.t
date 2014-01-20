#!/usr/bin/perl -w
#
# ~/check_logfiles/test/016smartactionhash.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 11;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $configfile = q!
$options =  "report=long";
$seekfilesdir = "./var/tmp";
@searches = ({
      tag => "smart",
      logfile => "./var/adm/messages",
      criticalpatterns => {
         'pat1' => '.*connection unexpectedly closed.*',
         'pat2' => '.*rsync error.*',
      },
      warningpatterns => {
         'pat1' => '.*total size is 0 .*',
      },
      options => 'supersmartscript',
      script => sub {
          my $level = lc $ENV{CHECK_LOGFILES_SERVICESTATE};
          my $output = $ENV{CHECK_LOGFILES_SERVICEOUTPUT};
          my $patnum = $ENV{CHECK_LOGFILES_PATTERN_KEY};
          printf "%s.%s.%s\n", $level, $patnum, $output;
          return $ENV{CHECK_LOGFILES_SERVICESTATEID};
      },
});
!;
open CCC, ">./etc/check_actionhash.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_actionhash.cfg" });
my $action = $cl->get_search_by_tag("smart");
$cl->reset();

$action->delete_logfile();
$action->delete_seekfile();
$action->loggercrap(undef, undef, 100);
$cl->run();


$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "i had a connection but the connection unexpectedly closed which is not good");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "empty. null. the total size is 0 and maybe even less");
#sleep 1;
$cl->run();
$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
diag($cl->{long_exitmessage});
ok($cl->expect_result(0, 1, 5, 0, 2));
my @long = split(/\n/, $cl->{long_exitmessage});
ok($long[1] =~ /critical\.pat2\..*rsync error.*/);
ok($long[2] =~ /critical\.pat2\..*rsync error.*/);
ok($long[3] =~ /critical\.pat2\..*rsync error.*/);
ok($long[4] =~ /critical\.pat2\..*rsync error.*/);
ok($long[5] =~ /critical\.pat1\..*connection unexpectedly closed.*/);
ok($long[6] =~ /warning\.pat1\..*total size is 0 .*/);


# now with patternfile
my $patternfilecontent =<<'EOF';
$criticalpatterns = {
  "pat1" => "Failed password",
  "pat2" => "Failed powersupply",
};
$warningpatterns = {
  "pat1" => "Unknown user",
};
$warningexceptions = {
  "epat1" => "Unknown user lausser",
};
EOF

$cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/adm/messages",
              patternfiles => TESTDIR."/etc/patternfile5.pat",
              criticalexceptions => "Failed password for invalid user (lausser|seppl)",
              warningpatterns => {
                  "pat2" => "Failed password for invalid user seppl",
              },
            }
        ]    });
my $ssh = $cl->get_search_by_tag("ssh");
#printf "%s\n", Data::Dumper::Dumper($ssh);
#exit;
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");

# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->logger(undef, undef, 2, "Failed password for invalid user user1...");
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find the four criticals and two warnings
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user user2");
$ssh->logger(undef, undef, 2, "Failed password for invalid user sepp");
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Unknown user hiasl");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 4, 0, 2));

# now find the four criticals and one warnings
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user user2");
$ssh->logger(undef, undef, 2, "Failed password for invalid user sepp");
$ssh->logger(undef, undef, 2, "Failed password for invalid user lausser");
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user lausser");
$ssh->logger(undef, undef, 1, "Unknown user hiasl");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 1, 4, 0, 2));

# now find the two criticals and three warnings
# user seppl will be critical, then revoked, then warning
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user user2");   #c
$ssh->logger(undef, undef, 2, "Failed password for invalid user seppl");   #c ex, w
$ssh->logger(undef, undef, 2, "Failed password for invalid user lausser"); #c ex
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 1, "Unknown user lausser");                     #w ex, w
$ssh->logger(undef, undef, 1, "Unknown user hiasl");                       #w
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 3, 2, 0, 2));

