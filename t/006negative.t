#!/usr/bin/perl -w
#
# ~/check_logfiles/test/005negative.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 6;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "rsync",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => [ 
              '.*connection unexpectedly closed.*', 
              '.*rsync error.*', 
              'rsync:.*', 
              '!.*DEBUT.*', 
              '!.*FIN.*', 
              '!.*building file list.*', 
              '!.*files to consider.*', 
              '!.*sent .* bytes\s+received .* bytes\s+.* bytes/sec.*', 
              '!.*total size is .* \s+speedup is .*' 
          ], 
          warningpatterns => [ 
              '.*total size is 0 .*', 
              '.*sent 0 bytes.*', 
              '.*received 0 bytes.*' 
          ],
	    }
	]    });
$Data::Dumper::Indent = 1;
#printf "%s\n", Data::Dumper::Dumper($cl);
my $rsync = $cl->get_search_by_tag("rsync");
$cl->reset();
$rsync->delete_logfile();
$rsync->delete_seekfile();
diag("deleted logfile and seekfile");
$rsync->trace("deleted logfile and seekfile");
$rsync->logger(undef, undef, 1, "Failed password for invalid user1...");
diag("wrote 1 message");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 6, 0, 2));

$cl->reset();
$rsync->delete_logfile();
$rsync->delete_seekfile();
$rsync->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
$rsync->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 6, 0, 2));

$cl->reset();
$rsync->loggercrap(undef, undef, 100);
$rsync->logger(undef, undef, 1, "Ici le DEBUT ");
$rsync->loggercrap(undef, undef, 100);
$rsync->logger(undef, undef, 4, "there was an rsync error");
$rsync->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
$rsync->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 8, 0, 2));

# backup working perfectly
$cl->reset();
$rsync->loggercrap(undef, undef, 100);
$rsync->logger(undef, undef, 1, "DEBUT du backup");
$rsync->loggercrap(undef, undef, 100);
$rsync->logger(undef, undef, 1, "building file list ... done");
$rsync->loggercrap(undef, undef, 100);
$rsync->logger(undef, undef, 1, "files to consider:...");
$rsync->logger(undef, undef, 1, "file file file");
$rsync->logger(undef, undef, 1, "sent 871 bytes  received 26 bytes  163.09 bytes/sec");
$rsync->loggercrap(undef, undef, 100);
$rsync->logger(undef, undef, 1, "total size is 30053  speedup is 33.50");
$rsync->loggercrap(undef, undef, 100);
$rsync->logger(undef, undef, 1, "FIN du backup");
sleep 1;
$cl->run();
$rsync->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# backup with warning
$cl->reset();
$rsync->loggercrap(undef, undef, 100);
$rsync->logger(undef, undef, 1, "DEBUT du backup");
$rsync->loggercrap(undef, undef, 100);
$rsync->logger(undef, undef, 1, "building file list ... done");
$rsync->logger(undef, undef, 1, "files to consider:...");
$rsync->loggercrap(undef, undef, 100);
$rsync->logger(undef, undef, 1, "file file file");
$rsync->logger(undef, undef, 1, "sent 0 bytes  received 0 bytes  0 bytes/sec");
$rsync->loggercrap(undef, undef, 100);
$rsync->logger(undef, undef, 1, "total size is 0  speedup is 0");
$rsync->loggercrap(undef, undef, 100);
$rsync->logger(undef, undef, 1, "FIN du backup");
$rsync->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
$rsync->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 3, 0, 0, 1));

#backup did not run at all
$cl->reset();
sleep 1;
$cl->run();
$rsync->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 6, 0, 2));

