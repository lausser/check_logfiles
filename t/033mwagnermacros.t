#!/usr/bin/perl -w
#
# ~/check_logfiles/test/033wagnermacros.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 3;
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
	seekfilesdir => TESTDIR."/var/tmp",
	macros => { CL_VG00 => '/dev/vg00', CL_VG => '/dev/vg' },
	searches => [
	    {
              tag => 'Maestro',
              logfile => '/tmp/mytest/out.log',
              criticalpatterns => ['exception'],
              options => 'script,nocase',
              script => 'nagmsg',
              scriptparams => '-n chaos -m $CL_TAG$ -s warning -t "$CL_SERVICEOUTPUT$"',
            },
            {
              tag => 'BACKUP',
              logfile => '/tmp/mytest/ou',
              rotation => '.*out\d.log',
              type => 'rotating::uniform',
              criticalpatterns => ['gaga','markus'],
              options => 'script,nocase',
              script => 'nagmsg',
              scriptparams => '-n chaos -m $CL_TAG$ -s critical -t "$CL_SERVICEOUTPUT$"',
            },
	]
});
my $maestro = $cl->get_search_by_tag("Maestro");
my $backup = $cl->get_search_by_tag("BACKUP");
$maestro->delete_logfile();
$maestro->delete_seekfile();
$backup->delete_logfile();
$backup->delete_seekfile();

ok($maestro->{tag} eq $maestro->{macros}->{CL_TAG});
ok($backup->{tag} eq $backup->{macros}->{CL_TAG});

my $scriptparams = $backup->{scriptparams};
$backup->resolve_macros(\$scriptparams);
diag($scriptparams);
ok($scriptparams eq '-n chaos -m BACKUP -s critical -t "$CL_SERVICEOUTPUT$"');
