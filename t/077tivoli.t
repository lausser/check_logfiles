#!/usr/bin/perl -w
#
# ~/check_logfiles/test/001simple.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 14;
use Cwd;
use lib "../plugins-scripts";
use Nagios::Tivoli::Config::Logfile;
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


#my $tivoli = Nagios::Tivoli::Config::Logfile->new({
#  formatfile => ["./etc/syslog_enh_logfile_linux.fmt2"],
#});


my @privatestates = ();

if ($^O =~ /MSWin/) {
 -f 'etc/tivoli.cfg' && system ('DEL /Q /S /F .\etc\tivoli.cfg');
} else {
 -f 'etc/tivoli.cfg' && system ("rm -rf etc/tivoli.cfg");
}
my $configfile =<<EOCFG;
        \$protocolsdir = "./var/tmp";
        \$seekfilesdir = "./var/tmp";
        \@searches = (
            {
              tag => "tivtest",
              logfile => "./var/adm/messages",
              tivolipatterns => ["./etc/syslog_enh_logfile_linux.fmt"],
              #tivolipatterns => ["./etc/syslog_enh_logfile_linux.fmt2"],
              options => "supersmartscript",
              script => sub {
                \$tivoli = \$CHECK_LOGFILES_PRIVATESTATE->{tivolimatch};
                if (\$tivoli->{format_name} ne "NO MATCHING RULE") {
                  printf "%s", \$CHECK_LOGFILES_PRIVATESTATE->{tivolimatch}->{subject};
                  return \$tivoli->{exit_code};
                } else {
                  printf "%s", \$ENV{CHECK_LOGFILES_SERVICEOUTPUT};
                  return 2;
                }
              }
            }
        );
EOCFG

open CCC, ">./etc/tivoli.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/tivoli.cfg"});
my $tivtest = $cl->get_search_by_tag("tivtest");
$tivtest->delete_logfile();
$tivtest->delete_seekfile();
$tivtest->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$tivtest->trace("initial run");
$tivtest->logger(undef, undef, 1, "start tivoli testing");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

my @examples = (
'gateway1 Server Administrator: Instrumentation Service EventID: 1354  Power supply detected a failure  Sensor location: PS 2 Status   Chassis location: Main System Chassis  Previous state was: Unknown  Power Supply type: AC  Power Supply state: Presence detected, Failure detected, AC lost',
'gateway1 Server Administrator: Instrumentation Service EventID: 1012  IPMI status  Interface: OS',
'gateway1 Server Administrator: Instrumentation Service EventID: 1001  Server Administrator startup complete',
'gateway1 Server Administrator: Storage Service EventID: 2164  See readme.txt for a list of validated controller driver versions.',
'gateway1 Server Administrator: Instrumentation Service EventID: 1000  Server Administrator starting',
'gateway1 Server Administrator: Instrumentation Service EventID: 1306  Redundancy lost  Redundancy unit: BMC PS Redundancy  Chassis location: Main System Chassis  Previous redundancy state was: Unknown',
'gateway1 Server Administrator: Instrumentation Service EventID: 1354  Power supply detected a failure  Sensor location: PS 2 Status   Chassis location: Main System Chassis  Previous state was: Unknown  Power Supply type: AC  Power Supply state: Presence detected, Failure detected, AC lost',
'gateway1 Server Administrator: Instrumentation Service EventID: 1012  IPMI status  Interface: OS',
'gateway1 Server Administrator: Instrumentation Service EventID: 1001  Server Administrator startup complete',
'gateway1 Server Administrator: Storage Service EventID: 2164  See readme.txt for a list of validated controller driver versions.',
'gateway1 Server Administrator: Instrumentation Service EventID: 1000  Server Administrator starting',
'gateway1 Server Administrator: Instrumentation Service EventID: 1306  Redundancy lost  Redundancy unit: BMC PS Redundancy  Chassis location: Main System Chassis  Previous redundancy state was: Unknown',
'gateway1 Server Administrator: Instrumentation Service EventID: 1354  Power supply detected a failure  Sensor location: PS 2 Status   Chassis location: Main System Chassis  Previous state was: Unknown  Power Supply type: AC  Power Supply state: Presence detected, Failure detected, AC lost',
'gateway1 Server Administrator: Instrumentation Service EventID: 1012  IPMI status  Interface: OS',
'gateway1 Server Administrator: Instrumentation Service EventID: 1001  Server Administrator startup complete',
'gateway1 Server Administrator: Storage Service EventID: 2164  See readme.txt for a list of validated controller driver versions.',
'gateway1 Server Administrator: Instrumentation Service EventID: 1053  Temperature sensor detected a warning value  Sensor location: BMC Ambient Temp  Chassis location: Main System Chassis  Previous state was: OK (Normal)  Temperature sensor value (in Degrees Celsius): 21.0',
'gateway1 Server Administrator: Instrumentation Service EventID: 1052  Temperature sensor returned to a normal value  Sensor location: BMC Ambient Temp  Chassis location: Main System Chassis  Previous state was: Non-Critical (Warning)  Temperature sensor value (in Degrees Celsius): 20.0'
);

$tivtest->trace(sprintf "+----------------------- test %d ------------------", 1);

# MINOR/1 Log_Linux_HW_Dell_Error
# %t %s Server Administrator: %s Service EventID: %s4 %s*
# -V3 $3
# -V4 $4
# -V5 $5
# silo PRINTF("%s4", V4)
# msg PRINTF("%s Service EventID: %s4 %s", V3, V4, V5)
# severity MINOR
# END

# FORMAT *DISCARD*
# %t %s Server Administrator: Storage Service EventID: %s*
#END

$tivtest->logger('dellsrv', 'Server Administrator:', 1, "Storage Service EventID: 1004 on PE 1850");
# -V3 Storage
# -V4 100
# -V5 on PE 1850
# silo PRINTF("%s4", V4) = 1004
# msg PRINTF("%s Service EventID: %s4 %s", V3, V4, V5)
# = Storage Service EventID: 1004 on PE 1850
# fliegt aber raus wg discard

# deshalb nochmal aber ohne Storage
$tivtest->logger('dellsrv', 'Server Administrator:', 1, "Power Service EventID: 1004 on PE 1850");
# = Power Service EventID: 1004 on PE 1850

# DISCARD* (Log_Linux_HW_Dell_Error)
# %t %s Server Administrator: %s Service EventID: 1304 %s*
$tivtest->logger('dellsrv', 'Server Administrator:', 1, "Storage Service EventID: 1304 on PE 1850");

# FORMAT Logfile_Base
# %t %s %s*
# hostname LABEL
# adapter_host LABEL
# date $1
# origin $2
# msg $3
# END

# FORMAT Log_Linux_HW_Serverview FOLLOWS Logfile_Base
# %t %s ServerView RAID: [0013][%s] %s*
# id 0013
# msg $4
# severity CRITICAL
# END

# CRITICAL/2 Log_Linux_HW_Serverview FOLLOWS Logfile_Base
# %t %s ServerView RAID: [0013][%s] %s*
$tivtest->logger("fjssrv", "ServerView RAID:", 1,"[0013][IO_ERR] io timeout"); 
# io timeout

# MINOR/1 Log_Unix_ClusterStatus
# FORMAT Log_Unix_ClusterStatus FOLLOWS Logfile_Base
# %t %s %s CLUSTERSTATUS %s*
# -V3 $3
# -V4 $4
# msg PRINTF("%s CLUSTERSTATUS %s", V3, V4)
# severity MINOR
# END

$tivtest->logger('fjssrv', 'hacluster', 1, "CLUSTERSTATUS no response from cluster peer");
# hacluster CLUSTERSTATUS no response from cluster peer


# CRITICAL/2 Log_Unix_ClusterStatus
# FORMAT Log_Unix_ClusterStatus FOLLOWS Logfile_Base
# %t %s %s CLUSTERSTATUS %s* is in faulted or inconsistent state !
# -V3 $3
# -V4 $4
# msg PRINTF("%s CLUSTERSTATUS %s is in faulted or inconsistent state !", V3, V4)
# severity CRITICAL
# END

# %t %s %s CLUSTERSTATUS %s* is in faulted or inconsistent state !
$tivtest->logger('fjssrv', 'hacluster', 1, "CLUSTERSTATUS cluster forsc is in faulted or inconsistent state !");
# hacluster CLUSTERSTATUS cluster forsc  is in faulted or inconsistent state !

#$tivtest->loggercrap(undef, undef, 100);
sleep 1;
$tivtest->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 2, 2, 0, 2));




# 2 now find the two criticals
$tivtest->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
#$tivtest->loggercrap(undef, undef, 10);
# MINOR
$tivtest->logger('srvxy', 'Server Administrator:', 2, "Screen Service EventID: 113 screen is black");
# Screen Service EventID: 113 screen is black
# CRITICAL
$tivtest->logger('srvxy', "ServerView RAID:", 2, "[0426][MIRR_KAPUTT] mirror broken"); 
# mirror broken
# MINOR
$tivtest->logger('srvxy', "ServerView RAID:", 1, "Drive Array Device Failure battery low");
# ServerView RAID: Drive Array Device Failure battery low
#$tivtest->loggercrap(undef, undef, 10);

sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 3, 2, 0, 2));

ok (${$tivtest->{matchlines}->{WARNING}}[0]->[1] eq "Screen Service EventID: 113 screen is black");
ok (${$tivtest->{matchlines}->{WARNING}}[1]->[1] eq "Screen Service EventID: 113 screen is black");
ok (${$tivtest->{matchlines}->{CRITICAL}}[0]->[1] eq "Raid kaputt: mirror broken"); # 6
ok (${$tivtest->{matchlines}->{CRITICAL}}[1]->[1] eq "Raid kaputt: mirror broken");
ok (${$tivtest->{matchlines}->{WARNING}}[2]->[1] eq "ServerView RAID: Drive Array Device Failure battery low");

#diag(Data::Dumper::Dumper($tivtest->{matchlines}));
#diag(Data::Dumper::Dumper($tivtest->{privatestate}));
#diag(Data::Dumper::Dumper($cl->{privatestate}->{tivtest}));
#diag(Data::Dumper::Dumper($tivtest));
#diag(Data::Dumper::Dumper($cl));

diag("-----------------------");
diag("-----multiline------------------");
diag("-----------------------");
$cl->reset();
# Log_Linux_HW_GAM (silo B)
#$tivtest->loggercrap(undef, undef, 10);
#$tivtest->logger(undef, undef, 1, "SeqNo=4 ctl=0 chn=0 tgt=0 lun=0 Event= 87:MLXEV_SYSDEV_CRITICAL occurred at Fri Jun  5 12:26:47 2009 and logged at Fri Jun  5 12:26:47 2009", 1);
#$tivtest->logger(undef, undef, 1, "SeqNo=4 ctl=0 chn=0 tgt=0 lun=0 Event= B:MLYEV_SYSDEV_CRITICAL occurred at Fri Jun  5 12:27:47 2009 and logged at Fri Jun  5 12:27:47 2009", 1);
#$tivtest->logger(undef, undef, 1, "SeqNo=4 ctl=0 chn=0 tgt=0 lun=0 Event= XY:MLYEV_SYSTEM_CRITICAL occurred at Fri Jun  5 12:27:47 2009 and logged at Fri Jun  5 12:27:47 2009", 1);
$tivtest->logger(undef, undef, 1, "SeqNo=4 ctl=0 chn=0 tgt=0 lun=0 Event= 87:MLXEV_SYSDEV_CRITICAL", 1);
$tivtest->logger(undef, undef, 1, "  occurred at Fri Jun  5 12:26:47 2009 and logged at Fri Jun  5 12:26:47 2009", 1);
$tivtest->logger(undef, undef, 1, "SeqNo=8 ctl=0 chn=0 tgt=0 lun=0 Event= XY:MLXEV_SYSDEV_AECHZ", 1);
$tivtest->logger(undef, undef, 1, "  occurred at Fri Jun  5 12:28:47 2009 and logged at Fri Jun  5 12:28:47 2009", 1);
#$tivtest->loggercrap(undef, undef, 10);
#%s* Event= B:%s%n occurred at %s* and logged at %s*
# erbt msg PRINTF("%s Event= %s:%s", V1, silo, msgpart)
sleep 1;
$cl->run();
diag("now run");
#printf STDERR "%s\n", Data::Dumper::Dumper($tivtest->{matchlines});
ok(${$tivtest->{matchlines}->{WARNING}}[0]->[1] =~
    /.+ Event= 87:MLXEV_SYSDEV_CRITICAL$/);
ok(${$tivtest->{matchlines}->{WARNING}}[1]->[1] eq
    "SeqNo=8 ctl=0 chn=0 tgt=0 lun=0 Event= XY:MLXEV_SYSDEV_AECHZ");
diag($cl->has_result());
diag($cl->{exitmessage});
#diag(Data::Dumper::Dumper($tivtest->{matchlines}));
#diag(Data::Dumper::Dumper($tivtest->{privatestate}));



###################################################################
# nochmal abschnitt 1 aber mit anderem mapping
# minor => critical
# critical => critical
diag ("modify mappings");
if ($^O =~ /MSWin/) {
 -f 'etc/tivoli2.cfg' && system ('DEL /Q /S /F .\etc\tivoli2.cfg');
} else {
 -f 'etc/tivoli2.cfg' && system ("rm -rf etc/tivoli2.cfg");
}
sleep 1;

$configfile =<<EOCFG;
        \$protocolsdir = "./var/tmp";
        \$seekfilesdir = "./var/tmp";
        \@searches = (
            {
              tag => "tivtest2",
              logfile => "./var/adm/messages",
              tivolipatterns => ["./etc/syslog_enh_logfile_linux.fmt"],
              #tivolipatterns => ["./etc/syslog_enh_logfile_linux.fmt2"],
              tivolimapping => {
                minor => 2,
                warning => 2,
                critical => 2,
              },
              options => "supersmartscript",
              script => sub {
                \$tivoli = \$CHECK_LOGFILES_PRIVATESTATE->{tivolimatch};
                if (\$tivoli->{format_name} ne "NO MATCHING RULE") {
                  printf "%s", \$CHECK_LOGFILES_PRIVATESTATE->{tivolimatch}->{subject};
                  return \$tivoli->{exit_code};
                } else {
                  printf "%s", \$ENV{CHECK_LOGFILES_SERVICEOUTPUT};
                  return 2;
                }
              }
            }
        );
EOCFG

open CCC, ">./etc/tivoli2.cfg";
print CCC $configfile;
close CCC;
sleep 1;
undef $cl;
my $xcl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/tivoli2.cfg"});
$tivtest = $xcl->get_search_by_tag("tivtest2");
$tivtest->delete_logfile();
$tivtest->delete_seekfile();
$tivtest->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$tivtest->trace("initial run");
$tivtest->logger(undef, undef, 1, "start tivoli testing");
$xcl->run();
diag($xcl->has_result());
diag($xcl->{exitmessage});
ok($xcl->expect_result(0, 0, 0, 0, 0));

# MINOR/1 Log_Linux_HW_Dell_Error
# %t %s Server Administrator: %s Service EventID: %s4 %s*
# -V3 $3
# -V4 $4
# -V5 $5
# silo PRINTF("%s4", V4)
# msg PRINTF("%s Service EventID: %s4 %s", V3, V4, V5)
# severity MINOR
# END

# FORMAT *DISCARD*
# %t %s Server Administrator: Storage Service EventID: %s*
#END

$tivtest->logger('dellsrv', 'Server Administrator:', 1, "Storage Service EventID: 1004 on PE 1850");
# -V3 Storage
# -V4 100
# -V5 on PE 1850
# silo PRINTF("%s4", V4) = 1004
# msg PRINTF("%s Service EventID: %s4 %s", V3, V4, V5)
# = Storage Service EventID: 1004 on PE 1850
# fliegt aber raus wg discard

# deshalb nochmal aber ohne Storage
$tivtest->logger('dellsrv', 'Server Administrator:', 1, "Power Service EventID: 1004 on PE 1850");
# = Power Service EventID: 1004 on PE 1850

# DISCARD* (Log_Linux_HW_Dell_Error)
# %t %s Server Administrator: %s Service EventID: 1304 %s*
$tivtest->logger('dellsrv', 'Server Administrator:', 1, "Storage Service EventID: 1304 on PE 1850");

# FORMAT Logfile_Base
# %t %s %s*
# hostname LABEL
# adapter_host LABEL
# date $1
# origin $2
# msg $3
# END

# FORMAT Log_Linux_HW_Serverview FOLLOWS Logfile_Base
# %t %s ServerView RAID: [0013][%s] %s*
# id 0013
# msg $4
# severity CRITICAL
# END

# CRITICAL/2 Log_Linux_HW_Serverview FOLLOWS Logfile_Base
# %t %s ServerView RAID: [0013][%s] %s*
$tivtest->logger("fjssrv", "ServerView RAID:", 1,"[0013][IO_ERR] io timeout"); 
# io timeout

# MINOR/1 Log_Unix_ClusterStatus
# FORMAT Log_Unix_ClusterStatus FOLLOWS Logfile_Base
# %t %s %s CLUSTERSTATUS %s*
# -V3 $3
# -V4 $4
# msg PRINTF("%s CLUSTERSTATUS %s", V3, V4)
# severity MINOR
# END

$tivtest->logger('fjssrv', 'hacluster', 1, "CLUSTERSTATUS no response from cluster peer");
# hacluster CLUSTERSTATUS no response from cluster peer


# CRITICAL/2 Log_Unix_ClusterStatus
# FORMAT Log_Unix_ClusterStatus FOLLOWS Logfile_Base
# %t %s %s CLUSTERSTATUS %s* is in faulted or inconsistent state !
# -V3 $3
# -V4 $4
# msg PRINTF("%s CLUSTERSTATUS %s is in faulted or inconsistent state !", V3, V4)
# severity CRITICAL
# END

# %t %s %s CLUSTERSTATUS %s* is in faulted or inconsistent state !
$tivtest->logger('fjssrv', 'hacluster', 1, "CLUSTERSTATUS cluster forsc is in faulted or inconsistent state !");
# hacluster CLUSTERSTATUS cluster forsc  is in faulted or inconsistent state !

#$tivtest->loggercrap(undef, undef, 100);
sleep 1;
$tivtest->trace("initial run");
$xcl->run();

diag($xcl->has_result());
diag($xcl->{exitmessage});
ok($xcl->expect_result(0, 0, 4, 0, 2));




###################################################################
# nochmal aber ohne handler-script
# minor => critical
# critical => critical
diag ("no handler");
if ($^O =~ /MSWin/) {
 -f 'etc/tivoli3.cfg' && system ('DEL /Q /S /F .\etc\tivoli3.cfg');
} else {
 -f 'etc/tivoli3.cfg' && system ("rm -rf etc/tivoli3.cfg");
}
sleep 1;

$configfile =<<EOCFG;
        \$protocolsdir = "./var/tmp";
        \$seekfilesdir = "./var/tmp";
        \@searches = (
            {
              tag => "tivtest2",
              logfile => "./var/adm/messages",
              tivolipatterns => ["./etc/syslog_enh_logfile_linux.fmt"],
              tivolimapping => {
                minor => 2,
                warning => 2,
                critical => 2,
              },
            }
        );
EOCFG

open CCC, ">./etc/tivoli3.cfg";
print CCC $configfile;
close CCC;
sleep 1;
undef $cl;
my $ycl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/tivoli3.cfg"});
$tivtest = $ycl->get_search_by_tag("tivtest2");
$tivtest->delete_logfile();
$tivtest->delete_seekfile();
$tivtest->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$tivtest->trace("initial run");
$tivtest->logger(undef, undef, 1, "start tivoli testing");
$ycl->run();
diag($ycl->has_result());
diag($ycl->{exitmessage});
ok($ycl->expect_result(0, 0, 0, 0, 0));

# MINOR/1 Log_Linux_HW_Dell_Error
# %t %s Server Administrator: %s Service EventID: %s4 %s*
# -V3 $3
# -V4 $4
# -V5 $5
# silo PRINTF("%s4", V4)
# msg PRINTF("%s Service EventID: %s4 %s", V3, V4, V5)
# severity MINOR
# END

# FORMAT *DISCARD*
# %t %s Server Administrator: Storage Service EventID: %s*
#END

$tivtest->logger('dellsrv', 'Server Administrator:', 1, "Storage Service EventID: 1004 on PE 1850");
# -V3 Storage
# -V4 100
# -V5 on PE 1850
# silo PRINTF("%s4", V4) = 1004
# msg PRINTF("%s Service EventID: %s4 %s", V3, V4, V5)
# = Storage Service EventID: 1004 on PE 1850
# fliegt aber raus wg discard

# deshalb nochmal aber ohne Storage
$tivtest->logger('dellsrv', 'Server Administrator:', 1, "Power Service EventID: 1004 on PE 1850");
# = Power Service EventID: 1004 on PE 1850

# DISCARD* (Log_Linux_HW_Dell_Error)
# %t %s Server Administrator: %s Service EventID: 1304 %s*
$tivtest->logger('dellsrv', 'Server Administrator:', 1, "Storage Service EventID: 1304 on PE 1850");

# MINOR/1 Log_Unix_ClusterStatus
# FORMAT Log_Unix_ClusterStatus FOLLOWS Logfile_Base
# %t %s %s CLUSTERSTATUS %s*
# -V3 $3
# -V4 $4
# msg PRINTF("%s CLUSTERSTATUS %s", V3, V4)
# severity MINOR
# END

$tivtest->logger('fjssrv', 'hacluster', 1, "CLUSTERSTATUS no response from cluster peer");
# hacluster CLUSTERSTATUS no response from cluster peer


# CRITICAL/2 Log_Unix_ClusterStatus
# FORMAT Log_Unix_ClusterStatus FOLLOWS Logfile_Base
# %t %s %s CLUSTERSTATUS %s* is in faulted or inconsistent state !
# -V3 $3
# -V4 $4
# msg PRINTF("%s CLUSTERSTATUS %s is in faulted or inconsistent state !", V3, V4)
# severity CRITICAL
# END

# %t %s %s CLUSTERSTATUS %s* is in faulted or inconsistent state !
$tivtest->logger('fjssrv', 'hacluster', 1, "CLUSTERSTATUS cluster forsc is in faulted or inconsistent state !");
# hacluster CLUSTERSTATUS cluster forsc  is in faulted or inconsistent state !

# FORMAT Logfile_Base
# %t %s %s*
# hostname LABEL
# adapter_host LABEL
# date $1
# origin $2
# msg $3
# END

# FORMAT Log_Linux_HW_Serverview FOLLOWS Logfile_Base
# %t %s ServerView RAID: [0013][%s] %s*
# id 0013
# msg $4
# severity CRITICAL
# END

# CRITICAL/2 Log_Linux_HW_Serverview FOLLOWS Logfile_Base
# %t %s ServerView RAID: [0013][%s] %s*
$tivtest->logger("fjssrv", "ServerView RAID:", 1,"[0013][IO_ERR] io timeout"); 
# io timeout

$tivtest->loggercrap(undef, undef, 100);
sleep 1;
$ycl->run();
diag($ycl->has_result());
diag($ycl->{exitmessage});
ok($ycl->expect_result(0, 0, 4, 0, 2));


