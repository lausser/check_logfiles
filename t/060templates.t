#!/usr/bin/perl -w
#
# ~/check_logfiles/test/060templates.t
#
#  Test logfiles which will be deleted and recreated instead of rotated.
#

use strict;
use Test::More tests => 19;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $configfile =<<EOCFG;	
	\$seekfilesdir = "./var/tmp";
	\@searches = (
	    {
	      template => "outlook",
	      logfile => "./var/adm/messages",
	      criticalpatterns => "mailbox corrupt",
	      warningpatterns => "mailbox full",
	      options => 'perfdata,syslogclient=\$CL_TAG\$'
	    },
	    {
	      template => "excel",
	      logfile => "./var/adm/messages",
	      criticalpatterns => "oo file found",
	      options => 'perfdata,syslogclient=\$CL_TAG\$'
	    },
	    {
	      tag => "simple",
	      logfile => "./var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      options => "perfdata"
	    });
EOCFG

open CCC, ">./etc/templates.cfg";
print CCC $configfile;
close CCC;

$configfile =<<EOCFG;	
	\$seekfilesdir = "./var/tmp";
	\@searches = (
	    {
	      template => "outlook",
	      logfile => "./var/adm/messages",
	      criticalpatterns => "mailbox corrupt",
	      warningpatterns => "mailbox full",
	      options => 'perfdata,syslogclient=\$CL_TAG\$'
	    },
	    {
	      template => "excel",
	      logfile => "./var/adm/messages",
	      criticalpatterns => "oo file found",
	      options => 'perfdata,syslogclient=\$CL_TAG\$'
	    },
	    {
	      tag => "simple",
	      logfile => "./var/adm/messages",
	      criticalpatterns => "Failed password",
	      warningpatterns => "Unknown user",
	      options => "perfdata"
	    });
EOCFG

open CCC, ">./etc/templates2.cfg";
print CCC $configfile;
close CCC;

my $cl0815 = Nagios::CheckLogfiles::Test->new({ 
	cfgfile => "./etc/templates.cfg",
    selectedsearches => ['excel', 'outlook'],
    dynamictag => 'pc0815.muc' });
printf STDERR "%s\n", $Nagios::CheckLogfiles::ExitMsg;
#printf STDERR "%s", Data::Dumper::Dumper($cl0815);

my $cl4711 = Nagios::CheckLogfiles::Test->new({ 
	cfgfile => "./etc/templates.cfg",
    selectedsearches => ['excel', 'outlook'],
    dynamictag => 'pc4711.muc' });  
    
my $clall = Nagios::CheckLogfiles::Test->new({ 
	cfgfile => "./etc/templates.cfg",
    dynamictag => 'pc4711.muc' });  
ok(scalar(@{$clall->{searches}}) == 3);
    
my $clsimple = Nagios::CheckLogfiles::Test->new({ 
	cfgfile => "./etc/templates.cfg", });
diag(sprintf "clsimple has %d searches", scalar(@{$clsimple->{searches}}));
ok(scalar(@{$clsimple->{searches}}) == 1);

my $outlook0815 = $cl0815->get_search_by_template("outlook");
my $excel0815 = $cl0815->get_search_by_template("excel");
my $outlook4711 = $cl4711->get_search_by_template("outlook");
my $excel4711 = $cl4711->get_search_by_template("excel");

foreach my $cl ($cl0815, $cl4711, $clall, $clsimple) {
  foreach my $s (@{$cl->{searches}}) {
  	$s->delete_seekfile();
  	$s->delete_logfile();
  }
}

$cl0815->run();
$cl4711->run();
$clall->run();
$clsimple->run();

# check the creation of the right seekfiles
ok(-f "./var/tmp/templates.._var_adm_messages.outlook_pc0815.muc");
ok(-f "./var/tmp/templates.._var_adm_messages.outlook_pc4711.muc");
ok(-f "./var/tmp/templates.._var_adm_messages.excel_pc0815.muc");
ok(-f "./var/tmp/templates.._var_adm_messages.excel_pc4711.muc");
ok(-f "./var/tmp/templates.._var_adm_messages.simple");
foreach my $cl ($cl0815, $cl4711, $clall, $clsimple) {
  foreach my $s (@{$cl->{searches}}) {
  	$s->delete_seekfile();
  }
}

ok(! -f "./var/tmp/templates.._var_adm_messages.outlook_pc0815.muc");
ok(! -f "./var/tmp/templates.._var_adm_messages.outlook_pc4711.muc");
ok(! -f "./var/tmp/templates.._var_adm_messages.excel_pc0815.muc");
ok(! -f "./var/tmp/templates.._var_adm_messages.excel_pc4711.muc");

# reset counters
$cl0815->run();
$cl4711->run();
$clall->run();
$clsimple->run();

$outlook0815->logger(undef, undef, 4, "pc0815.muc: Failed password");
$outlook0815->logger(undef, undef, 2, "pc4711.muc: Failed password");
$outlook0815->logger(undef, undef, 4, "pc0815.muc: mailbox corrupt");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 4, "pc0815.muc: mailbox full");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 4, "pc04711.muc: ramsch");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 14, "pc4711.muc: mailbox full");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 4, "pc4711.muc: excel oo file found");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 4, "pc4711.muc: outlook mailbox full");
$outlook0815->loggercrap(undef, undef, 20);

$cl0815->reset();
$cl0815->run(); 
$cl4711->reset();
$cl4711->run();
$clall->reset();
$clall->run();
$clsimple->reset();
$clsimple->run();
# 4 mailb corr, 4 mailb full
diag($cl0815->has_result());
diag($cl0815->{exitmessage});
ok($cl0815->expect_result(0, 4, 4, 0, 2));
ok($cl0815->{exitmessage} =~ /CRITICAL - \(4 errors, 4 warnings\) - .* mailbox corrupt /);
diag($cl4711->has_result());
diag($cl4711->{exitmessage});
ok($cl4711->expect_result(0, 18, 4, 0, 2));
ok($cl4711->{exitmessage} =~ /CRITICAL - \(4 errors, 18 warnings\) - .* oo file .* /);
diag($clall->has_result());
diag($clall->{exitmessage});

$clall->reset();
$clall->run();
$outlook0815->logger(undef, undef, 4, "pc0815.muc: Failed password");
$outlook0815->logger(undef, undef, 2, "pc4711.muc: Failed password");
$outlook0815->logger(undef, undef, 4, "pc0815.muc: mailbox corrupt");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 4, "pc0815.muc: mailbox full");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 4, "pc4711.muc: ramsch");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 14, "pc4711.muc: mailbox full");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 7, "pc4711.muc: excel oo file found");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 5, "pc4711.muc: outlook mailbox full");
$outlook0815->loggercrap(undef, undef, 20);
$clall->reset();
$clall->run();
diag($clall->has_result());
diag($clall->{exitmessage});
ok($clall->expect_result(0, 19, 13, 0, 2));
ok($clall->{exitmessage} =~ /CRITICAL - \(13 errors, 19 warnings\) - .*4711.muc: Failed .* /);

$clsimple->reset();
$clsimple->run();
$outlook0815->logger(undef, undef, 4, "pc0815.muc: Failed password");
$outlook0815->logger(undef, undef, 2, "pc4711.muc: Failed password");
$outlook0815->logger(undef, undef, 4, "pc0815.muc: mailbox corrupt");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 4, "pc0815.muc: mailbox full");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 4, "pc4711.muc: ramsch");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 14, "pc4711.muc: mailbox full");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 7, "pc4711.muc: excel oo file found");
$outlook0815->loggercrap(undef, undef, 20);
$outlook0815->logger(undef, undef, 5, "pc4711.muc: outlook mailbox full");
$outlook0815->loggercrap(undef, undef, 20);
$clsimple->reset();
$clsimple->run();
diag($clsimple->has_result());
diag($clsimple->{exitmessage});
ok($clsimple->expect_result(0, 0, 6, 0, 2));
ok($clsimple->{exitmessage} =~ /CRITICAL - \(6 errors\) - .*4711.muc: Failed .* /);

#$cl4711->run();
#$clsimple->run()
