#! /usr/bin/perl
use strict;
use Net::SNMP;

my $hostname = $ENV{CHECK_LOGFILES_SNMP_TRAP_SINK_HOST} 
    || 'nagios.dierichs.de';
my $version = $ENV{CHECK_LOGFILES_SNMP_TRAP_SINK_VERSION} 
    || 'snmpv1';
my $community = $ENV{CHECK_LOGFILES_SNMP_TRAP_SINK_COMMUNITY} 
    || 'public';
my $port = $ENV{CHECK_LOGFILES_SNMP_TRAP_SINK_PORT} 
    || 162;
my $oid = $ENV{CHECK_LOGFILES_SNMP_TRAP_ENTERPRISE_OID} 
    || '1.3.6.1.4.1.20006.1.5.1';


my ($session, $error) = Net::SNMP->session(
    -hostname     => $hostname,
    -version      => $version,
    -community    => $community,
    -port         => $port      # Need to use port 162
);

if (!defined($session)) {
   printf("ERROR: %s.\n", $error);
   exit 1;
}

my @varbind = ($oid, OCTET_STRING, $ENV{CHECK_LOGFILES_SERVICEOUTPUT});
my $result = $session->trap(
    -enterprise   => $oid,
    -specifictrap => $ENV{CHECK_LOGFILES_SERVICESTATEID},
    -varbindlist  => \@varbind);
$session->close;
exit 0;

