#!/usr/bin/perl -w
#
# ~/check_logfiles/test/082initfromline.t
#
#  Test if an encoded configfile is correctly decoded
#

use strict;
use Test::More;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

plan tests => 2;


my @patterns = ();

my $configfile = q{
@searches = ({ 
  tag => "test",
  logfile => "/var/log/messages",
  rotation => "SOLARIS",
  criticalpatterns => [
    "ERROR",
    "root on none",
  ],
  options => "script",
  script => sub {
    use LWP;
    print "hello world";
    my $browser = LWP::UserAgent->new();
    my $response = $browser->post(
    'https://10.0.15.248/monitor/upload/upload.php',
     [text1 => 'blabla',
      text2 => 'blablubb',
      'Datei' => [undef,'job_name',],
     ],
     'Content_Type' => 'form-data',
    );

  }
});
};

open CCC, ">./etc/encodeme.cfg";
print CCC $configfile;
close CCC;
open (CFG,"./etc/encodeme.cfg");
my $contents = "";
while (<CFG>) {$contents .= $_}
#print $contents."\n###\n";
$contents =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg;
close (CFG);


my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => $contents });
printf STDERR "%s\n", $cl->{cfgfile};
ok($cl->{cfgfile} eq $configfile);

our($seekfilesdir, $protocolsdir, $scriptpath, $protocolretention,
    $prescript, $prescriptparams ,$prescriptstdin, $prescriptdelay,
    $postscript, $postscriptparams, $postscriptstdin, $postscriptdelay,
    @searches, @logs, $tracefile, $options, $report, $timeout, $pidfile);
our $MACROS = {};

eval $cl->{cfgfile};
printf STDERR "error: %s\n", $@;
ok(! $@);

