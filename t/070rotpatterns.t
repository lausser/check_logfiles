#!/usr/bin/perl -w
#
# ~/check_logfiles/test/004rotation.t
#
#  Test the capability of finding rotated logfiles.
#  Use the predefined names.

use strict; 
use Test::More tests => 5;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => "."; 


if ($^O =~ /MSWin/) {
  # in a desperate attempt...
  $ENV{PATH} = $ENV{PATH}.';C:\Programme\cygwin\bin;C:\cygwin\bin';
}

sub delete_and_create_ramsch {
  my @archives = (
    "messages", "messagess", "message",
    "messages.0", "messages.00", "messages0", "messagess.0", "message.0", "messagess.0", "messagess0",
    "messages.0.gz", "messages0gz", "messagess.0gz", "message.0gz", "messagess.0gz", "messagess0gz",
    "messages0.gz", "messages.00.gz", "messagess.0.gz", "message.0.gz", "messagess.0.gz", "messagess0.gz",
    "messages.1", "messages.01", "messages1", "messagess.1", "message.1", "messagess.1", "messagess1",
    "messages.1.gz", "messages.01.gz", "messages1gz", "messagess.1gz", "message.1gz", "messagess.1gz", "messagess1gz",
    "messages1.gz", "messagess.1.gz", "message.1.gz", "messagess.1.gz", "messagess1.gz",
    "messages.2", "messages.02", "messages2", "messagess.2", "message.2", "messagess.2", "messagess2",
    "messages.2.gz", "messages.02.gz", "messages2gz", "messagess.2gz", "message.2gz", "messagess.2gz", "messagess2gz",
    "messages2.gz", "messagess.2.gz", "message.2.gz", "messagess.2.gz", "messagess2.gz",
    "messages2xgz", "messagess.2xgz", "message.2xgz", "messagess.2xgz", "messagess2xgz",
    "messagessx2xgz", "messagex2xgz", "messagessx2xgz",
    "messages.10.gz", "messages..0.gz",
    "messages.12345678",
    "messages00000000", "messages000000000000", "messages00000000000", "messages000000",
    "messages00000000.gz", "messages000000000000.gz", "messages00000000000.gz", "messages000000.gz",
    "messages00000000xgz", "messages000000000000xgz", "messages00000000000xgz", "messages000000xgz",
    "messages-00000000.gz", "messages-000000000000.gz", "messages-00000000000.gz", "messages-000000.gz",
    "messages.00000000.gz", "messages.000000000000.gz", "messages.00000000000.gz", "messages.000000.gz",
    "messages.00000000xgz", "messages.000000000000xgz", "messages.00000000000xgz", "messages.000000xgz",
    "messages:00000000xgz", "messages:000000000000xgz", "messages:00000000000xgz", "messages:000000xgz",
    "messages.xxxxxxxxxgz", "messages.xxxxxxxxxxxxxgz", "messages.xxxxxxxxxxxxgz", "messages.xxxxxxxgz",
    "messages..........gz", "messages..............gz", "messages.............gz", "messages........gz",
    "messages11111111", "messages111111111111", "messages11111111111", "messages111111",
    "messages11111111.gz", "messages111111111111.gz", "messages11111111111.gz", "messages111111.gz",
    "messages11111111xgz", "messages111111111111xgz", "messages11111111111xgz", "messages111111xgz",
    "messages-11111111.gz", "messages-111111111111.gz", "messages-11111111111.gz", "messages-111111.gz",
    "messages.11111111.gz", "messages.111111111111.gz", "messages.11111111111.gz", "messages.111111.gz",
    "messages.11111111xgz", "messages.111111111111xgz", "messages.11111111111xgz", "messages.111111xgz",
    "messages:11111111xgz", "messages:111111111111xgz", "messages:11111111111xgz", "messages:111111xgz",
    "messages.0.bz2", "messages0bz2", "messagess.0bz2", "message.0bz2", "messagess.0bz2", "messagess0bz2",
    "messages0.bz2", "messages.00.bz2", "messagess.0.bz2", "message.0.bz2", "messagess.0.bz2", "messagess0.bz2",    "messages.1.bz2", "messages.01.bz2", "messages1bz2", "messagess.1bz2", "message.1bz2", "messagess.1bz2", "messagess1bz2",
    "messages1.bz2", "messagess.1.bz2", "message.1.bz2", "messagess.1.bz2", "messagess1.bz2",
    "messages.2.bz2", "messages.02.bz2", "messages2bz2", "messagess.2bz2", "message.2bz2", "messagess.2bz2", "messagess2bz2",
    "messages2.bz2", "messagess.2.bz2", "message.2.bz2", "messagess.2.bz2", "messagess2.bz2",
    "messages2xbz2", "messagess.2xbz2", "message.2xbz2", "messagess.2xbz2", "messagess2xbz2",
    "messagessx2xbz2", "messagex2xbz2", "messagessx2xbz2",
    "messages.10.bz2", "messages..0.bz2",
    "messages00000000.bz2", "messages000000000000.bz2", "messages00000000000.bz2", "messages000000.bz2",
    "messages00000000xbz2", "messages000000000000xbz2", "messages00000000000xbz2", "messages000000xbz2",
    "messages-00000000.bz2", "messages-000000000000.bz2", "messages-00000000000.bz2", "messages-000000.bz2",
    "messages.00000000.bz2", "messages.000000000000.bz2", "messages.00000000000.bz2", "messages.000000.bz2",
    "messages.00000000xbz2", "messages.000000000000xbz2", "messages.00000000000xbz2", "messages.000000xbz2",
    "messages:00000000xbz2", "messages:000000000000xbz2", "messages:00000000000xbz2", "messages:000000xbz2",
    "messages.xxxxxxxxxbz2", "messages.xxxxxxxxxxxxxbz2", "messages.xxxxxxxxxxxxbz2", "messages.xxxxxxxbz2",
    "messages..........bz2", "messages..............bz2", "messages.............bz2", "messages........bz2",
    "messages11111111.bz2", "messages111111111111.bz2", "messages11111111111.bz2", "messages111111.bz2",
    "messages11111111xbz2", "messages111111111111xbz2", "messages11111111111xbz2", "messages111111xbz2",
    "messages-11111111.bz2", "messages-111111111111.bz2", "messages-11111111111.bz2", "messages-111111.bz2",
    "messages.11111111.bz2", "messages.111111111111.bz2", "messages.11111111111.bz2", "messages.111111.bz2",
    "messages.11111111xbz2", "messages.111111111111xbz2", "messages.11111111111xbz2", "messages.111111xbz2",
    "messages:11111111xbz2", "messages:111111111111xbz2", "messages:11111111111xbz2", "messages:111111xbz2",
  );

  foreach my $ramsch (glob TESTDIR."/var/tmp/*") {
    unlink $ramsch;
  }
  foreach my $ramsch (@archives) {
    if ($ramsch =~ /gz$/) {
      open (RAMSCH, "| gzip >".TESTDIR."/var/tmp/".$ramsch);
    } elsif ($ramsch =~ /bz2$/) {
      open (RAMSCH, "| bzip2 >".TESTDIR."/var/tmp/".$ramsch);
    } else {
      open (RAMSCH, ">".TESTDIR."/var/tmp/".$ramsch);
    }
    printf RAMSCH "ramsch %s %d\n", $ramsch, rand 10000; # win32 fingerprint is the content
    close RAMSCH;
  }
}

my $cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "ssh",
              logfile => TESTDIR."/var/tmp/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user",
              rotation => "SOLARIS",
            }
        ]    });
my $ssh = $cl->get_search_by_tag("ssh");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
delete_and_create_ramsch();
printf "look into %s\n", TESTDIR."/var/tmp/";
sleep 1;
$ssh->trace("initial run");
$cl->run();
$ssh->{rotation} = "loglogdate8gz";
#$ssh->{rotation} = sprintf '^%s[\.\-]{0,1}[0-9]{8}\.gz$', $ssh->{logbasename};
$ssh->prepare();
$ssh->{logrotated} = 1;
$ssh->{logmodified} = 1;
$ssh->{laststate}->{logtime} = 0;
$ssh->collectfiles();
diag(sprintf "pattern is /%s/", $ssh->{filenamepattern});
foreach (map { $_->{filename} } @{$ssh->{relevantfiles}}) {
  diag($_);
}
ok(scalar(@{$ssh->{relevantfiles}}) == 7);

$ssh->{rotation} = "loglogdate8bz2";
#$ssh->{rotation} = sprintf '^%s[\.\-]{0,1}[0-9]{8}\.gz$', $ssh->{logbasename};
$ssh->prepare();
$ssh->{logrotated} = 1;
$ssh->{logmodified} = 1;
$ssh->{laststate}->{logtime} = 0;
$ssh->collectfiles();
diag(sprintf "pattern is /%s/", $ssh->{filenamepattern});
foreach (map { $_->{filename} } @{$ssh->{relevantfiles}}) {
  diag($_);
}
ok(scalar(@{$ssh->{relevantfiles}}) == 7);

$ssh->{rotation} = "loglog0log1gz";
#$ssh->{rotation} = sprintf '^%s\.((0)|([1-9]+\.gz))$', $ssh->{logbasename}, $ssh->{logbasename};
$ssh->prepare();
$ssh->{logrotated} = 1;
$ssh->{logmodified} = 1;
$ssh->{laststate}->{logtime} = 0;
$ssh->collectfiles();
diag(sprintf "pattern is /%s/", $ssh->{filenamepattern});
foreach (map { $_->{filename} } @{$ssh->{relevantfiles}}) {
  diag($_);
}
ok(scalar(@{$ssh->{relevantfiles}}) == 8);

$ssh->{rotation} = "loglog0gzlog1gz";
#$ssh->{rotation} = sprintf '^%s\.((0)|([1-9]+[0-9]*))\.gz$', $ssh->{logbasename}, $ssh->{logbasename};
$ssh->prepare();
$ssh->{logrotated} = 1;
$ssh->{logmodified} = 1;
$ssh->{laststate}->{logtime} = 0;
$ssh->collectfiles();
diag(sprintf "pattern is /%s/", $ssh->{filenamepattern});
foreach (map { $_->{filename} } @{$ssh->{relevantfiles}}) {
  diag($_);
}
ok(scalar(@{$ssh->{relevantfiles}}) == 9);

$ssh->{rotation} = "loglog0log1";
#$ssh->{rotation} = sprintf '^%s\.((0)|([1-9]+[0-9]*))$', $ssh->{logbasename}, $ssh->{logbasename};
$ssh->prepare();
$ssh->{logrotated} = 1;
$ssh->{logmodified} = 1;
$ssh->{laststate}->{logtime} = 0;
$ssh->collectfiles();
diag(sprintf "pattern is /%s/", $ssh->{filenamepattern});
foreach (map { $_->{filename} } @{$ssh->{relevantfiles}}) {
  diag($_);
}
ok(scalar(@{$ssh->{relevantfiles}}) == 5);
