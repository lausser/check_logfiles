package Nagios::CheckLogfiles::Search::Oraclealertlog;

use strict;
use Exporter;
use File::Basename;
use Time::Local;
use IO::File;
use vars qw(@ISA);

use constant OK => 0;
use constant WARNING => 1;
use constant CRITICAL => 2;
use constant UNKNOWN => 3;

@ISA = qw(Nagios::CheckLogfiles::Search);

sub new {
  my $self = bless {}, shift;
  return $self->init(shift);
}

sub init {
  my $self = shift;
  my $params = shift;
  $self->{esxdiag}->{connect} = {
    server => $params->{esxdiag}->{server},
    host => $params->{esxdiag}->{server} ?
        $params->{esxdiag}->{host} : undef,
    username => $params->{esxdiag}->{username},
    password => $params->{esxdiag}->{password},
    log => $params->{esxdiag}->{log}, # hostd
  };
  foreach my $option (qw(server host username password log)) {
    $Opts::options{$option}->{value} = $self->{esxdiag}->{connect}->{$option};
  }
  $self->{logfile} = sprintf "%s/esxdiag.%s%s%s", $self->{seekfilesdir},
      $self->{esxdiag}->{log},
      $self->{esxdiag}->{server},
      $self->{esxdiag}->{host},
      $self->{tag};
  # virtualcenter + host # host managed by vc
  # virtualcenter. default logs = vc logs
  # host # esx server
  $self->SUPER::init($params);
}
    
sub prepare {
  my $self = shift;
  $self->{options}->{nologfilenocry} = 1;
}

sub loadstate {
  my $self = shift;
  $self->SUPER::loadstate();
  # if this is the very first run, look back 5 mintes in the past.
  $self->{laststate}->{lineend} ||= 0;
}

sub savestate {
  my $self = shift;
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
  # remember the last line number
  $self->{newstate}->{lineend} = $self->{logdata}->lineEnd;
  $self->SUPER::savestate();
}

sub analyze_situation {
  my $self = shift;
  $self->{logmodified} = 1;
}

sub collectfiles {
  my $self = shift;
  my $fh = new IO::File;
  if ($self->{logmodified}) {
    my $linesread = 0;
    eval {
      use VMware::VIRuntime;
      use VMware::VILib;
      if ($self->{esxdiag}->{session} = Util::connect()) {
        my $instance_type = Vim::get_service_content()->about->apiType;
        $self->{esxdiag}->{diagmgr} = Vim::get_service_content()->DiagnosticManager;
        my $host_view = $Opts::options{host} ? 
            Vim::find_entity_views(
                view_type => 'HostSystem',
                filter => { 'name' => "^$Opts::options{host}\$" }
            ) :
            Vim::find_entity_views(
                view_type => 'HostSystem'
            );
        if (@$host_view) {
          if ($instance_type eq 'VirtualCenter') {
            $self->{esxdiag}->{logdata} = 
                $self->{esxdiag}->{diagmgr}->BrowseDiagnosticLog(
                    host => $host_view->[0],
                    start => $self->{laststate}->{lineend} + 1,
                );
          } else {
            $self->{esxdiag}->{logdata} = 
                $self->{esxdiag}->{diagmgr}->BrowseDiagnosticLog(
                    start => $self->{laststate}->{lineend} + 1,
                );
          }
        } else {
          $self->addevent('UNKNOWN', sprintf "host %s not found", 
              $Opts::options{host});
        }
        Util::disconnect();
      }
      
    };
    if ($@) {
      $self->trace(sprintf "database operation failed: %s", $@);
      $self->addevent('UNKNOWN', sprintf "connect operation failed: %s", $@);
    }
    $self->trace(sprintf "read %d lines from database", $linesread);
    if ($linesread) {
      if (my $fh = new IO::File($self->{logfile}, "r")) {
        $self->trace(sprintf "reopen logfile");
        push(@{$self->{relevantfiles}},
          { filename => "esxdiag",
            fh => $fh, seekable => 0,
            modtime => $self->{eventlog}->{nowminute},
            fingerprint => "0:0" });
      }
    }
  }
}

__END__
#!/usr/bin/perl -w
#
# Copyright 2007 VMware, Inc. All rights reserved.
#
# This script creates a Perl object reference to the ServiceContent data
# object, and then creates a reference to the diagnosticManager. The script
# follows ('tails') the log as it changes. 

use strict;
use warnings;


# get ServiceContent
my $content = Vim::get_service_content();
my $diagMgr = Vim::get_view(mo_ref => $content->diagnosticManager);
# Obtain the last line of the logfile by setting an arbitrarily large
# line number as the starting point
my $log = $diagMgr->BrowseDiagnosticLog(
    key => "hostd",
    start => "999999999");
my $lineEnd = $log->lineEnd;

# First, get the last 5 lines of the log, and then check every 2 seconds
# to see if the log size has increased.
my $start = $lineEnd - 5;

# Disconnect on receipt of an interrupt signal while in the infinite
# loop below.
$SIG{INT} = sub {
    Util::disconnect();
    exit;
 };
while (1) {
$log = $diagMgr->BrowseDiagnosticLog(
   key => "hostd",
   start => $start);
#printf "linestart %d\n", $log->lineStart;
#printf "lineend %d\n", $log->lineEnd;
if ($log->lineStart != 0) {
   foreach my $line (@{$log->lineText}) {

# next if ($line =~ /verbose\]/);
   print "$line\n";
  }
}
$start = $log->lineEnd + 1;
sleep 3;
}


