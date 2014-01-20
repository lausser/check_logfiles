package Nagios::CheckLogfiles::Search::Esxdiag;

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
    server => $params->{esxdiag}->{server}, # 
    host => $params->{esxdiag}->{server} ? # wenn server = datacenter
        $params->{esxdiag}->{host} : undef,
    username => $params->{esxdiag}->{username},
    password => $params->{esxdiag}->{password},
    log => $params->{esxdiag}->{log} || 'hostd',
  };
  $self->{esxdiag}->{connect}->{url} = sprintf 'https://%s/sdk/webService', 
      $self->{esxdiag}->{connect}->{server};
  $self->{logfile} = sprintf "%s/esxdiag.%s_%s_%s",
      $self->{seekfilesdir},
      $self->{esxdiag}->{connect}->{log},
      $self->{esxdiag}->{connect}->{server},
      $self->{esxdiag}->{connect}->{host} ?
          $self->{esxdiag}->{connect}->{host} : 'host',
      $self->{tag};
  $self->{esxdiag}->{connect}->{token} = sprintf "%s/esxtok.%s_%s",
      $self->{seekfilesdir},
      $self->{esxdiag}->{connect}->{server},
      $self->{esxdiag}->{connect}->{host} ?
          $self->{esxdiag}->{connect}->{host} : 'host';
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
  # if this is the very first run, use an insane offet
  $self->{laststate}->{lineend} = $self->{laststate}->{lineend} ?
      ($self->{laststate}->{lineend} + 1) : 999999;
}

sub savestate {
  my $self = shift;
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
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
      require VMware::VIRuntime;
      my %loginparams = (
        service_url => $self->{esxdiag}->{connect}->{url},
        user_name => $self->{esxdiag}->{connect}->{username},
        password => $self->{esxdiag}->{connect}->{password},
      );
      my $vim = undef;
      eval {
        # das bringt's nicht. login ist genauso schnell
        #$vim = Vim::load_session(
        #    service_url => $self->{esxdiag}->{connect}->{url},
        #    session_file => $self->{esxdiag}->{connect}->{token});
        $vim = Vim::login(%loginparams) if ! $vim;
        #Vim::save_session(
        #    session_file => $self->{esxdiag}->{connect}->{token});
      };
      if ($vim) {
        my $instance_type = Vim::get_service_content()->about->apiType;
        my $diagmgr = Vim::get_service_content()->diagnosticManager();
        my $diagmgr_view = $diagmgr ? Vim::get_view(mo_ref => $diagmgr) : undef;
        if ($diagmgr_view) {
          my $host_view = undef;
          my $logdata = undef;
          if ($instance_type eq 'VirtualCenter') {
            my $host_views = Vim::find_entity_views(
                view_type => 'HostSystem',
                filter => {'name' => $self->{esxdiag}->{host}},
                properties => ['name']);
            $host_view = $host_views->[0] if $host_views;
          } else {
            $host_view = Vim::find_entity_view(
                view_type => 'HostSystem',
                properties => ['name']); # increases the speed dramatically
          }
          if ($host_view) {
            my %browseparams = (
                key => $self->{esxdiag}->{connect}->{log},
                start => $self->{laststate}->{lineend},
            );
            $browseparams{host} = $self->{esxdiag}->{connect}->{host}
                if $self->{esxdiag}->{connect}->{host}; # VirtualCenter
            $self->trace(sprintf 'browsing view for host %s', $host_view->name);
            $self->trace(sprintf 'start reading at line %d',
                $self->{laststate}->{lineend});
            $logdata = $diagmgr_view->BrowseDiagnosticLog(%browseparams);
            $self->trace(sprintf 'log interval is %d..%d',
                $logdata->lineStart, $logdata->lineEnd);
            if ($logdata->lineStart < $self->{laststate}->{lineend}) {
              # rotation, 
              # z.b. "start reading at line 4133"-> "log interval is 0..43"
              $browseparams{start} = $logdata->lineStart;
              $logdata = $diagmgr_view->BrowseDiagnosticLog(%browseparams);
              $self->trace(sprintf 'rotation detected. new log interval %d..%d',
                  $logdata->lineStart, $logdata->lineEnd);
            }
            $self->{laststate}->{lineend} = $logdata->lineEnd;
            if ($logdata->lineText) {
              if (my $fh = new IO::File($self->{logfile}, 'w')) {
                foreach my $line (@{$logdata->lineText}) {
                  $fh->printf("%s\n", $line);
                  $linesread++;
                }
                $fh->close();
              }
            } else {
              $self->trace('nothing to do');
            }
          } else {
            $self->trace('no host view');
          }
        } else {
          $self->trace('no diag manager view');
        }
        Vim::logout(); # auskommentieren, wenn sessions benutzt werden
      } else {
        chomp $@ if $@;
        $self->trace(sprintf 'unable to connect %s', $@);
        $self->addevent('UNKNOWN', sprintf 'unable to connect %s', $@);
      }
    };
    if ($@) {
      $self->trace(sprintf "vi api operation failed: %s", $@);
      $self->addevent('UNKNOWN', sprintf "vi api operation failed: %s", $@);
    }
    $self->trace(sprintf "read %d lines from esx server", $linesread);
    if ($linesread) {
      if (my $fh = new IO::File($self->{logfile}, "r")) {
        $self->trace(sprintf "reopen logfile");
        push(@{$self->{relevantfiles}},
          { filename => "esxdiag",
            fh => $fh, seekable => 1, statable => 1,
            modtime => time,
            fingerprint => "0:0" });
      }
    }
  }
}

1;
