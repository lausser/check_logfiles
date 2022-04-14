package Nagios::CheckLogfiles::Search::Ipmitool;

# http://download.intel.com/design/servers/ipmi/IPMIv2_0rev1_0.pdf
#
# SEL Entries have a unique `Record ID' field. This field is used for
# retrieving log entries from the SEL. SEL reading can be done in 
# a `random access' manner. That is, SEL Entries can be read in any 
# order assuming that the Record ID is known.
# SEL Record IDs 0000h and FFFFh are reserved for functional use
# and are not legal ID values. Record IDs are handles. They are not
# required to be sequential or consecutive. Applications should not
# assume that SEL Record IDs will follow any particular numeric ordering.
#
# Man beachte die letzten beiden Saetze. Sollte der dafuer Verantwortliche
# diese Zeilen lesen: Ich finde dich, du Schwein!

use strict;
use Exporter;
use File::Basename;
use Time::Local;
use IO::File;
use vars qw(@ISA);
require Digest::MD5; # qw(md5_base64);

use constant OK => 0;
use constant WARNING => 1;
use constant CRITICAL => 2;
use constant UNKNOWN => 3;

@ISA = qw(Nagios::CheckLogfiles::Search::Simple);

sub new {
  my $self = bless {
    eventids => [],
    eventbuffer => [],
  }, shift;
  return $self->init(shift);
}

sub init {
  my $self = shift;
  my $params = shift;
  $self->{logfile} = sprintf "%s/ipmitool.%s", $self->{seekfilesdir},
      $self->{tag};
  $self->SUPER::init($params);
  $self->{clo} = {
      path => $params->{ipmitool}->{path} ?
          $params->{ipmitool}->{path} : "/usr/bin/ipmitool",
      ## cache => exists $params->{ipmitool}->{cache} ? 1 : 0,
      ## using a local cache makes no sense here
      ## maybe checking remote sdr will be a feature in the future
      extraparams => exists $params->{ipmitool}->{extraparams} ?
          $params->{ipmitool}->{extraparams} : "",
      listcmd => exists $params->{ipmitool}->{elist} ? "elist" : "list",
  };
}

sub prepare {
  my $self = shift;
  $self->{options}->{nologfilenocry} = 1;
  $self->{logfile} = sprintf "%s/ipmitool.sel.dump.%s",
      $self->system_tempdir(), $self->{tag};
  $self->{sdrcache} = sprintf "%s/ipmitool.sdr.cache",
      $self->system_tempdir();
  #$self->trace("cache param %s %s", $self->{clo}->{cache}, $self->{sdrcache});
  #$self->trace("list cmd %s", $self->{clo}->{listcmd});
  #$self->trace("time - foo %s", (time - (stat($self->{sdrcache}))[9]));
  #$self->trace("system comand: %s %s", $self->{clo}->{path}, $self->{sdrcache});
  if ($self->{clo}->{cache} && (! -f $self->{sdrcache} || 
      ((time - (stat($self->{sdrcache}))[9]) > 86400))) {
    ## $self->trace("creating/refreshing sdr cache %s", $self->{sdrcache});
    ## system($self->{clo}->{path}.' sdr dump '.$self->{sdrcache}.' >/dev/null 2>&1');
  }
  unlink $self->{logfile};
  my $ipmitool_sel_list = sprintf "%s %s %s sel %s 2>&1 |",
      $self->{clo}->{path}, 
      $self->{clo}->{extraparams}, 
      $self->{clo}->{cache} ? "-S $self->{sdrcache}" : "",
      $self->{clo}->{listcmd};
  my $ipmitool_fh = new IO::File;
  my $spool_fh = new IO::File;
  $self->trace("executing %s", $ipmitool_sel_list);
  # 8 | 08/10/2007 | 15:09:00 | Power Unit #0x01 | Power off/down
  # 9 | Pre-Init Time-stamp   | Chassis #0xa9 | State Asserted
  if ($ipmitool_fh->open($ipmitool_sel_list)) { 
    while (my $event = $ipmitool_fh->getline()) {
      chomp $event;
      next if $event =~ /SEL has no entries/;
      push(@{$self->{eventlog}->{eventbuffer}}, $event);
    }
    $ipmitool_fh->close();
  }
  $self->trace("wrote spoolfile %s", $self->{logfile});
}

sub loadstate {
  my $self = shift;
  $self->SUPER::loadstate();
  $self->{eventlog}->{last_eventids} = $self->{laststate}->{eventids} || [];
  $self->{laststate}->{logoffset} = 0;
}

sub savestate {
  my $self = shift;
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
  $self->{newstate}->{eventids} = $self->{eventlog}->{eventids};
  $self->SUPER::savestate();
}

sub analyze_situation {
  my $self = shift;
  my $spool_fh = new IO::File;
  if ($spool_fh->open('>'.$self->{logfile})) {
    foreach my $event (@{$self->{eventlog}->{eventbuffer}}) {
      if ($event =~ /^\s*(\w+)\s*\|/) {
        my $eventid = $1;
        push(@{$self->{eventlog}->{eventids}}, $eventid);
        if (! grep { $eventid eq $_ } @{$self->{eventlog}->{last_eventids}}) {
          $self->trace("found new eventid %s", $eventid);
          $event =~ s/\|/;/g;
          $spool_fh->printf("%s\n", $event);
          $self->{logmodified} = 1;
          $self->{logrotated} = 1;
        }
      } else {
        $self->trace("no match eventid %s", $event);
      }
    }
    $spool_fh->close();
  }
}

sub rewind {
  my $self = shift;
  $self->loadstate();
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
  $self->addmatch(0, "reset");
  $self->{newstate}->{eventids} = [];
  $self->savestate();
  return $self;
}

