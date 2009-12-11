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
      cache => exists $params->{ipmitool}->{elist} ? 1 : 0,
      listcmd => exists $params->{ipmitool}->{elist} ? "elist" : "list"
  };
}

sub prepare {
  my $self = shift;
  $self->{options}->{nologfilenocry} = 1;
  $self->{logfile} = sprintf "%s/ipmitool.sel.dump.%s",
      $self->system_tempdir(), $self->{tag};
  $self->{sdrcache} = sprintf "%s/ipmitool.sdr.cache",
      $self->system_tempdir();
  if ($self->{clo}->{cache} && (! -f $self->{sdrcache} || 
      ((time - ($self->{sdrcache})[9]) > 86400))) {
    $self->trace("creating/refreshing sdr cache %s", $self->{sdrcache});
    system($self->{clo}->{path}.' sdr dump '.$self->{sdrcache}.' >/dev/null 2>&1');
  }
  unlink $self->{logfile};
  my $ipmitool_sel_list = sprintf "%s %s sel %s 2>&1 |",
      $self->{clo}->{path}, 
      $self->{clo}->{cache} ? "-S $self->{sdrcache}" : "",
      $self->{clo}->{listcmd};
  my $ipmitool_fh = new IO::File;
  my $spool_fh = new IO::File;
  $self->trace("executing %s", $ipmitool_sel_list);
  # 8 | 08/10/2007 | 15:09:00 | Power Unit #0x01 | Power off/down
  # 9 | Pre-Init Time-stamp   | Chassis #0xa9 | State Asserted
  if ($ipmitool_fh->open($ipmitool_sel_list)) {
    if ($spool_fh->open('>'.$self->{logfile})) {
      while (my $event = $ipmitool_fh->getline()) {
        chomp $event;
        next if $event =~ /SEL has no entries/;
        if (/^\s*(\w+)\s*\|/) {
          push(@{$self->{eventlog}->{eventids}}, $1);
          $self->trace("found new eventid %s", $1);
          if (! grep $1, @{$self->{eventlog}->{last_eventids}}) { # new id
            $event =~ s/\|/;/g;
            $spool_fh->printf("%s\n", $event);
          }
        }
      }
      $spool_fh->close();
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

sub getfilefingerprint {
  my $self = shift;
  my $file = shift;
  if (-f $file) {
    my $magic;
    if (ref $file) {
      my $pos = $file->tell();
      $file->seek(0, 0);
      $magic = $file->getline() || "this_was_an_empty_file";
      $file->seek(0, $pos);
    } else {
      my $fh = new IO::File;
      $fh->open($file, "r");
      $magic = $fh->getline() || "this_was_an_empty_file";
      $fh->close();
    }
    $self->trace("magic: %s", $magic);
    return(Digest::MD5::md5_base64($magic));
  } else {
    return "0:0";
  }
}
