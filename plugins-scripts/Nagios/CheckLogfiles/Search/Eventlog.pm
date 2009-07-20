package Nagios::CheckLogfiles::Search::Eventlog;

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
  $self->{logfile} = '/eventlog/is/cool';
  $self->default_options({ winwarncrit => 0 });
  $self->SUPER::init($params);
  if ($self->{options}->{winwarncrit}) {
    push(@{$self->{patterns}->{WARNING}}, "EE_WW_TT");
    push(@{$self->{patterns}->{CRITICAL}}, "EE_EE_TT");
  }
  $self->{eventlog} = { 
    # system, security, application
    eventlog => $params->{eventlog}->{eventlog} || "system",
    computer => $params->{eventlog}->{computer} || Win32::NodeName,
    username => $params->{eventlog}->{username},
    password => $params->{eventlog}->{password},
    source => $params->{eventlog}->{source},
  };
  # computer: I changed "\\\\MYPDC" to $dc ($dc = Win32::AdminMisc::GetDC("MYDOMAIN");)


}
  
sub prepare {
  my $self = shift;
  $self->{options}->{nologfilenocry} = 1;
  $self->{eventlog}->{thissecond} = time;
}

sub loadstate {
  my $self = shift;
  $self->SUPER::loadstate();
  # always scan the whole output. thst's what starttime is for.
  $self->{laststate}->{logoffset} = 0;
  # if this is the very first run, look back 5 mintes in the past.
  $self->{laststate}->{logtime} = $self->{laststate}->{logtime} ?
      $self->{laststate}->{logtime} : $self->{eventlog}->{thissecond} - 600;
} 
  
sub savestate {
  my $self = shift;
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
  $self->{newstate}->{logtime} = $self->{eventlog}->{thissecond};
  $self->SUPER::savestate();
}

sub analyze_situation {
  my $self = shift;
  if ($self->{options}->{lookback}) {
    $self->{eventlog}->{lastsecond} = time - $self->{options}->{lookback};
    $self->trace("looking back until %s",
        scalar localtime $self->{eventlog}->{lastsecond});
  } else {
    $self->{eventlog}->{lastsecond} = $self->{laststate}->{logtime};
    $self->trace("last scanned until %s",
        scalar localtime $self->{eventlog}->{lastsecond});
  }
  $self->trace(sprintf "from %s to %s",
      scalar localtime $self->{eventlog}->{lastsecond},
      scalar localtime $self->{eventlog}->{thissecond});
  if ($self->{eventlog}->{lastsecond} < $self->{eventlog}->{thissecond}) {
    $self->{logmodified} = 1;
  } else {
    # this happens if you call the plugin in too short intervals.
    $self->trace("please wait for a second");
  }
}

sub collectfiles {
  my $self = shift;
  $self->trace(sprintf "get everything %d <= event < %d",
      $self->{eventlog}->{lastsecond},
      $self->{eventlog}->{thissecond});
  if ($self->{logmodified}) {
    open(*FH, sprintf ">%s/orschlorschknorsch_%s",
        $self->system_tempdir(), $self->{tag});
    tie *FH, 'Nagios::CheckLogfiles::Search::Eventlog::Handle',
        $self->{eventlog}, $self->{options}->{winwarncrit}, $self->{tivoli};
    push(@{$self->{relevantfiles}},
      { filename => "eventlog|",
        fh => *FH, seekable => 0,
        modtime => $self->{eventlog}->{thissecond},
        fingerprint => "0:0" });
  }
}

sub getfilefingerprint {
  return 1;
}

sub finish {
  my $self = shift;
  foreach my $level (qw(CRITICAL WARNING UNKNOWN)) {
    if (scalar(@{$self->{matchlines}->{$level}})) {
      foreach my $match (@{$self->{matchlines}->{$level}}) {
        $match =~ s/EE_WW_TT//;
        $match =~ s/EE_EE_TT//;
      }
    }
  }
}

package Nagios::CheckLogfiles::Search::Eventlog::Handle;

use strict;
require Tie::Handle;
use Exporter;
use Win32::EventLog;
use Carp;
use vars qw(@ISA);
@ISA = qw(Tie::Handle Nagios::CheckLogfiles::Search::Eventlog);
our $AUTOLOAD;
$Win32::EventLog::GetMessageText = 1;
my @events = ();

sub TIEHANDLE {
  my $class = shift;
  my $eventlog = shift;
  my $winwarncrit = shift;
  my $tivoli = shift;
  my $self = {};
  my $oldest = 0;
  my $numevents = 0;
  my $event = {
      'Length' => undef,
      'RecordNumber' => undef, 
      'TimeGenerated' => undef,
      'TimeWritten' => undef, 
      'EventID' => undef, 
      'EventType' => undef,  
      'Category' => undef,
      'ClosingRecordNumber' => undef,
      'Source' => undef, 
      'Computer' => undef,
      'Strings' => undef,
      'Data' => undef
  };
  @events = ();
  if (my $handle = 
      Win32::EventLog->new($eventlog->{eventlog}, $eventlog->{computer})) {
    $handle->GetOldest($oldest);
    $handle->GetNumber($numevents);
    if ($numevents) { # sonst gibts haessliche undef-fehler wegen:
      $handle->Read((EVENTLOG_SEEK_READ|EVENTLOG_BACKWARDS_READ),
          $oldest, $event);
      while ($numevents) {
        $handle->Read((EVENTLOG_SEQUENTIAL_READ|EVENTLOG_FORWARDS_READ),
            0, $event);
        if (($event->{Timewritten} >= $eventlog->{lastsecond}) &&
          ($event->{Timewritten} < $eventlog->{thissecond})) {
          if (! $eventlog->{source} ||
              ($eventlog->{source} &&
              (lc $eventlog->{source} eq lc $event->{Source}))) {
            if ($tivoli) {
              if (! $event->{Message}) {
                $event->{Message} = $event->{Strings};
                $event->{Message} =~ s/\0/ /g;
                $event->{Message} =~ s/\s*$//g;
              }
              $event->{Message} = sprintf "%s %s %s %s %s %s %s",
                  join(" ", (split(/ /, scalar localtime $event->{TimeGenerated}))[1,2,3,4]), # month day time and year => %t %s
                  $event->{Category},
                  ($event->{EventType} == EVENTLOG_ERROR_TYPE) ? 'Error' :
                  ($event->{EventType} == EVENTLOG_WARNING_TYPE) ? 'Warning' :
                  ($event->{EventType} ==  EVENTLOG_INFORMATION_TYPE) ? 'Information':
                  ($event->{EventType} ==  EVENTLOG_AUDIT_SUCCESS) ? 'AuditSuccess':
                  ($event->{EventType} ==  EVENTLOG_AUDIT_FAILURE) ? 'AuditFailure': 'Unknown',
                  'N/A',
                  join('_', split(" ", $event->{Source})),
                  $event->{EventID},
                  $event->{Message} ? $event->{Message} : "unknown message";
            } else {
              Win32::EventLog::GetMessageText($event);
              if (! $event->{Message}) {
                $event->{Message} = $event->{Strings};
                $event->{Message} =~ s/\0/ /g;
                $event->{Message} =~ s/\s*$//g;
              }
              $event->{Message} = 'unknown message' if ! $event->{Message};
              $event->{Message} =~ tr/\r\n/ /d;
              # timestamp vornedran
              $event->{Message} .= ' '.(scalar localtime $event->{Timewritten});
            }
            my %tmp_event = %{$event};
            if ($winwarncrit) {
              if ($tmp_event{EventType} == EVENTLOG_WARNING_TYPE) {
                $tmp_event{Message} = "EE_WW_TT".$tmp_event{Message};
              } elsif ($tmp_event{EventType} == EVENTLOG_ERROR_TYPE) {
                $tmp_event{Message} = "EE_EE_TT".$tmp_event{Message};
              }
            }
            push(@events, \%tmp_event);
          }
        }
        $numevents--;
      }
    } else {
      printf STDERR "0 events\n";
    }
    $handle->Close();
  }
  bless $self, $class;
  return $self;
}

sub SEEK {
} 

sub STAT {
} 

sub OPEN {
}
  
sub CLOSE {
}
  
sub GETC { 
} 

sub READ {
} 
  
sub READLINE {
  if (my $event = shift @events) {
    my $event_id= $event->{EventID} & 0xffff;
    return $event->{Message};
  } else {
    return undef;
  }
}

sub AUTOLOAD {
 #printf "uarghh %s\n", $AUTOLOAD;
}

1;
