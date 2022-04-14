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
  $self->default_options({ winwarncrit => 0, 
      eventlogformat => '%g %i %m' });
  $self->SUPER::init($params);
  if ($self->get_option('lookback')) {
    if ($self->get_option('lookback') =~ /^(\d+)(s|m|h|d)$/) {
      if ($2 eq 's') {
        $self->set_option('lookback', $1);
      } elsif ($2 eq 'm') {
        $self->set_option('lookback', $1 * 60);
      } elsif ($2 eq 'h') {
        $self->set_option('lookback', $1 * 60 * 60);
      } elsif ($2 eq 'd') {
        $self->set_option('lookback', $1 * 60 * 60 * 24);
      }
    } else {
      printf STDERR "illegal time interval (must be <number>[s|m|h|d]\n";
      $self = undef;
      return undef;
    }
  }
  if ($self->get_option('winwarncrit')) {
    push(@{$self->{patterns}->{WARNING}}, "EE_WW_TT");
    push(@{$self->{patterns}->{CRITICAL}}, "EE_EE_TT");
    push(@{$self->{patternfuncs}->{WARNING}}, 
        eval "sub { local \$_ = shift; return m/EE_WW_TT/o; }");
    push(@{$self->{patternfuncs}->{CRITICAL}},
        eval "sub { local \$_ = shift; return m/EE_EE_TT/o; }");

  }
  push(@{$self->{patterns}->{UNKNOWN}}, "EE_UU_TT");
  push(@{$self->{patternfuncs}->{UNKNOWN}},
      eval "sub { local \$_ = shift; return m/EE_UU_TT/o; }");
  $self->{eventlog} = { 
    # system, security, application
    eventlog => $params->{eventlog}->{eventlog} || 'system',
    computer => $params->{eventlog}->{computer} || Win32::NodeName(),
    username => $params->{eventlog}->{username} || Win32::LoginName(),
    password => $params->{eventlog}->{password} || '',
    source => $params->{eventlog}->{source},
    speedup => $params->{eventlog}->{speedup} || 1,
    include => $params->{eventlog}->{include} || {},
    exclude => $params->{eventlog}->{exclude} || {},
  };
  $self->resolve_macros(\$self->{eventlog}->{eventlog});
  $self->resolve_macros(\$self->{eventlog}->{computer});
  $self->resolve_macros(\$self->{eventlog}->{username}) if $self->{eventlog}->{username};
  $self->resolve_macros(\$self->{eventlog}->{password}) if $self->{eventlog}->{password};
  # computer: I changed "\\\\MYPDC" to $dc ($dc = Win32::AdminMisc::GetDC("MYDOMAIN");)
  # keys fuer include/exclude: source,category,type,eventid
  foreach my $item (qw(Source Category EventType EventID)) {
    foreach (keys %{$self->{eventlog}->{include}}) {
      if (lc $_ eq lc $item) {
        $self->{eventlog}->{include}->{$item} = 
            lc $self->{eventlog}->{include}->{$_};
        delete $self->{eventlog}->{include}->{$_} if $_ ne $item;
      }
    }
    foreach (keys %{$self->{eventlog}->{exclude}}) {
      if (lc $_ eq lc $item) {
        $self->{eventlog}->{exclude}->{$item} =
            lc $self->{eventlog}->{exclude}->{$_};
        delete $self->{eventlog}->{exclude}->{$_} if $_ ne $item;
      }
    }
  }
  if (! exists $self->{eventlog}->{include}->{operation} ||
      $self->{eventlog}->{include}->{operation} ne 'or') {
    $self->{eventlog}->{include}->{operation} = 'and'
  }
  if (! exists $self->{eventlog}->{exclude}->{operation} ||
      $self->{eventlog}->{exclude}->{operation} ne 'and') {
    $self->{eventlog}->{exclude}->{operation} = 'or'
  }
  $self->{orschlorschknorsch} = sprintf "%s/%s.temp_evtlog2file",
        $self->system_tempdir(), $self->{tag};
}
  
sub prepare {
  my $self = shift;
  #$self->{options}->{nologfilenocry} = 1;
  $self->{eventlog}->{thissecond} = time;
  push(@{$self->{exceptions}->{CRITICAL}}, 'CHECK_LOGFILES INTERNAL ERROR');
  push(@{$self->{exceptions}->{WARNING}}, 'CHECK_LOGFILES INTERNAL ERROR');
}

sub loadstate {
  my $self = shift;
  $self->SUPER::loadstate();
  # always scan the whole output. thst's what starttime is for.
  $self->{laststate}->{logoffset} = 0;
  # if this is the very first run, look back 5 mintes in the past.
  # with allyoucaneat set, look back 10 years
  $self->{laststate}->{logtime} = $self->{laststate}->{logtime} ?
      $self->{laststate}->{logtime} : 
      $self->{options}->{allyoucaneat} ? 
          $self->{eventlog}->{thissecond} - 315360000 :
          $self->{eventlog}->{thissecond} - 600;
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
    open(*FH, ">$self->{orschlorschknorsch}");
    tie *FH, 'Nagios::CheckLogfiles::Search::Eventlog::Handle',
        $self->{eventlog}, 
        $self->get_option('winwarncrit'),
        $self->get_option('eventlogformat'),
        $self->get_option('logfilenocry'),
        $self->{tivoli},
        $self->{tracefile};
    push(@{$self->{relevantfiles}},
      { filename => "eventlog|",
        fh => *FH, seekable => 0, statable => 1,
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
        $match =~ s/EE_UU_TT//;
      }
    }
    if (exists $self->{lastmsg} && exists $self->{lastmsg}->{$level}) {
      $self->{lastmsg}->{$level} =~ s/EE_WW_TT//;
      $self->{lastmsg}->{$level} =~ s/EE_EE_TT//;
      $self->{lastmsg}->{$level} =~ s/EE_UU_TT//;
    }
  }
  if (-f $self->{orschlorschknorsch}) {
    unlink $self->{orschlorschknorsch};
  }
}

sub rewind {
  my $self = shift;
  $self->loadstate();
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
  $self->addmatch(0, "reset");
  $self->{eventlog}->{thissecond} = 1;
  $self->savestate();
  return $self;
}


package Nagios::CheckLogfiles::Search::Eventlog::Handle;

use strict;
use Exporter;
use POSIX qw(strftime);
require Tie::Handle;
use Win32::EventLog;
use Win32::TieRegistry (Delimiter => "/");
use Win32::WinError;
use IO::File;
use vars qw(@ISA);
@ISA = qw(Tie::Handle Nagios::CheckLogfiles::Search::Eventlog);
our $AUTOLOAD;
our $tracefile;
$Win32::EventLog::GetMessageText = 1;
our @events = ();


sub TIEHANDLE {
  my $class = shift;
  my $eventlog = shift;
  my $winwarncrit = shift;
  my $eventlogformat = shift;
  my $logfilenocry = shift;
  my $tivoli = shift;
  $tracefile = shift;
  my $self = {};
  my $oldestoffset = undef;       # oldest event in the eventlog
  my $numevents = undef;          # number of events in the eventlog
  my $newestoffset = 0;       # latest event in the eventlog
  my $save_newestoffset = 0; 
  my $seekoffset = 0;         # temporary pointer
  my $firstoffset = 0;        # first event created after the last run
  my $event = {
      'Length' => undef,
      'RecordNumber' => undef, 
      'TimeGenerated' => undef,
      'Timewritten' => undef, 
      'EventID' => undef, 
      'EventType' => undef,  
      'Category' => undef,
      'ClosingRecordNumber' => undef,
      'Source' => undef, 
      'Computer' => undef,
      'Strings' => undef,
      'Data' => undef,
      'User' => undef,
  };
  @events = ();
  my $offsetcache = {};
  my $mustabort = 0;
  my $internal_error = "";
  my $lasterror = 0;
  my $handle = undef;
  my $must_close_ipc = 0;

  if ($tivoli->{object}) {
    $eventlogformat = "_tecad_win_";
  }
  # 
  # Schritt 1
  #
  # Falls es sich um einen Remote-Rechner handelt, muss erst eine
  # Verbindung zu dessen IPC$-Resource hergestellt werden
  # Bei einem Server 2008 kann dies ein lokaler Benutzer sein,
  # der zur Gruppe Ereignisprotokolleser gehoert
  #
  if ($eventlog->{computer} ne Win32::NodeName) {
    my @harmlesscodes = (1219);
    # 1219 Mehrfache Verbindungen zu einem Server oder ....
    # net use \\remote\IPC$ /USER:Administrator adminpw
    eval {
      require Win32::NetResource;
    };
    if ($@) {
      $mustabort = 1;
      $internal_error = 'Win32::NetResource not installed';
    } else {
      trace(sprintf "connect to %s as %s with password ***",
          $eventlog->{computer}, $eventlog->{username});
      if (Win32::NetResource::AddConnection({
          'Scope' => 0,
          'Type' => 0,
          'DisplayType' => 0, # RESOURCEDISPLAYTYPE_GENERIC
          'Usage' => 0,
          'RemoteName' => "\\\\".$eventlog->{computer}."\\IPC\$",
          'LocalName' => '',
          'Comment' => "check_logfiles",
          #'Provider' => "Microsoft Windows Network"
      }, $eventlog->{password}, $eventlog->{username}, 0)) {
        trace("created ipc channel");
        $must_close_ipc = 1;
      } else {
        Win32::NetResource::GetError($lasterror);
        if (scalar(grep { $lasterror == $_ } @harmlesscodes) == 0) {
          $mustabort = 1;
          $internal_error = 'IPC$ '.Win32::FormatMessage($lasterror);
          trace("ipc channel could not be established");
        } else {
          trace("ipc channel already established");
        }
      }
    }
  }
  #
  # Schritt 2
  #
  # Oeffnen der Registry und kontrollieren, ob es das gewuenschte
  # Eventlog ueberhaupt gibt
  #
  if (! $mustabort) {
    my @haseventlogs = ("application", "system", "security");
    eval {
      my $data = undef;
      if ($eventlog->{computer} ne Win32::NodeName()) {
        trace("looking into remote registry");
        $data = $Registry->Connect( $eventlog->{computer},
            'HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/EventLog/',
            { Access=>Win32::TieRegistry::KEY_READ(), Delimiter => "/" } );
      } else {
        trace("looking into registry");
        $data = $Registry->Open(
            'HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/EventLog/',
            { Access=>Win32::TieRegistry::KEY_READ(), Delimiter => "/" } );
      }
      if ($data) {
        push(@haseventlogs, grep { 
            my $var = $_; ! grep /^$var$/, @haseventlogs
        } map { lc $_ } $data->SubKeyNames);
        trace(sprintf "known eventlogs: %s", join(',', @haseventlogs));
        undef $data;
      } else {
        die "no data from HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/EventLog/";
      }
    };
    if ($@) {
      $mustabort = 1;
      $internal_error = "Cannot read registry";
      trace(sprintf "looking into registry failed: %s", $@);
    } elsif (! scalar(grep { lc $eventlog->{eventlog} eq $_ } @haseventlogs)) {
      $mustabort = 1;
      $internal_error = sprintf "Eventlog %s does not exist",
          $eventlog->{eventlog} if $logfilenocry;
    }
  }
  #
  # Schritt 3
  #
  # Oeffnen des Eventlogs
  #
  if (! $mustabort) {
    my @harmlesscodes = (0, 997);
    trace(sprintf "opening handle to eventlog %s", $eventlog->{eventlog});
    $handle =
        Win32::EventLog->new($eventlog->{eventlog}, $eventlog->{computer});
    $lasterror = Win32::GetLastError();
    #    0 Der Vorgang wurde erfolgreich beendet
    #  997 überlappender E/A-Vorgang wird verarbeitet.
    #    5 Zugriff verweigert
    # 1722 Der RPC-Server ist nicht verfügbar.

    # 1722 eventlog gueltig, ip gueltig, aber kein windows-rechner
    # 1722 eventlog gueltig, ip nicht pingbar
    #    5 kein secure channel zum remoterechner vorhanden

    if (! $handle || scalar(grep { $lasterror == $_ } @harmlesscodes) == 0) {
      # sinnlos, weiterzumachen
      $mustabort = 1;
      $internal_error = 'open Eventlog '.Win32::FormatMessage($lasterror);
      trace("opening handle to eventlog failed");
    }
  }
  #
  # Schritt 4
  #
  # Anzahl der Eintraege auslesen.
  # Dieser Schritt dient ausserdem dazu, die Berechtigung zum Lesen
  # zu ueberpruefen, da unter Cygwin der letzte Schritt erfolgreich
  # ausfaellt, auch wenn keine Leseberechtigung besteht.
  #
  if (! $mustabort) {
    $handle->GetOldest($oldestoffset);
    $handle->GetNumber($numevents);
    if (! defined $numevents) {
      # cygwin perl sagt zu allem errorcode=0, auch wenn keine berechtigung
      # zum zugriff vorliegt. aber ein undef ist zumindest ein indiz, dass
      # etwas faul ist.
      $mustabort = 1;
      $internal_error = "Eventlog permission denied";
    }
  }
  #
  # Schritt 5
  #
  # Jetzt beginnt das eigentliche Auslesen des Eventlogs
  #
  if (! $mustabort) {
    if ($numevents) { 
      $newestoffset = $oldestoffset + $numevents - 1;
      trace(sprintf "eventlog has offsets %d..%d",
          $oldestoffset, $newestoffset);
      if (! $eventlog->{speedup}) {
        $firstoffset = $oldestoffset;
      } else {
        # new method. find the first event which lies within the range
        # oldestoffset <= offset <= newestoffset
        $save_newestoffset = $newestoffset;
        $handle->Read((EVENTLOG_SEEK_READ|EVENTLOG_BACKWARDS_READ),
            $oldestoffset, $event);
        $offsetcache->{$oldestoffset} = $event->{Timewritten};
        if ($event->{Timewritten} >= $eventlog->{lastsecond}) {
          # even the oldest record was created after the last run 
          # of check_logfiles. the log was cleared or this is the first run ever
          $firstoffset = $oldestoffset;
          trace(sprintf "i start from the beginning %d", $firstoffset);
        } else {
          $handle->Read((EVENTLOG_SEEK_READ|EVENTLOG_BACKWARDS_READ),
              $newestoffset, $event);
          $offsetcache->{$newestoffset} = $event->{Timewritten};
          if ($event->{Timewritten} >= $eventlog->{lastsecond}) {
            # the latest event was created after the last run of check_logfiles
            $seekoffset = $newestoffset;
            trace(sprintf "start at offset %d", $seekoffset);
            do {
              # get the seekoffset's time
              $handle->Read((EVENTLOG_SEEK_READ|EVENTLOG_BACKWARDS_READ),
                  $seekoffset, $event);
              $offsetcache->{$seekoffset} = $event->{Timewritten};
              if ($event->{Timewritten} >= $eventlog->{lastsecond}) {
                # inside the search interval. but is it the oldest?
                if ((exists $offsetcache->{$seekoffset - 1}) &&
                    ($offsetcache->{$seekoffset - 1} < 
                    $eventlog->{lastsecond})) {
                  $firstoffset = $seekoffset;
                  trace(sprintf "found first offset %d (=)", $firstoffset);
                } else {
                  $newestoffset = $seekoffset;
                  $seekoffset = 
                      $oldestoffset + int (($seekoffset - $oldestoffset) / 2);
                  trace(sprintf "try offset %d (<)", $seekoffset);
                }
              } else {
                # too old. but maybe the next offset?
                if ((exists $offsetcache->{$seekoffset + 1}) &&
                    ($offsetcache->{$seekoffset + 1} >= 
                    $eventlog->{lastsecond})) {
                  $firstoffset = $seekoffset + 1;
                  trace(sprintf "found first offset %d (+)", $firstoffset);
                } else {
                  $oldestoffset = $seekoffset;
                  $seekoffset = 
                      $seekoffset + int (($newestoffset - $seekoffset) / 2);
                  trace(sprintf "try offset %d (>)", $seekoffset);
                }
              }
            } while (! $firstoffset);
            # now position at the first element in question
            $handle->Read((EVENTLOG_SEEK_READ|EVENTLOG_BACKWARDS_READ),
                $firstoffset, $event);
            # adjust the number of elements to scan
            $newestoffset = $save_newestoffset;
          } else {
            # there are no new events
            # fake firstoffset to avoid entering the while loop
            $firstoffset = $newestoffset + 1;
            trace(sprintf "no new events fake %d", $firstoffset);
          }
        }
      }
      while ($firstoffset <= $newestoffset) {
        # sequential_reads are not reliable, so better use direct access
        $handle->Read((EVENTLOG_SEEK_READ|EVENTLOG_FORWARDS_READ),
            $firstoffset, $event);
        if (($event->{Timewritten} >= $eventlog->{lastsecond}) &&
          ($event->{Timewritten} < $eventlog->{thissecond})) {
          if (included($event, $eventlog->{include}) && 
              ! excluded($event, $eventlog->{exclude})) {
            #printf STDERR "passed filter %s\n", Data::Dumper::Dumper($event);
            my $tmp_event = {};
            %{$tmp_event} = %{$event};
            Win32::EventLog::GetMessageText($tmp_event);
            format_message($eventlogformat, $tmp_event);
            if ($winwarncrit) {
              if ($tmp_event->{EventType} == EVENTLOG_WARNING_TYPE) {
                $tmp_event->{Message} = "EE_WW_TT".$tmp_event->{Message};
              } elsif ($tmp_event->{EventType} == EVENTLOG_ERROR_TYPE) {
                $tmp_event->{Message} = "EE_EE_TT".$tmp_event->{Message};
              }
            }
            push(@events, $tmp_event);
          } else {
            #printf STDERR "blocked by filter %s\n", Data::Dumper::Dumper($event);
          }
        }
        $firstoffset++;
      }
    } else {
      #printf STDERR "0 events\n";
    }
  } else {
    my $now = time;
    my $tmp_event = {};
    $tmp_event->{Message} = 
        "EE_UU_TTCHECK_LOGFILES INTERNAL ERROR ".$internal_error;
    $tmp_event->{Message} =~ s/\0/ /g;
    $tmp_event->{Message} =~ s/\s*$//g;
    $tmp_event->{TimeGenerated} = $now;
    $tmp_event->{Timewritten} = $now;
    $tmp_event->{Source} = 'check_logfiles'; # internal usage
    $tmp_event->{EventType} = EVENTLOG_ERROR_TYPE; # internal usage
    $tmp_event->{EventID} = 0;
    format_message($eventlogformat, $tmp_event);
    push(@events, $tmp_event) if $internal_error;
  }
  #
  # Aufraeumen
  #
  $handle->Close() if $handle;
  if ($must_close_ipc) {
    if (Win32::NetResource::CancelConnection(
        "\\\\".$eventlog->{computer}."\\IPC\$", 0, 0)) {
      trace("closed the ipc connection");
    } else {
      trace("could not close the ipc connection");
      if (Win32::NetResource::CancelConnection(
          "\\\\".$eventlog->{computer}."\\IPC\$", 0, 1)) {
        trace("closed the ipc connection by force");
      } else {
        trace("could not close the ipc connection even by force");
      }
    }
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
    return $event->{Message};
  } else {
    return undef;
  }
}

sub format_message {
  my $eventlogformat = shift;
  my $event = shift;
  # formatstring:
  # %t EventType
  # %c Category
  # %s Source
  # %i EventID
  # %m Message
  # %w Timewritten
  # %g Timegenerated
  # %d Date/Time
  # %u User # not documented @ cpan
  if ($eventlogformat eq "_tecad_win_") {
    $eventlogformat = "%__TiVoLi__g %C %t N/A %s %__TiVoLi__i %m";
  }
  if (! $event->{Message}) {
      $event->{Message} = $event->{Strings};
      $event->{Message} =~ s/\0/ /g;
      $event->{Message} =~ s/\s*$//g;
  }
  $event->{Message} = 'unknown message' if ! $event->{Message};
  $event->{Message} =~ tr/\r\n/ /d;
  my $tz = '';
  my $format = {};
  $format->{'%t'} =
      ($event->{EventType} == -1) ?
          'Internal' :
      ($event->{EventType} == EVENTLOG_WARNING_TYPE) ?
          'Warning' :
      ($event->{EventType} == EVENTLOG_ERROR_TYPE) ?
          'Error' :
      ($event->{EventType} == EVENTLOG_INFORMATION_TYPE) ?
          'Information' :
      ($event->{EventType} == EVENTLOG_AUDIT_SUCCESS) ?
          'AuditSuccess' :
      ($event->{EventType} == EVENTLOG_AUDIT_FAILURE) ?
          'AuditFailure' :
      ($event->{EventType} == EVENTLOG_SUCCESS) ?
          'Success' : 'UnknType';
  $format->{'%c'} = ! $event->{Category} ? 'None' :
      join('_', split(" ", $event->{Category}));
  $format->{'%C'} = ! $event->{Category} ? 'None' : $event->{Category};
  $format->{'%s'} = join('_', split(" ", $event->{Source}));
  $format->{'%i'} = sprintf '%04d', $event->{EventID} & 0xffff;
  $format->{'%__TiVoLi__i'} = sprintf '%s', $event->{EventID} & 0xffff;
  $format->{'%m'} = $event->{Message};
  $format->{'%w'} = strftime("%Y-%m-%dT%H:%M:%S",
      localtime($event->{Timewritten})).$tz;
  $format->{'%g'} = strftime("%Y-%m-%dT%H:%M:%S",
      localtime($event->{TimeGenerated})).$tz;
  $format->{'%W'} = $event->{Timewritten};
  $format->{'%G'} = $event->{TimeGenerated};
  $format->{'%u'} = $event->{User} || 'undef';
  $format->{'%__TiVoLi__g'} = join(" ", (split(/\s+/,
      scalar localtime $event->{TimeGenerated}))[1,2,3,4]);
      # month day time and year => %t %s
  my $message = $eventlogformat;
  foreach (keys %{$format}) {
    $message =~ s/$_/$format->{$_}/g;
  }
  while ($message =~ /%(\d+)m/) {
    my $search = "%".$1."m";
    my $replace = sprintf "%.".$1."s", $event->{Message};
    $message =~ s/$search/$replace/g;
  }
  $event->{Message} = $message;
}

sub included {
  my $event = shift;
  my $filter = shift;
  my $filters = 0;
  my $matches = {};
  # EventCategory ist ein INTEGER!!!
  # und ausserdem ist pro Source ein eigener Satz von Kategorien moeglich
  # man muesste deren Bezeichnungen aus der Registry lesen.
  # in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application
  # stehen die Sources, die eigene Kategorien definiert haben.
  # Im Key CategoryMessageFile ist die Datei hinterlegt, der die Kategorien
  # entnommen werden koennen. In CategoryCount steht die Anzahl der
  # selbstdefinierten Kategorien.
  foreach my $attr (qw(Source Category)) {
    $matches->{$attr} = 0;
    if (exists $filter->{$attr}) {
      foreach my $item (split(',', $filter->{$attr})) {
        #printf "items: %s ? %s\n", $item, $event->{$attr};
        if (lc $item eq lc $event->{$attr}) {
          #printf "-> %s eq %s\n", lc $item, lc $event->{$attr};
          $matches->{$attr}++;
        }
      }
    } else {
      #printf "no filter for %s\n", $attr;
      $matches->{$attr}++;
    }
  }
  foreach my $attr (qw(EventID)) {
    $matches->{$attr} = 0;
    if (exists $filter->{$attr}) {
      foreach my $item (split(',', $filter->{$attr})) {
        #printf "items: %s ? %s\n", $item, $event->{$attr};
        #if (lc $item eq lc ($event->{$attr} & 0xffff)) {
        if ($item == ($event->{$attr} & 0xffff)) {
          #printf "-> %s eq %s\n", lc $item, lc ($event->{$attr} & 0xffff);
          $matches->{$attr}++;
        }
      }
    } else {
      #printf "no filter for %s\n", $attr;
      $matches->{$attr}++;
    }
  }
  foreach my $attr (qw(EventType)) {
    $matches->{$attr} = 0;
    if (exists $filter->{$attr}) {
#printf "succ %s\n", EVENTLOG_SUCCESS;
#printf "warn %s\n", EVENTLOG_WARNING_TYPE;
#printf "err %s\n", EVENTLOG_ERROR_TYPE;
#printf "info %s\n", EVENTLOG_INFORMATION_TYPE;
#printf "audit %s\n", EVENTLOG_AUDIT_SUCCESS;
#printf "fail %s\n", EVENTLOG_AUDIT_FAILURE;
      foreach my $item (split(',', $filter->{$attr})) {
        if ((lc $item =~ /^succ/ && $event->{$attr} == EVENTLOG_SUCCESS) ||
            (lc $item =~ /warn/ && $event->{$attr} == EVENTLOG_WARNING_TYPE) ||
            (lc $item =~ /err/ && $event->{$attr} == EVENTLOG_ERROR_TYPE) ||
            (lc $item =~ /info/ && $event->{$attr} == EVENTLOG_INFORMATION_TYPE) ||
            (lc $item =~ /audit.*succ/ && $event->{$attr} == EVENTLOG_AUDIT_SUCCESS) ||
            (lc $item =~ /fail/ && $event->{$attr} == EVENTLOG_AUDIT_FAILURE)) {
          $matches->{$attr}++;
        }
      }
    } else {
      #printf "no filter for %s\n", $attr;
      $matches->{$attr}++;
    }	
  }
  if ($filter->{operation} eq 'and') {
    return (scalar(grep { $matches->{$_} } keys %{$matches}) == 4) ? 1 : 0;
  } else {
    return (scalar(grep { $matches->{$_} } keys %{$matches}) == 0) ? 0 : 1;
  }
}

sub excluded {
  my $event = shift;
  my $filter = shift;
  my $filters = 0;
  my $matches = {};
  # EventCategory ist ein INTEGER!!!
  foreach my $attr (qw(Source Category)) {
    $matches->{$attr} = 0;
    if (exists $filter->{$attr}) {
      foreach my $item (split(',', $filter->{$attr})) {
        #printf "items: %s ? %s\n", $item, $event->{$attr};
        if (lc $item eq lc $event->{$attr}) {
          #printf "-> %s eq %s\n", lc $item, lc $event->{$attr};
          $matches->{$attr}++;
        }
      }
    } else {
      #printf "no filter for %s\n", $attr;
      #$matches->{$attr}++;
    }
  }
  foreach my $attr (qw(EventID)) {
    $matches->{$attr} = 0;
    if (exists $filter->{$attr}) {
      foreach my $item (split(',', $filter->{$attr})) {
        #printf "items: %s ? %s\n", $item, $event->{$attr};
        #if (lc $item eq lc ($event->{$attr} & 0xffff)) {
        if ($item == ($event->{$attr} & 0xffff)) {
          #printf "-> %s eq %s\n", lc $item, lc ($event->{$attr} & 0xffff);
          $matches->{$attr}++;
        }
      }
    } else {
      #printf "no filter for %s\n", $attr;
      #$matches->{$attr}++;
    }
  }
  foreach my $attr (qw(EventType)) {
    $matches->{$attr} = 0;
    if (exists $filter->{$attr}) {
      foreach my $item (split(',', $filter->{$attr})) {
        if ((lc $item =~ /^succ/ && $event->{$attr} == EVENTLOG_SUCCESS) ||
            (lc $item =~ /warn/ && $event->{$attr} == EVENTLOG_WARNING_TYPE) ||
            (lc $item =~ /err/ && $event->{$attr} == EVENTLOG_ERROR_TYPE) ||
            (lc $item =~ /info/ && $event->{$attr} == EVENTLOG_INFORMATION_TYPE) ||
            (lc $item =~ /audit.*succ/ && $event->{$attr} == EVENTLOG_AUDIT_SUCCESS) ||
            (lc $item =~ /fail/ && $event->{$attr} == EVENTLOG_AUDIT_FAILURE)) {
          #printf "type %s matched\n", $item;
          $matches->{$attr}++;
        }
      }
    } else {
      #printf "no filter for %s\n", $attr;
      #$matches->{$attr}++;
    }	
  }
  #printf "%s\n", Data::Dumper::Dumper($matches);
  if ($filter->{operation} eq 'and') {
    return (scalar(grep { $matches->{$_} } keys %{$matches}) == 4) ? 1 : 0;
  } else {
    return (scalar(grep { $matches->{$_} } keys %{$matches}) == 0) ? 0 : 1;
  }
}

sub trace {
  my $format = shift;
  if (-f $tracefile) {
    my $logfh = new IO::File;
    $logfh->autoflush(1);
    if ($logfh->open($tracefile, "a")) {
      $logfh->printf("%s: ", scalar localtime);
      $logfh->printf($format, @_);
      $logfh->printf("\n");
      $logfh->close();
    }
  }
}


sub AUTOLOAD {
 #printf "uarghh %s\n", $AUTOLOAD;
}

1;
