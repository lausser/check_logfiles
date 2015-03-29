package Nagios::CheckLogfiles::Search::Wevtutil;

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

@ISA = qw(Nagios::CheckLogfiles::Search::Eventlog);

sub init {
  my $self = shift;
  my $params = shift;
  # can be called with type=wevtutil:eventlog= or type=wevtutil:wevtutil=
  %{$params->{eventlog}} = %{$params->{wevtutil}} if $params->{wevtutil};
  $self->SUPER::init($params);
}

sub startofmin {
  my $self = shift;
  my $timestamp = shift;
  my($sec, $min, $hour, $mday, $mon, $year) =
      (gmtime $timestamp)[0, 1, 2, 3, 4, 5];
  return timegm(0, $min, $hour, $mday, $mon, $year);
}

sub collectfiles {
  my $self = shift;
  $self->trace(sprintf "get everything %d <= event < %d",
      $self->{eventlog}->{lastsecond},
      $self->{eventlog}->{thissecond});
printf STDERR "logmod %s\n", $self->{logmodified};
  if ($self->{logmodified}) {
    open(*FH, ">$self->{orschlorschknorsch}");
    tie *FH, 'Nagios::CheckLogfiles::Search::Wevtutil::Handle',
        $self->{eventlog},
        $self->get_option('winwarncrit'),
        $self->get_option('eventlogformat'),
        $self->get_option('logfilenocry'),
        $self->{tivoli},
        $self->{tracefile},
        ($^O =~ "MSWin") ? "C:/WINDOWS/system32/wevtutil" :
            "/cygdrive/c/WINDOWS/system32/wevtutil";
    push(@{$self->{relevantfiles}},
      { filename => "eventlog|",
        fh => *FH, seekable => 0, statable => 1,
        modtime => $self->{eventlog}->{thissecond},
        fingerprint => "0:0" });
printf STDERR "relevantfiles  %s\n", scalar(@{$self->{relevantfiles}});
  }
}


package Nagios::CheckLogfiles::Search::Wevtutil::Handle;

use strict;
use Exporter;
use POSIX qw(strftime);
require Tie::Handle;
use IO::File;
use Time::Piece;
use Date::Manip;
use constant EVENTLOG_INFORMATION_TYPE => 0x0004;
use constant EVENTLOG_WARNING_TYPE => 0x0002;
use constant EVENTLOG_ERROR_TYPE => 0x0001;
use vars qw(@ISA);
@ISA = qw(Nagios::CheckLogfiles::Search::Eventlog::Handle);
our $AUTOLOAD;
our $tracefile;
our @events = ();

sub TIEHANDLE {
  my $class = shift;
  my $eventlog = shift;
  my $winwarncrit = shift;
  my $eventlogformat = shift;
  my $logfilenocry = shift;
  my $tivoli = shift;
  $tracefile = shift;
  my $wevtutil = shift;
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
  # Schritt 3
  #
  # Oeffnen des Eventlogs
  #
  if (! $mustabort) {
# letzte sekunde lesen
#      $mustabort = 1;
#      $internal_error = "Eventlog permission denied";
  }
  #
  # Schritt 5
  #
  # Jetzt beginnt das eigentliche Auslesen des Eventlogs
  #
  if (! $mustabort) {
printf STDERR "eventlog %s\n", Data::Dumper::Dumper($eventlog);
    my $exec = sprintf "%s query-events %s \"/query:*[System[TimeCreated[\@SystemTime>='%s' and \@SystemTime<'%s']]]\" %s", $wevtutil,
        $eventlog->{eventlog},
        iso($eventlog->{lastsecond}),
        iso($eventlog->{thissecond}),
        ($^O eq "cygwin") ? '2>/dev/null |' : '2>NUL |';
printf STDERR "exec %s\n", $exec;
    trace("calling %s", $exec);
    my $fh = new IO::File;
    if ($fh->open($exec)) {
printf STDERR "iofile open\n";
      trace("calling %s", $exec);
      while (my $line = $fh->getline()) {
printf STDERR "getline-> %s\n", $line;
        my $event = transform($line);

            printf STDERR "passed filter %s\n", Data::Dumper::Dumper($event);



          if (included($event, $eventlog->{include}) &&
              ! excluded($event, $eventlog->{exclude})) {
            printf STDERR "really passed filter %s\n", Data::Dumper::Dumper($event);
            my $tmp_event = {};
            %{$tmp_event} = %{$event};
            #Win32::EventLog::GetMessageText($tmp_event);
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
            printf STDERR "blocked by filter %s\n", Data::Dumper::Dumper($event);
          }
















      }
printf STDERR "now close\n";
      $fh->close();
    } else {
printf STDERR "iofile failed\n";
      # haette in schritt 3 gefunden werden muessen
      trace("cannot execute wevtutil");
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
  bless $self, $class;
printf STDERR "%s tied with %d events\n", ref($self), scalar(@events);
  return $self;
}

sub READLINE {
  if (my $event = shift @events) {
printf STDERR "readline: %s\n", Data::Dumper::Dumper($event);
    return $event->{Message};
  } else {
printf STDERR "readline: empt\n";
    return undef;
  }
}

sub AUTOLOAD {
 # sonst mault perl wegen inherited autoload deprecated blabla
}

sub iso {
  my $timestamp = shift;
  #my $t = $^O =~ "MSWin" ? gmtime $timestamp : localtime $timestamp;
  my $t = localtime $timestamp;
printf "isoize %s to %s\n", scalar localtime $timestamp, $t->datetime();
  return $t->datetime;
  my($sec, $min, $hour, $mday, $mon, $year) =
      #($^O =~ "MSWin" ? gmtime $timestamp : localtime $timestamp)[0, 1, 2, 3, 4, 5];
      (gmtime $timestamp)[0, 1, 2, 3, 4, 5];
  my $iso = sprintf "%02d-%02d-%02dT%02d:%02d:%02d",
      $year + 1900, $mon + 1, $mday, $hour, $min, $sec;
printf STDERR "iso %s -> %s\n", scalar localtime $timestamp, $iso;
 return $iso;
}

sub transform {
  my $xml = shift;
#<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='check_logfiles'/><EventID Qualifiers='0'>1</EventID><Level>4</Level><Task>0</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2015-03-28T23:00:44.000000000Z'/><EventRecordID>120492</EventRecordID><Channel>Application</Channel><Computer>it10</Computer><Security UserID='S-1-5-21-1938173854-155546141-2860328369-1000'/></System><EventData><Data>Firewall problem2</Data></EventData></Event>
  my $event = {};
  $xml =~ /<Level>(\d+)<\/Level>/; $event->{EventType} = $1;
  $xml =~ /<Channel>(.+)<\/Channel>/; $event->{Category} = $1;
  $xml =~ /<Provider Name='(.*?)'\/>/; $event->{Source} = $1;
  $xml =~ /<EventID.*?>(\d+)<\/EventID>/; $event->{EventID} = sprintf "%04d", $1;
  $xml =~ /<Data>(.+)<\/Data>/; $event->{Message} = $1;
  $xml =~ /<Security UserID='(.*?)'\/>/; $event->{User} = $1;
  $xml =~ /<TimeCreated SystemTime='(.+?)'\/>/;
printf STDERR "transform %s\n", $1;
  my $t = ParseDate($1);
  $event->{TimeCreated} = UnixDate($t, "%s");
printf STDERR "to %s\n", $event->{TimeCreated};
  $event->{TimeWritten} = $event->{TimeCreated};
  return $event;
}
1;
