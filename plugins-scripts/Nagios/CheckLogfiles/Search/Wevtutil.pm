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

sub iso {
  my $self = shift;
  my $timestamp = shift;
  my($sec, $min, $hour, $mday, $mon, $year) =
      (gmtime $timestamp)[0, 1, 2, 3, 4, 5];
  return sprintf "%02d-%02d-%02dT%02d:%02d:%02d",
      $year + 1900, $mon + 1, $mday, $hour, $min, $sec;
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
  }
}


package Nagios::CheckLogfiles::Search::Wevtutil::Handle;

use strict;
use Exporter;
use POSIX qw(strftime);
require Tie::Handle;
use IO::File;
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
printf STDERR "getline %s\n", $line;
        push(@events, $line);
      }
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
  return $self;
}

sub AUTOLOAD {
 # sonst mault perl wegen inherited autoload deprecated blabla
}

sub iso {
  my $timestamp = shift;
  my($sec, $min, $hour, $mday, $mon, $year) =
      ($^O =~ "MSWin" ? gmtime $timestamp : localtime $timestamp)[0, 1, 2, 3, 4, 5];
  my $iso = sprintf "%02d-%02d-%02dT%02d:%02d:%02d",
      $year + 1900, $mon + 1, $mday, $hour, $min, $sec;
printf STDERR "iso %s -> %s\n", scalar localtime $timestamp, $iso;
 return $iso;
}


1;
