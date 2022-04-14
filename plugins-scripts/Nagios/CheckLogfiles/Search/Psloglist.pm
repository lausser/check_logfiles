package Nagios::CheckLogfiles::Search::Psloglist;

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
  $self->{logfile} = '/psloglist/is/cool';
  $self->SUPER::init($params);
  $self->{clo} = {
  	path => $params->{psloglist}->{path} ? $params->{psloglist}->{path} :
  	    ($^O =~ "MSWin") ? "C:/Programme/PsTools/psloglist" :
  	    "/cygdrive/c/Programme/PsTools/psloglist",
    eventlog => $params->{psloglist}->{eventlog} || "system",
    computer => $params->{psloglist}->{computer},
    username => $params->{psloglist}->{username},
    password => $params->{psloglist}->{password},
    source => $params->{psloglist}->{source}
  };
}
    
sub prepare {
  my $self = shift;
  $self->{options}->{nologfilenocry} = 1;
  # the last minute is the end time. in-progess minutes are not 
  # interesting yet.
  my($sec, $min, $hour, $mday, $mon, $year) = 
      (localtime time)[0, 1, 2, 3, 4, 5];
  $self->{eventlog}->{thisminute} = 
      timelocal(0, $min, $hour, $mday, $mon, $year);
  $self->{eventlog}->{nowminutefilter} = sprintf "%02d.%02d.%4d %02d:%02d:.*",
      $mday, $mon + 1, $year + 1900, $hour, $min;
  $self->trace(sprintf "i will discard messages with %s", 
      $self->{eventlog}->{nowminutefilter});
  $self->addfilter(0, $self->{eventlog}->{nowminutefilter});
}

sub loadstate {
  my $self = shift;
  $self->SUPER::loadstate();
  # always scan the whole output. thst's what starttime is for.
  $self->{laststate}->{logoffset} = 0;
  # if this is the very first run, look back 5 mintes in the past.
  $self->{laststate}->{logtime} = $self->{laststate}->{logtime} ?
      $self->{laststate}->{logtime} : $self->{eventlog}->{thisminute} - 600;
}

sub savestate {
  my $self = shift;
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
  # remember the last minute scanned.
  $self->{newstate}->{logtime} = $self->{eventlog}->{thisminute};
  $self->SUPER::savestate();
}

sub analyze_situation {
  my $self = shift;
  $self->trace("last scanned until %s", 
      scalar localtime $self->{laststate}->{logtime});
  $self->{eventlog}->{distance} = 
      1 + int ((time - $self->{laststate}->{logtime}) / 60);
  $self->trace("analyze events from the last %d minutes", 
      $self->{eventlog}->{distance});
  $self->trace(sprintf "from %s to %s",
      scalar localtime (time - 60 * $self->{eventlog}->{distance}),
      scalar localtime time);
  if ((time - $self->{laststate}->{logtime}) > 60) {
    $self->{logmodified} = 1; 
    my($sec, $min, $hour, $mday, $mon, $year) = 
        (localtime ($self->{laststate}->{logtime} - 60))[0, 1, 2, 3, 4, 5];
    $self->{eventlog}->{thenminutefilter} = 
       sprintf "%02d.%02d.%4d %02d:%02d:.*",
        $mday, $mon + 1, $year + 1900, $hour, $min;
    $self->addfilter(0, $self->{eventlog}->{thenminutefilter});
    $self->trace(sprintf "filter %s\,", $self->{eventlog}->{nowminutefilter});
    $self->trace(sprintf "filter %s\,", $self->{eventlog}->{thenminutefilter});
  } else {
    # this happens if you call the plugin in too short intervals.
    $self->trace("please wait for a minute"); 
  }
}

sub collectfiles {
  my $self = shift;
  my $fh = new IO::File;
  if ($self->{logmodified}) {
    my $eventlog = sprintf "%s %s %s %s -s -m %d -r %s %s %s", $self->{clo}->{path},
        $self->{clo}->{computer} ? '\\\\'.$self->{clo}->{computer} : "",
        $self->{clo}->{username} ? '-u '.$self->{clo}->{username} : "",
        $self->{clo}->{password} ? '-p '.$self->{clo}->{password} : "",
        $self->{eventlog}->{distance},
        $self->{clo}->{source} ? '-o '.$self->{clo}->{source} : "",
        $self->{clo}->{eventlog},
        ($^O eq "cygwin") ? '2>/dev/null |' : '2>NUL |';
    $self->trace("calling %s", $eventlog);
    if ($fh->open($eventlog)) {
      while (my $line = $fh->getline()) {
    	$self->trace(sprintf "skipping header %s", $line);
        last if $line =~ /^\w+ log on/;
      }
      push(@{$self->{relevantfiles}},
        { filename => "eventlog|",
          fh => $fh, seekable => 0, statable => 1,
          modtime => $self->{eventlog}->{nowminute},
          fingerprint => "0:0" });
    } else {
      $self->trace("cannot execute psloglist");
      $self->addmatch('UNKNOWN', "cannot execute psloglist");
    }
  }
}

1;
