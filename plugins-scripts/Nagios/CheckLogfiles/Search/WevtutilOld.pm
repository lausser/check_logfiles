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

@ISA = qw(Nagios::CheckLogfiles::Search);

sub new {
  my $self = bless {}, shift;
  return $self->init(shift);
}

sub startofmin {
  my $self = shift;
  my $timestamp = shift;
  my($sec, $min, $hour, $mday, $mon, $year) =
      (localtime $timestamp)[0, 1, 2, 3, 4, 5];
  return timelocal(0, $min, $hour, $mday, $mon, $year);
}

sub iso {
  my $self = shift;
  my $timestamp = shift;
  my($sec, $min, $hour, $mday, $mon, $year) =
      (localtime $timestamp)[0, 1, 2, 3, 4, 5];
  return sprintf "%02d-%02d-%02dT%02d:%02d:%02d",
      $year + 1900, $mon + 1, $mday, $hour, $min, $sec;
}

sub init {
  my $self = shift;
  my $params = shift;
  $self->{logfile} = '/wevtutil/is/cool';
  $self->SUPER::init($params);
  $self->{clo} = {
      path => $params->{wevtutil}->{path} ? $params->{wevtutil}->{path} :
          ($^O =~ "MSWin") ? "C:/WINDOWS/system32/wevtutil" :
          "/cygdrive/c/WINDOWS/system32/wevtutil",
      eventlog => $params->{wevtutil}->{eventlog} || "system",
      source => $params->{wevtutil}->{provider} || $params->{wevtutil}->{source},
  };
}

sub prepare {
  my $self = shift;
  $self->{options}->{nologfilenocry} = 1;
  # the last minute is the end time. in-progess minutes are not
  # interesting yet.
  # 2015-03-25T16:08:12.000000000Z
  my($sec, $min, $hour, $mday, $mon, $year) =
      (localtime time)[0, 1, 2, 3, 4, 5];
  $self->{eventlog}->{thisminute} = $self->startofmin(time);
  $self->{eventlog}->{thisminuteiso} = $self->iso(
      $self->{eventlog}->{thisminute});
  $self->trace(sprintf "i will search until < %s",
      $self->{eventlog}->{thisminuteiso});
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
  $self->trace(sprintf "from %s to %s",
      scalar localtime ($self->{laststate}->{logtime}),
      scalar localtime $self->{eventlog}->{thisminute});
  if ((time - $self->{laststate}->{logtime}) > 60) {
    $self->{logmodified} = 1;
    my($sec, $min, $hour, $mday, $mon, $year) =
        (localtime ($self->{laststate}->{logtime} - 60))[0, 1, 2, 3, 4, 5];
    $self->{eventlog}->{thenminuteiso} = $self->iso(
        $self->{laststate}->{logtime});
  $self->trace(sprintf "from %s to %s",
    $self->{eventlog}->{thenminuteiso},
    $self->{eventlog}->{thisminuteiso});
  } else {
    # this happens if you call the plugin in too short intervals.
    $self->trace("please wait for a minute");
  }
}

sub collectfiles {
  my $self = shift;
  my $fh = new IO::File;
  if ($self->{logmodified}) {
    # thisminute in xpath-format, query < 
    # $self->{laststate}->{logtime}, query >=
    my $eventlog = sprintf "%s query-events %s \"/query:*[System[TimeCreated[\@SystemTime>='%s' and \@SystemTime<'%s']]]\" %s", $self->{clo}->{path},
        $self->{clo}->{eventlog},
        $self->{eventlog}->{thenminuteiso},
        $self->{eventlog}->{thisminuteiso},
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
          modtime => $self->{eventlog}->{thisminute},
          fingerprint => "0:0" });
    } else {
      $self->trace("cannot execute wevtutil");
      $self->addevent('UNKNOWN', "cannot execute wevtutil");
    }
  }
}

1;











__END__
Nach zwei WOchen Schnauze voll vom Crimson-API für Win32::Eventlog. Geht auch einfacher:
https://social.technet.microsoft.com/Forums/windows/en-US/6f158957-28ea-4ce9-a688-ccfa7bbd16bd/wevtutil-command-options-for-date

