package Nagios::CheckLogfiles::Search::Errpt;

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
  $self->{logfile} = sprintf "%s/errpt.%s", $self->{seekfilesdir},
      $self->{tag};
  $self->SUPER::init($params);
  $self->{clo} = {
  	path => $params->{errpt}->{path} ? 
  	    $params->{errpt}->{path} : "/usr/bin/errpt",
    errortype => $params->{errpt}->{errortype},
    errorclass => $params->{errpt}->{errorclass},
    errorlabel => $params->{errpt}->{errorlabel},
    errorresource => $params->{errpt}->{errorresource},
  };
  $self->addfilter(0, 'IDENTIFIER TIMESTAMP');
}
  
sub prepare {
  my $self = shift;
  $self->{options}->{nologfilenocry} = 1;
  # the last minute is the end time. in-progess minutes are not 
  # interesting yet.
  my($sec, $min, $hour, $mday, $mon, $year) = 
      #(localtime $self->{macros}->{CL_DATE_TIMESTAMP})[0, 1, 2, 3, 4, 5];
      # macro is not suitable for testing because it is not updated
      (localtime time)[0, 1, 2, 3, 4, 5];
  $self->{errpt}->{endtime} = 
      timelocal(0, $min, $hour, $mday, $mon, $year) - 60;
}

sub loadstate {
  my $self = shift;
  $self->SUPER::loadstate();
  # always scan the whole output. thst's what starttime is for.
  $self->{laststate}->{logoffset} = 0;
  # if this is the very first run, look back 5 mintes in the past.
  $self->{errpt}->{starttime} = $self->{laststate}->{logtime} ?
      $self->{laststate}->{logtime} + 60 : $self->{errpt}->{endtime} - 300;
}

sub savestate {
  my $self = shift;
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
  # remember the last minute scanned.
  $self->{newstate}->{logtime} = $self->{errpt}->{endtime};
  $self->SUPER::savestate();
}

sub analyze_situation {
  my $self = shift;
  if ($self->{errpt}->{starttime} <= $self->{errpt}->{endtime}) {
    $self->{logmodified} = 1; 
  } else {
    # this happens if you call the plugin in too short intervals.
    $self->trace("%s not before %s", 
        scalar localtime $self->{errpt}->{starttime},
        scalar localtime $self->{errpt}->{endtime});
  }
}

sub collectfiles {
  my $self = shift;
  my $fh = new IO::File;
  if ($self->{logmodified}) {
    my($sec, $min, $hour, $mday, $mon, $year) = 
        (localtime $self->{errpt}->{starttime})[0, 1, 2, 3, 4, 5];
    $self->{errpt}->{ibmstarttime} = sprintf "%02d%02d%02d%02d%02d",
        $mon + 1, $mday, $hour, $min, substr($year + 1900, 2, 2);
    ($sec, $min, $hour, $mday, $mon, $year) = 
        (localtime $self->{errpt}->{endtime})[0, 1, 2, 3, 4, 5];
    $self->{errpt}->{ibmendtime} = sprintf "%02d%02d%02d%02d%02d",
        $mon + 1, $mday, $hour, $min, substr($year + 1900, 2, 2);
    my $errpt = sprintf "%s -s %s -e %s %s %s %s %s|", $self->{clo}->{path},
        $self->{errpt}->{ibmstarttime}, $self->{errpt}->{ibmendtime},
        $self->{clo}->{errortype} ? '-T '.$self->{clo}->{errortype} : "",
        $self->{clo}->{errorclass} ? '-d '.$self->{clo}->{errorclass} : "",
        $self->{clo}->{errorlabel} ? '-J '.$self->{clo}->{errorlabel} : "",
        $self->{clo}->{errorresource} ? '-N '.$self->{clo}->{errorresource} : "";
    $self->trace("calling %s", $errpt); 
    $self->trace("calling errpt -s (%s) -e (%s)", 
        scalar localtime $self->{errpt}->{starttime},
        scalar localtime $self->{errpt}->{endtime});
    if ($fh->open($errpt)) {
      push(@{$self->{relevantfiles}},
        { filename => "errpt|",
          fh => $fh, seekable => 0, statable => 1,
          modtime => $self->{errpt}->{endtime},
          fingerprint => "0:0" });
    } else {
      $self->trace("cannot execute errpt");
      $self->addmatch('UNKNOWN', "cannot execute errpt");
    }
  }
}

