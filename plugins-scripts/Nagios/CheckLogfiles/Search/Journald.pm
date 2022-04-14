package Nagios::CheckLogfiles::Search::Journald;

use strict;
use Exporter;
use File::Basename;
use vars qw(@ISA);
use POSIX qw(strftime);

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
  $self->{logfile} = "/usr/bin/journalctl";
  $self->{journaldunit} = $params->{journald}->{unit};
  if ($self->{journaldunit} and $self->{tag} eq "default") {
    $self->{tag} = $self->{journaldunit};
  }
  $self->default_options({ exeargs => "", });
  $self->SUPER::init($params);
}

sub prepare {
  my $self = shift;
  $self->{options}->{nologfilenocry} = 1;
}

sub analyze_situation {
  my $self = shift;
  $self->{logmodified} = 1;
}

sub collectfiles {
  my $self = shift;
  my @rotatedfiles = ();
  my $fh = new IO::File;
  if ($self->getfileisexecutable($self->{logfile})) {
    my $cmdline = $self->{logfile};
    if ($self->{journaldunit}) {
      $cmdline = $cmdline." --unit '".$self->{journaldunit}."'";
    }
    $cmdline = $cmdline." --since '".strftime("%Y-%m-%d %H:%M:%S", localtime($self->{journald}->{since}))."'|";
    if ($fh->open($cmdline)) {
      push(@{$self->{relevantfiles}},
        { filename => $self->{logfile},
          fh => $fh, seekable => 0, statable => 1,
          modtime => time,
          fingerprint => "0:0" });
    } else {
      $self->trace("cannot execute ".$cmdline);
      $self->addmatch('UNKNOWN', "cannot execute ".$cmdline);
    }
  } else {
    if (-e $self->{logfile}) {
      #  permission problem
      $self->trace("could not open %s", $self->{logfile});
      $self->addmatch('CRITICAL', sprintf "could not open %s",
          $self->{logfile});
    } else {
      if ($self->get_option('logfilenocry')) {
        $self->trace("could not find %s", $self->{logfile});
        $self->addmatch($self->get_option('logfilemissing'),
            sprintf "could not find %s",
            $self->{logfile});
      } else {
        # dont care.
        $self->trace("could not find %s, but that's ok",
            $self->{logfile});
      }
    }
  }
}

sub loadstate {
  my $self = shift;
  $self->SUPER::loadstate();
  $self->{journald}->{since} = $self->{laststate}->{runtime} ? $self->{laststate}->{runtime} : time();
  $self->{laststate}->{logoffset} = 0;
}

sub savestate {
  my $self = shift;
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
  $self->SUPER::savestate();
}
