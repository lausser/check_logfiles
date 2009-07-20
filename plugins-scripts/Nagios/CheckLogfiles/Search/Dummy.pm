package Nagios::CheckLogfiles::Search::Dummy;

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
  $self->{logfile} = sprintf "%s/dummy.%s", $self->{seekfilesdir},
      $self->{tag};
  $self->SUPER::init($params);
}
  
sub prepare {
  my $self = shift;
  $self->{options}->{nologfilenocry} = 1;
}

sub loadstate {
  my $self = shift;
  $self->SUPER::loadstate();
}

sub savestate {
  my $self = shift;
}

sub analyze_situation {
  my $self = shift;
}

sub collectfiles {
  my $self = shift;
}

