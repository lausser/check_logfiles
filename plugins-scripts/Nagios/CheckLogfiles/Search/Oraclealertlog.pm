package Nagios::CheckLogfiles::Search::Oraclealertlog;

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
  $self->{oraalert}->{tns} = {
    connect => $params->{oraclealertlog}->{connect} ||
        $params->{oraclealertlog}->{sid},
    username => $params->{oraclealertlog}->{username},
    password => $params->{oraclealertlog}->{password},
  };
  $self->{logfile} = sprintf "%s/alertlog.%s.%s", $self->{seekfilesdir},
      $self->{tag},
      $self->{oraalert}->{tns}->{connect};
  $self->SUPER::init($params);
  $self->resolve_macros(\$self->{oraalert}->{tns}->{connect});
  $self->resolve_macros(\$self->{oraalert}->{tns}->{username});
  $self->resolve_macros(\$self->{oraalert}->{tns}->{password});
  return $self;
}
    
sub prepare {
  my $self = shift;
  $self->{options}->{nologfilenocry} = 1;
  # the last second is the end time. in-progess seconds are not 
  # interesting yet.
  $self->{oraalert}->{highestfound} = 0;
}

sub loadstate {
  my $self = shift;
  $self->SUPER::loadstate();
  # always scan the whole output. thst's what starttime is for.
  $self->{laststate}->{logoffset} = 0;
  # if this is the very first run, look back 5 mintes in the past.
  # hopefully the clocks are synchronized
  $self->{laststate}->{logtime} = $self->{laststate}->{logtime} ?
      $self->{laststate}->{logtime} : time - 300;
}

sub savestate {
  my $self = shift;
    foreach (keys %{$self->{laststate}}) {
      $self->{newstate}->{$_} = $self->{laststate}->{$_};
    }
  # remember the last second scanned.
  $self->{newstate}->{logtime} = $self->{oraalert}->{highestfound} ?
      $self->{oraalert}->{highestfound} : $self->{laststate}->{logtime};
  $self->SUPER::savestate();
}

sub analyze_situation {
  my $self = shift;
  $self->trace("last scanned until %s",
      scalar localtime $self->{laststate}->{logtime});
  $self->{logmodified} = 1;
}

sub collectfiles {
  my $self = shift;
  my $fh = new IO::File;
  if ($self->{logmodified}) {
    # open database connection and select rows created
    # since $self->{laststate}->{logtime} and now (db now, not plugin now)
    my $linesread = 0;
    eval {
      require DBI;
      if (my $dbh = DBI->connect(
          sprintf("DBI:Oracle:%s", $self->{oraalert}->{tns}->{connect}),
          $self->{oraalert}->{tns}->{username},
          $self->{oraalert}->{tns}->{password},
          { RaiseError => 1, PrintError => 0 })) {
        $dbh->do(q{ ALTER SESSION SET NLS_NUMERIC_CHARACTERS=".," });
        # suchen bis zur letzten abgeschlossenen sekunde (inklusive)
        my $sql = q{
            SELECT alert_timestamp, alert_text FROM alert_log 
            WHERE ROUND(alert_timestamp) > ? AND alert_date <= SYSDATE - 1/86400
            ORDER BY alert_timestamp
        };
        if (my $sth = $dbh->prepare($sql)) {
          $self->trace(sprintf "select events between %d and now (%s and sysdate())",     
              $self->{laststate}->{logtime},
              scalar localtime $self->{laststate}->{logtime});
          $sth->execute($self->{laststate}->{logtime});
          if (my $fh = new IO::File($self->{logfile}, "w")) {
            while(my($alert_timestamp, $alert_text) = $sth->fetchrow_array()) {
              next if ! $alert_text; # es gibt auch leere Zeilen
              # bei ora-perl-conversion gibts manchmal 1234567890.999999999
              $alert_timestamp = int(0.5 + $alert_timestamp);
              $fh->printf("%s %s\n", scalar localtime $alert_timestamp, $alert_text);     
              $self->{oraalert}->{highestfound} = $alert_timestamp;
              $linesread++;
            }
            $fh->close();
          }
          $sth->finish();
        }
        $dbh->disconnect();
      }
    };
    if ($@) {
      $self->trace(sprintf "database operation failed: %s", $@);
      $self->addmatch('UNKNOWN', sprintf "database operation failed: %s", $@);
    }
    $self->trace(sprintf "read %d lines from database", $linesread);
    if ($linesread) {
      if (my $fh = new IO::File($self->{logfile}, "r")) {
        $self->trace(sprintf "reopen logfile");
        push(@{$self->{relevantfiles}},
          { filename => "eventlog|",
            fh => $fh, seekable => 0, statable => 1,
            modtime => time, # not relevant because already analyzed
            fingerprint => "0:0" });
      }
    }
  }
}

1;
