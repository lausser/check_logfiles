package Nagios::CheckLogfiles::Search::Dumpel;

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
  $self->{logfile} = '/dumpel/is/cool';
  $self->default_options({ winwarncrit => 0, eventlogformat => '%g %i %m',
      language => 'en', randominode => 1 });
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
  if (-f 'C:\Programme') {
    $self->set_option('language', 'de');
  }
  $self->{eventlog} = {
  	path => $params->{dumpel}->{path} ? $params->{dumpel}->{path} : (
            -f "C:/Programme" ? "C:/Programme/Resource Kit/dumpel" :
                    "C:/Program Files/Resource Kit/dumpel" ),
    eventlog => $params->{dumpel}->{eventlog} || "system",
    computer => $params->{dumpel}->{computer},
    username => $params->{dumpel}->{username},
    password => $params->{dumpel}->{password},
    source => $params->{dumpel}->{source},
    days => $params->{dumpel}->{days},
    include => $params->{eventlog}->{include} || {},
    exclude => $params->{eventlog}->{exclude} || {},
  };
  $self->resolve_macros(\$self->{eventlog}->{eventlog});
  $self->resolve_macros(\$self->{eventlog}->{computer}) if $self->{eventlog}->{computer};
  $self->resolve_macros(\$self->{eventlog}->{username}) if $self->{eventlog}->{username};
  $self->resolve_macros(\$self->{eventlog}->{password}) if $self->{eventlog}->{password};
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
  $self->trace(sprintf "i will discard messages newer or equal than %s", 
      scalar localtime $self->{eventlog}->{thisminute});
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
    $self->{eventlog}->{thenminute} =  $self->{laststate}->{logtime};
    $self->trace(sprintf "i will discard messages older than %s", 
        scalar localtime $self->{eventlog}->{thenminute});
  } else {
    # this happens if you call the plugin in too short intervals.
    $self->trace("please wait for a minute"); 
  }
}

sub collectfiles {
  my $self = shift;
  my $fh = new IO::File;
  if ($self->{logmodified}) {
    my $command = sprintf "%s -c -d %d -l %s %s %s",
        $self->{eventlog}->{path},
        $self->{eventlog}->{days} ? $self->{eventlog}->{days} : 1,
        $self->{eventlog}->{eventlog},
        $self->{eventlog}->{computer} ? '\\\\'.$self->{eventlog}->{computer} : "",
        ($^O eq "cygwin") ? '2>/dev/null |' : '2>NUL |';
    $self->trace("calling %s", $command);
    tie *{$fh}, 'Nagios::CheckLogfiles::Search::Dumpel::Handle',
        $command,
        $self->{eventlog},
        $self->{options},
        $self->{tivoli},
        $self->{tracefile};
    if ($fh->open($command)) {
      push(@{$self->{relevantfiles}},
        { filename => "eventlog|",
          fh => $fh, seekable => 0, statable => 0,
          modtime => $self->{eventlog}->{nowminute},
          fingerprint => "0:0" });
    } else {
      $self->trace("cannot execute dumpel");
      $self->addmatch('UNKNOWN', "cannot execute dumpel");
    }
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
}

sub rewind {
  my $self = shift;
  $self->loadstate();
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
  $self->addmatch(0, "reset");
  # 1 geht nicht weil NT sonst eine Minute vor 1970 landet beim loadstate
  $self->{eventlog}->{thisminute} = time - 3600 * 24 * 10;
  $self->savestate();
  return $self;
}


package Nagios::CheckLogfiles::Search::Dumpel::Handle;

use strict;
use Exporter;
use Time::Local;
use POSIX qw(strftime);
require Tie::Handle;
use Carp;
use IO::File;
use vars qw(@ISA);
@ISA = qw(Tie::Handle Nagios::CheckLogfiles::Search::Dumpel);
our $AUTOLOAD;
our $tracefile;
our $eventlog = {};
our $options = {};

use constant EVENTLOG_SUCCESS => 0x0000;
use constant EVENTLOG_ERROR_TYPE => 0x0001;
use constant EVENTLOG_INFORMATION_TYPE => 0x0004;
use constant EVENTLOG_WARNING_TYPE => 0x0002;
use constant EVENTLOG_AUDIT_FAILURE => 0x0010;
use constant EVENTLOG_AUDIT_SUCCESS => 0x0008;

sub TIEHANDLE {
  my $class = shift;
  my $command = shift;
  $eventlog = shift;
  $options = shift;
  my $tivoli = shift;
  $tracefile = shift;

  my $self = {};
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
  $self = new IO::File;
  if (open $self, $command) {
    return bless $self, $class;    # $self is a glob ref
  } else {
    return undef;
  }
}

sub SEEK {
  printf STDERR "i am SEEK\n";
}

sub FETCH {
  printf STDERR "i am FETCH\n";
}

sub STAT {
  printf STDERR "i am STAT\n";
  my $self = shift;
  return (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

sub OPEN {
  my $self = shift;
  my $filename = shift;
  $self->CLOSE;
  open($self, $filename)      or croak "can't reopen $filename: $!";
  return 1;
}

sub CLOSE {
  my $self = shift;
  return close $self;
}

sub GETC {
  printf STDERR "i am GETC\n";
}

sub READ {
  printf STDERR "i am READ\n";
}

sub DESTROY {
}

sub EOF {
  my $self = shift;
  return eof $self;
}


sub READLINE {
  # default output dtTCISucs
  # t - time
  # d - date
  # T - event type
  # C - event category
  # I event ID
  # S event source
  # u - user
  # c - computer
  # s - strings
  # 04.01.12,15:37:21,4,0,11707,MsiInstaller,N/A,LAUSSER6,Product: ActivePerl 5.14.2 Build 1402 -- Installation operation completed successfully.  
  my $self = shift;
  while (! eof($self)) {
    my $line = <$self>;
    if (! defined $line) {
      return undef;
    }
    $line =~ s/\015?\012?$//; 
    $line =~ s/\s+$//; 
    my($edate, $etime, $etype, $ecategory, $eid, $esource, $euser, $ecomputer, $estring) = split(/,/, $line, 9);
    my $timestamp = time;
    my $datetime = $edate.'#'.$etime;
    #if ($self->get_option('language') eq 'de') {
    if ($edate =~ /\d+\/\d+\/\d+/) {
      # 12/14/2005,10:08:41 AM,4,.....
      $datetime =~ /(\d+)\/(\d+)\/(\d+)#(\d+):(\d+):(\d+) (\w+)/;
      my ($month, $day, $year, $hour, $minute, $second, $pm) = ($1, $2, $3, $4, $5, $6, $7);
      $year += 2000 if $year < 100;
      $timestamp = timelocal($second, $minute, $hour, $day, $month - 1, $year);
      if ($pm eq 'PM') {
        $timestamp += 12 * 3600;
      }
    } else {
      # 04.01.12,15:30:11,1,0,....
      $datetime =~ /(\d+)\.(\d+)\.(\d+)#(\d+):(\d+):(\d+)/;
      my ($day, $month, $year, $hour, $minute, $second) = ($1, $2, $3, $4, $5, $6);
      $year += 2000 if $year < 100;
      $timestamp = timelocal($second, $minute, $hour, $day, $month - 1, $year);
    }
    my $tmp_event = {
      'Length' => 0,
      'RecordNumber' => 0,
      'TimeGenerated' => $timestamp,
      'Timewritten' => $timestamp,
      'EventID' => $eid,
      'EventType' => $etype,
      'Category' => $ecategory,
      'ClosingRecordNumber' => 0,
      'Source' => $esource,
      'Computer' => $ecomputer,
      'Strings' => $estring,
      'Data' => "",
      'User' => $euser,
    };
    if ($tmp_event->{TimeGenerated} >= $eventlog->{thenminute} &&
        $tmp_event->{TimeGenerated} < $eventlog->{thisminute}) {
      if (included($tmp_event, $eventlog->{include}) &&
          ! excluded($tmp_event, $eventlog->{exclude})) {
        #printf STDERR "passed filter %s\n", Data::Dumper::Dumper($tmp_event);
        if (! $tmp_event->{Message}) {
          $tmp_event->{Message} = $tmp_event->{Strings};
          $tmp_event->{Message} =~ s/\0/ /g;
          $tmp_event->{Message} =~ s/\s*$//g;
        }
        $tmp_event->{Message} = 'unknown message' if ! $tmp_event->{Message};
        $tmp_event->{Message} =~ tr/\r\n/ /d;
        if ($options->{winwarncrit}) {
          if ($tmp_event->{EventType} == EVENTLOG_WARNING_TYPE) {
            $tmp_event->{Message} = "EE_WW_TT".$tmp_event->{Message};
          } elsif ($tmp_event->{EventType} == EVENTLOG_ERROR_TYPE) {
            $tmp_event->{Message} = "EE_EE_TT".$tmp_event->{Message};
          }
        }
        return format_message($options->{eventlogformat}, $tmp_event);
      }
    }
    # no return yet = all lines missed time/include/exclude filter
    # continue whth the while-loop and read the next line
  }
  # no more lines
  return undef;
}   

sub AUTOLOAD {
 printf "uarghh %s\n", $AUTOLOAD;
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
  $format->{'%s'} = join('_', split(" ", $event->{Source}));
  $format->{'%i'} = sprintf '%04d', $event->{EventID} & 0xffff;
  $format->{'%m'} = $event->{Message};
  $format->{'%w'} = strftime("%Y-%m-%dT%H:%M:%S",
      localtime($event->{Timewritten})).$tz;
  $format->{'%g'} = strftime("%Y-%m-%dT%H:%M:%S",
      localtime($event->{TimeGenerated})).$tz;
  $format->{'%W'} = $event->{Timewritten};
  $format->{'%G'} = $event->{TimeGenerated};
  $format->{'%u'} = $event->{User} || 'undef';
  my $message = $eventlogformat;
  foreach (keys %{$format}) {
    $message =~ s/$_/$format->{$_}/g;
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

1;
