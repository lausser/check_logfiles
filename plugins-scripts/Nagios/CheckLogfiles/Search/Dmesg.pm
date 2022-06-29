package Nagios::CheckLogfiles::Search::Dmesg;

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
  $self->{logfile} = '/dmesg/is/cool';
  $self->default_options({ warncrit => 0, randominode => 1,
      dmesgformat => "%w %c: %m" });
  $self->SUPER::init($params);
  if ($self->get_option('warncrit')) {
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
  $self->{dmesg} = {
      path => $params->{dmesg}->{path} ? $params->{dmesg}->{path} :
          "/bin/dmesg",
      currentsecond => time,
  };
}
    
sub prepare {
  my $self = shift;
  $self->{options}->{nologfilenocry} = 1;
  $self->trace(sprintf "i will discard messages newer or equal than %s", 
      scalar localtime $self->{dmesg}->{currentsecond});
}

sub loadstate {
  my $self = shift;
  $self->SUPER::loadstate();
  # always scan the whole output. thst's what starttime is for.
  $self->{laststate}->{logoffset} = 0;
  # if this is the very first run, look back 5 mintes in the past.
  $self->{laststate}->{logtime} = $self->{laststate}->{logtime} ?
      $self->{laststate}->{logtime} : $self->{dmesg}->{currentsecond} - 600;
}

sub savestate {
  my $self = shift;
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
  # remember the second when we started (events with a timestamp >= this are ignored)
  $self->{newstate}->{logtime} = $self->{dmesg}->{currentsecond};
  $self->SUPER::savestate();
}

sub analyze_situation {
  my $self = shift;
  if ($self->{dmesg}->{currentsecond} == $self->{laststate}->{logtime}) {
    # this happens if you call the plugin in too short intervals.
    $self->trace("please wait for a second"); 
  } else {
    # >= $self->{laststate}->{logtime} and < $self->{dmesg}->{currentsecond}
    $self->trace("last scanned until (not including) %s", 
        scalar localtime $self->{laststate}->{logtime});
    $self->{dmesg}->{distance} = 
        int(($self->{dmesg}->{currentsecond} -
        $self->{laststate}->{logtime}) / 60);
    $self->trace("analyze events from the last %d minutes", 
        $self->{dmesg}->{distance});
    $self->trace(sprintf ">= %s < %s",
        scalar localtime $self->{laststate}->{logtime},
        scalar localtime $self->{dmesg}->{currentsecond});
    $self->{logmodified} = 1; 
    # eingeschlossen
    $self->{dmesg}->{fromsecond} = $self->{laststate}->{logtime};
    # ausgeschlossen
    $self->{dmesg}->{tosecond} = $self->{dmesg}->{currentsecond};
  }
}

sub collectfiles {
  my $self = shift;
  my $fh = new IO::File;
  if ($self->{logmodified}) {
    my $command = sprintf "%s -x 2>/dev/null |",
        $self->{dmesg}->{path};
    $self->trace("calling %s", $command);
    tie *{$fh}, 'Nagios::CheckLogfiles::Search::Dmesg::Handle',
        $command,
        $self->{dmesg},
        $self->{options},
        $self->{tracefile};
    if ($fh->open($command)) {
      push(@{$self->{relevantfiles}},
        { filename => "dmesg|",
          fh => $fh, seekable => 0, statable => 0,
          modtime => $self->{dmesg}->{nowminute},
          fingerprint => "0:0" });
    } else {
      $self->trace("cannot execute dmesg");
      $self->addmatch('UNKNOWN', "cannot execute dmesg");
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
        $match->[1] =~ s/EE_WW_TT//;
        $match->[1] =~ s/EE_EE_TT//;
        $match->[1] =~ s/EE_UU_TT//;
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
  $self->{dmesg}->{currentsecond} = 1;
  $self->SUPER::rewind();
  return $self;
}


package Nagios::CheckLogfiles::Search::Dmesg::Handle;

use strict;
use Exporter;
use Time::Local;
use POSIX qw(strftime);
require Tie::Handle;
use Carp;
use IO::File;
use vars qw(@ISA);
@ISA = qw(Tie::Handle Nagios::CheckLogfiles::Search::Dmesg);
our $AUTOLOAD;
our $tracefile;
our $dmesg = {};
our $options = {};
our $uptime = undef;
our $boottime = undef;

sub TIEHANDLE {
  my $class = shift;
  my $command = shift;
  $dmesg = shift;
  $options = shift;
  $tracefile = shift;
  ($uptime) = do { local @ARGV="/proc/uptime";<>}; ($uptime) = ($uptime =~ /^([\d\.]+)/);
  # zumindest unter wsl2 springt die boottime in der gegend rum.
  # update, auch auf servern mit enterprise-linuxen kann es vorkommen,
  # dass der folgende boottime-wert schwankt. das hat zur folge, dass
  # events unerkannt durchrutschen koennen. es liegt nicht in meiner macht,
  # das zu aendern. beschwert euch beim torvalds oder bei dem distributor,
  # dem ihr jedem monat ein vermoegen in den rachen schmeisst.
  # aber schon klar, ihr werdet das nicht machen, sondern stattdessen
  # mir mit eurem gewinsel auf den sack gehen.
  $boottime = time - $uptime;
  my $self = {};
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
  my $self = shift;
  while (! eof($self)) {
    my $line = <$self>;
    if (! defined $line) {
      return undef;
    }
    # kern  :warn  : [    2.939748] OTG VER PARAM: 0, OTG VER FLAG: 0
    # kern  :warn  : [    2.942712] Dedicated Tx FIFOs mode
    # 
    # kern  :warn  : [    2.946352] WARN::dwc_otg_hcd_init:1074: FIQ DMA bounce buffers: virt = b7504000 dma = 0xf7504000 len=9024
    # kern  :warn  : [    2.955065] FIQ FSM acceleration enabled for :
    #                               Non-periodic Split Transactions
    #                               Periodic Split Transactions
    #                               High-Speed Isochronous Endpoints
    #                               Interrupt/Control Split Transaction hack enabled
    # kern  :debug : [    2.969719] dwc_otg: Microframe scheduler enabled
    # 
    # kern  :warn  : [    2.969791] WARN::hcd_init_fiq:457: FIQ on core 1
    # 
    # kern  :warn  : [    2.975200] WARN::hcd_init_fiq:458: FIQ ASM at 807cb8b8 length 36
    # 
    # kern  :warn  : [    2.980487] WARN::hcd_init_fiq:497: MPHI regs_base at bb810000
    # kern  :info  : [    2.985907] dwc_otg 3f980000.usb: DWC OTG Controller
    if (! $line) {
      next;
    }
    if ($line !~ /^\w+\s*:\w+\s*: \[/) {
      next;
    }
    my($origin, $level, $message) = split(/:/, $line, 3);
    ( $origin =~ /^\s+/ ) && ( substr( $origin, 0, $+[ 0 ] ) = "" );
    ( $origin =~ /\s+$/ ) && ( substr( $origin, $-[ 0 ] )    = "" );
    ( $level =~ /^\s+/ ) && ( substr( $level, 0, $+[ 0 ] ) = "" );
    ( $level =~ /\s+$/ ) && ( substr( $level, $-[ 0 ] )    = "" );
    $message =~ /^\s*\[\s*(([\d]+)\.\d+)\]\s*(.*)$/;
    my $timegenerated = $boottime + $1;
    my $finetime = $boottime + $2;
    my $tmp_event = {
      'Category' => $origin,
      'Level' => $level,
      'TimeGenerated' => $timegenerated,
      'FineTimeGenerated' => $finetime,
      'Message' => $3,
    };
    if ($tmp_event->{TimeGenerated} >= $dmesg->{fromsecond} &&
        $tmp_event->{TimeGenerated} < $dmesg->{tosecond}) {
      $tmp_event->{Message} =~ tr/\r\n/ /d;
      if ($options->{warncrit}) {
        if ($tmp_event->{Level} eq "warn") {
          $tmp_event->{Message} = "EE_WW_TT".$tmp_event->{Message};
        } elsif ($tmp_event->{Level} =~ /^(err|crit|alert|emerg)/) {
          $tmp_event->{Message} = "EE_EE_TT".$tmp_event->{Message};
        }
      }
      return format_message($options->{dmesgformat}, $tmp_event);
    }
    # no return yet = all lines missed time/include/exclude filter
    # continue whth the while-loop and read the next line
  }
  # no more lines
  return undef;
}

sub format_message {
  my $dmesgformat = shift;
  my $event = shift;
  # formatstring:
  # %t Level
  # %s Source  (kern, daemon, syslog...)
  # %c Category (the program, systemd, blk_update_request,..)
  # %m Message
  # %w Timewritten
  #$event->{Message} =~ tr/\r\n/ /d;
  my $tz = '';
  my $format = {};
  $format->{'%t'} = $event->{Level};
  $format->{'%c'} = ! $event->{Category} ? 'None' :
      join('_', split(" ", $event->{Category}));
  $format->{'%C'} = ! $event->{Category} ? 'None' : $event->{Category};
  $format->{'%m'} = $event->{Message};
  $format->{'%w'} = strftime("%Y-%m-%dT%H:%M:%S",
      localtime($event->{TimeGenerated})).$tz;
  $format->{'%W'} = $event->{TimeGenerated};
  my $message = $dmesgformat;
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


sub AUTOLOAD {
 printf "uarghh %s\n", $AUTOLOAD;
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
