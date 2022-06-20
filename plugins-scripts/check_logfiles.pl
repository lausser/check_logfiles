package main;

use strict;
use utf8;
use File::Basename;
use File::Find;
use Getopt::Long;

#import Devel::TraceMethods qw( 
#    Nagios::CheckLogfiles
#    Nagios::CheckLogfiles::Search
#    Nagios::CheckLogfiles::Search::Simple
#    Nagios::CheckLogfiles::Search::Rotating
#    Nagios::CheckLogfiles::Search::Rotating::Uniform
#    Nagios::CheckLogfiles::Search::Virtual
#    Nagios::CheckLogfiles::Search::Prescript
#    Nagios::CheckLogfiles::Search::Postscript
#    Nagios::Tivoli::Config::Logfile
#    Nagios::Tivoli::Config::Logfile::Format
#    Nagios::Tivoli::Config::Logfile::Hit
#);
#Devel::TraceMethods::callback ( 
#    'Nagios::CheckLogfiles' => \&logger, 
#    'Nagios::CheckLogfiles::Search' => \&logger,
#    'Nagios::CheckLogfiles::Search::Simple' => \&logger,
#    'Nagios::CheckLogfiles::Search::Rotating' => \&logger,
#    'Nagios::CheckLogfiles::Search::Rotating::Uniform' => \&logger,
#    'Nagios::CheckLogfiles::Search::Virtual' => \&logger,
#    'Nagios::CheckLogfiles::Search::Prescript' => \&logger,
#    'Nagios::CheckLogfiles::Search::Postscript' => \&logger,
#    'Nagios::Tivoli::Config::Logfile' => \&logger,
#    'Nagios::Tivoli::Config::Logfile::Format' => \&logger,
#    'Nagios::Tivoli::Config::Logfile::Hit' => \&logger,
#);

use constant OK => 0;
use constant WARNING => 1;
use constant CRITICAL => 2;
use constant UNKNOWN => 3;

Getopt::Long::Configure qw(no_ignore_case); # compatibility with old perls
use vars qw (%commandline $SEEKFILESDIR $PROTOCOLSDIR $SCRIPTPATH);
$SEEKFILESDIR = '#SEEKFILES_DIR#';
$PROTOCOLSDIR = '#PROTOCOLS_DIR#';
$SCRIPTPATH = '#TRUSTED_PATH#';
my @cfgfiles = ();
my $needs_restart = 0;
my $enough_info = 0;

sub logger {
  my $method = shift;
  my @args = @_;
  printf STDERR "%s\n", $method;
  printf STDERR " %s\n", Data::Dumper::Dumper(\@args);
}

my $plugin_revision = '$Revision: 1.0 $ ';
my $progname = basename($0);

sub print_version {
  printf "%s v#PACKAGE_VERSION#\n", basename($0);
}

sub print_help {
  print <<EOTXT;
This Nagios Plugin comes with absolutely NO WARRANTY. You may use
it on your own risk!
Copyright by ConSol Software GmbH, Gerhard Lausser.

This plugin looks for patterns in logfiles, even in those who were rotated
since the last run of this plugin.

You can find the complete documentation at 
http://labs.consol.de/nagios/check_logfiles/

Usage: check_logfiles [-t timeout] -f <configfile>

The configfile looks like this:

\$seekfilesdir = '/opt/nagios/var/tmp';
# where the state information will be saved.

\$protocolsdir = '/opt/nagios/var/tmp';
# where protocols with found patterns will be stored.

\$scriptpath = '/opt/nagios/var/tmp';
# where scripts will be searched for.

\$MACROS = \{ CL_DISK01 => "/dev/dsk/c0d1", CL_DISK02 => "/dev/dsk/c0d2" \};

\@searches = (
  {
    tag => 'temperature',
    logfile => '/var/adm/syslog/syslog.log',
    rotation => 'bmwhpux',
    criticalpatterns => ['OVERTEMP_EMERG', 'Power supply failed'],
    warningpatterns => ['OVERTEMP_CRIT', 'Corrected ECC Error'],
    options => 'script,protocol,nocount',
    script => 'sendnsca_cmd'
  },
  {
    tag => 'scsi',
    logfile => '/var/adm/messages',
    rotation => 'solaris',
    criticalpatterns => 'Sense Key: Not Ready',
    criticalexceptions => 'Sense Key: Not Ready /dev/testdisk',
    options => 'noprotocol'
  },
  {
    tag => 'logins',
    logfile => '/var/adm/messages',
    rotation => 'solaris',
    criticalpatterns => ['illegal key', 'read error.*\$CL_DISK01\$'],
    criticalthreshold => 4
    warningpatterns => ['read error.*\$CL_DISK02\$'],
  }
);

EOTXT
}

sub print_usage {
  print <<EOTXT;
Usage: check_logfiles [-t timeout] -f <configfile> [--searches=tag1,tag2,...]
       check_logfiles [-t timeout] --logfile=<logfile> --tag=<tag> --rotation=<rotation>
                      --criticalpattern=<regexp> --warningpattern=<regexp>

EOTXT
}

sub decode_rfc3986 {
  my ($str) = @_;
  if ($str && $str =~ /^rfc3986:\/\/(.*)/) {
    $str = $1;
    $str =~ s/%([A-Za-z0-9]{2})/chr(hex($1))/seg;
  }
  return $str;
}

%commandline = ();
my @params = (
    "timeout|t=i",
    "version|V",
    "help|h",
    "debug|d",
    "verbose|v",
    #
    # 
    #
    "environment|e=s%",
    "daemon:i",
    "report=s",
    "reset",
    "unstick",
    #
    # limit process address space to i megabytes
    #
    "maxmemsize=i",
    #
    #
    #
    "install",
    "deinstall",
    "service=s",
    "username=s",
    "password=s",
    #
    # which searches
    #
    "config|f=s",
    "configdir|F=s",
    "searches=s",
    "selectedsearches=s",
    #
    # globals
    #
    "seekfilesdir=s",
    "protocolsdir=s",
    "protocolsretention=i",
    "macro=s%",
    "seekfileerror=s",
    #
    # thresholds
    #
    "warning=s",
    "critical=s",
    #
    # search
    #
    "template=s",
    "tag=s",
    "logfile=s",
    "rotation=s",
    "tivolipattern=s",
    "criticalpattern=s",
    "criticalexception=s",
    "warningpattern=s",
    "warningexception=s",
    "patternfile=s",
    "okpattern=s",
    "type=s",
    "archivedir=s",
    #
    # search options
    #
    "noprotocol",
    "nocase",
    "nologfilenocry",
    "logfilemissing=s",
    "maxlength=i",
    "syslogserver",
    "syslogclient=s",
    "sticky:s",
    "noperfdata",
    "winwarncrit",
    "lookback=s",
    "allyoucaneat",
    "context=i",
    "criticalthreshold=i",
    "warningthreshold=i",
    "encoding=s",
    "preferredlevel=s",
    "logfileerror=s",
    "rotatewait",
    "rununique",
    "htmlencode",
    "randominode",
    "randomdevno",
);
if (! GetOptions(\%commandline, @params)) {
  print_help();
  exit $ERRORS{UNKNOWN};
}

if (exists $commandline{version}) {
  print_version();
  exit UNKNOWN;
}

if (exists $commandline{help}) {
  print_help();
  exit UNKNOWN;
}

if (exists $commandline{config}) {
  $enough_info = 1;
} elsif (exists $commandline{configdir}) {
  $enough_info = 1;
} elsif (exists $commandline{logfile}) {
  $enough_info = 1;
} elsif (exists $commandline{type} && $commandline{type} =~ /^(eventlog|errpt|ipmitool|wevtutil|executable|dumpel|journald|dmesg)/) {
  $enough_info = 1;
} elsif (exists $commandline{deinstall}) {
  $commandline{type} = 'dummy';
  $enough_info = 1;
}

if (! $enough_info) {
  print_usage();
  exit UNKNOWN;
}

if (exists $commandline{daemon}) {
  my @newargv = ();
  foreach my $option (keys %commandline) {
    if (grep { /^$option/ && /=/ } @params) {
      push(@newargv, sprintf "--%s", $option);
      push(@newargv, sprintf "%s", $commandline{$option});
    } else {
      push(@newargv, sprintf "--%s", $option);
    }
  }
  #$0 = 'check_logfiles '.join(' ', @newargv);
  # SNMP shows a hwSWRunStatus 4 if there are blanks in /proc/pid/comm
  $0 = "check_logfiles\0".join("\0", @newargv);
  if (! $commandline{daemon}) {
    $commandline{daemon} = 300;
  }
}
if (exists $commandline{environment}) {
  # if the desired environment variable values are different from
  # the environment of this running script, then a restart is necessary.
  # because setting $ENV does _not_ change the environment of the running script.
  foreach (keys %{$commandline{environment}}) {
    if ((! $ENV{$_}) || ($ENV{$_} ne $commandline{environment}->{$_})) {
      $needs_restart = 1;
      $ENV{$_} = $commandline{environment}->{$_};
    }
  }
}
if ($needs_restart) {
  my @newargv = ();
  foreach my $option (keys %commandline) {
    if (grep { /^$option/ && /=/ } @params) {
      if (ref ($commandline{$option}) eq "HASH") {
        foreach (keys %{$commandline{$option}}) {
          push(@newargv, sprintf "--%s", $option);
          push(@newargv, sprintf "%s=%s", $_, $commandline{$option}->{$_});
        }
      } else {
        push(@newargv, sprintf "--%s", $option);
        push(@newargv, sprintf "%s", $commandline{$option});
      }
    } else {
      push(@newargv, sprintf "--%s", $option);
    }
  }
  exec $0, @newargv;
  # this makes sure that even a SHLIB or LD_LIBRARY_PATH are set correctly
  # when the perl interpreter starts. Setting them during runtime does not
  # help loading e.g. libclntsh.so
  exit;
}

if (exists $commandline{configdir}) {
  sub eachFile {
    my $filename = $_;
    my $fullpath = $File::Find::name;
    #remember that File::Find changes your CWD, 
    #so you can call open with just $_
    if ((-f $filename) && ($filename =~ /\.(cfg|conf)$/)) { 
      push(@cfgfiles, $fullpath);
    }
  }
  find (\&eachFile, $commandline{configdir});
  @cfgfiles = sort { $a cmp $b } @cfgfiles;
}
if (exists $commandline{config}) {
  # -f is always first
  unshift(@cfgfiles, $commandline{config});
}
if (scalar(@cfgfiles) == 1) {
  $commandline{config} = $cfgfiles[0];
} elsif (scalar(@cfgfiles) > 1) {
  $commandline{config} = \@cfgfiles;
}
if (exists $commandline{searches}) {
  $commandline{selectedsearches} = $commandline{searches};
}
if (! exists $commandline{selectedsearches}) {
  $commandline{selectedsearches} = "";
}
if (exists $commandline{type}) {
  my ($type, $details) = split(":", $commandline{type});
}
if (exists $commandline{criticalpattern}) {
  $commandline{criticalpattern} = '.*' if
      $commandline{criticalpattern} eq 'match_them_all';
  delete $commandline{criticalpattern} if
      $commandline{criticalpattern} eq 'match_never_ever';
}
if (exists $commandline{warningpattern}) {
  $commandline{warningpattern} = '.*' if
      $commandline{warningpattern} eq 'match_them_all';
  delete $commandline{warningpattern} if
      $commandline{warningpattern} eq 'match_never_ever';
}
if (! exists $commandline{seekfilesdir}) {
  if (exists $ENV{OMD_ROOT}) {
    $commandline{seekfilesdir} = $ENV{OMD_ROOT}."/var/tmp/check_logfiles";
  } else {
    $commandline{seekfilesdir} = $SEEKFILESDIR;
  } 
}

if ($^O eq "hpux") {
  $ENV{PATH} = $ENV{PATH}.":/usr/contrib/bin";
}

foreach my $key (keys %commandline) {
  $commandline{$key} = decode_rfc3986($commandline{$key});
}
if (my $cl = Nagios::CheckLogfiles->new({
    cfgfile => $commandline{config} ? $commandline{config} : undef,
    searches => [ 
        map {
          if (exists $commandline{type} && $commandline{type} eq 'rotating::uniform') {
            $_->{type} = $commandline{type};
          } elsif (exists $commandline{type}) {
            # "eventlog" or "eventlog:eventlog=application,include,source=cdrom,source=dvd,eventid=23,eventid=29,operation=or,exclude,eventid=4711,operation=and"
            my ($type, $details) = split(":", $commandline{type});
            $_->{type} = $type;
            if ($details) {
              $_->{$type} = {};
              my $toplevel = $_->{$type};
              foreach my $detail (split(",", $details)) {
                my ($key, $value) = split("=", $detail);
                if ($value) {
             	    if (exists $toplevel->{$key}) {
                    $toplevel->{$key} .= ','.$value;
                  } else {
                    $toplevel->{$key} = $value;	
                  }
                } else {
                  $_->{$type}->{$key} = {};
                  $toplevel = $_->{$type}->{$key};
                }
              }
            }
          }
          $_;
        }
        map { # ausputzen
            foreach my $key (keys %{$_}) { 
    	      delete $_->{$key} unless $_->{$key}}; $_;
        } ({
        tag => 
            $commandline{tag} ? $commandline{tag} : undef,
        logfile => 
            $commandline{logfile} ? $commandline{logfile} : undef,
        type => 
            $commandline{type} ? $commandline{type} : undef,
        rotation => 
            $commandline{rotation} ? $commandline{rotation} : undef,
        tivolipatterns =>
            $commandline{tivolipattern} ?
                $commandline{tivolipattern} : undef,
        criticalpatterns =>
            $commandline{criticalpattern} ?
                $commandline{criticalpattern} : undef,
        criticalexceptions =>
            $commandline{criticalexception} ?
                $commandline{criticalexception} : undef,
        warningpatterns =>
            $commandline{warningpattern} ?
                $commandline{warningpattern} : undef,
        warningexceptions =>
            $commandline{warningexception} ?
                $commandline{warningexception} : undef,
        okpatterns =>
            $commandline{okpattern} ?
                $commandline{okpattern} : undef,
        patternfiles =>
            $commandline{patternfile} ?
                $commandline{patternfile} : undef,
        options => join(',', grep { $_ }
            $commandline{noprotocol} ? "noprotocol" : undef,
            $commandline{nocase} ? "nocase" : undef,
            $commandline{noperfdata} ? "noperfdata" : undef,
            $commandline{nosavethresholdcount} ? "nosavethresholdcount" : undef,
            $commandline{thresholdexpiry} ? "thresholdexpiry=".$commandline{thresholdexpiry} : undef,
            $commandline{winwarncrit} ? "winwarncrit" : undef,
            $commandline{nologfilenocry} ? "nologfilenocry" : undef,
            $commandline{logfilemissing} ? "logfilemissing=".$commandline{logfilemissing} : undef,
            $commandline{syslogserver} ? "syslogserver" : undef,
            $commandline{syslogclient} ? "syslogclient=".$commandline{syslogclient} : undef,
            $commandline{maxlength} ? "maxlength=".$commandline{maxlength} : undef,
            $commandline{lookback} ? "lookback=".$commandline{lookback} : undef,
            $commandline{context} ? "context=".$commandline{context} : undef,
            $commandline{allyoucaneat} ? "allyoucaneat" : undef,
            $commandline{criticalthreshold} ? "criticalthreshold=".$commandline{criticalthreshold} : undef,
            $commandline{warningthreshold} ? "warningthreshold=".$commandline{warningthreshold} : undef,
            $commandline{encoding} ? "encoding=".$commandline{encoding} : undef,
            defined $commandline{sticky} ? "sticky".($commandline{sticky} ? "=".$commandline{sticky} : "") : undef,
            $commandline{preferredlevel} ? "preferredlevel=".$commandline{preferredlevel} : undef,
            $commandline{randominode} ? "randominode" : undef,
            $commandline{randomdevno} ? "randomdevno" : undef,
        ),
        archivedir =>
            $commandline{archivedir} ?
                $commandline{archivedir} : undef,
    })],
    options => join(',', grep { $_ }
        $commandline{report} ? "report=".$commandline{report} : undef,
        $commandline{seekfileerror} ? "seekfileerror=".(uc $commandline{seekfileerror}) : undef,
        $commandline{logfileerror} ? "logfileerror=".(uc $commandline{logfileerror}) : undef,
        $commandline{maxmemsize} ? "maxmemsize=".$commandline{maxmemsize} : undef,
        $commandline{rotatewait} ? "rotatewait" : undef,
        $commandline{htmlencode} ? "htmlencode" : undef,
        $commandline{rununique} ? "rununique" : undef,
    ),
    selectedsearches => [split(/,/, $commandline{selectedsearches})],
    dynamictag => $commandline{tag} ? $commandline{tag} : undef,
    #report => $commandline{report} ? $commandline{report} : undef,
    cmdlinemacros => $commandline{macro},
    seekfilesdir => $commandline{seekfilesdir} ? $commandline{seekfilesdir} : undef,
    protocolsdir => $commandline{protocolsdir} ? $commandline{protocolsdir} : undef,
    scriptpath => $commandline{scriptpath} ? $commandline{scriptpath} : undef,
    protocolsretention => $commandline{protocolsretention} ? $commandline{protocolsretention} : undef,
    reset => $commandline{reset} ? $commandline{reset} : undef,
    unstick => $commandline{unstick} ? $commandline{unstick} : undef,
    warning => $commandline{warning} ? $commandline{warning} : undef,
    critical => $commandline{critical} ? $commandline{critical} : undef,
  })) {
  $cl->{verbose} = $commandline{verbose} ? 1 : 0;
  $cl->{timeout} = $commandline{timeout} ? $commandline{timeout} : 360000;
  if ($commandline{install}) {
    $cl->install_windows_service($commandline{service}, $commandline{config},
        $commandline{username}, $commandline{password});
  } elsif ($commandline{deinstall}) {
    $cl->deinstall_windows_service($commandline{service});
  } elsif ($commandline{daemon}) {
    $cl->run_as_daemon($commandline{daemon});
  } else {
    $cl->run();
  }
  my $exitmessage      = $cl->{exitmessage};
  # Escape | character to not break perfdata
  $exitmessage         =~ s/\|/\/\//g;
  my $long_exitmessage = $cl->{long_exitmessage} ? $cl->{long_exitmessage}."\n" : "";
  printf "%s%s\n%s", $exitmessage,
      $cl->{perfdata} ? "|".$cl->{perfdata} : "",
      $long_exitmessage;
  exit $cl->{exitcode};
} else {
  printf "%s\n", $Nagios::CheckLogfiles::ExitMsg;
  exit $Nagios::CheckLogfiles::ExitCode;
}

