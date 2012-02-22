package Nagios::CheckLogfiles;

use strict;
use IO::File;
use File::Basename;
use File::Spec;
use Cwd;
use Data::Dumper;
#use Net::Domain qw(hostname hostdomain hostfqdn);
use Socket;
use POSIX qw(strftime);
use IPC::Open2;
use Errno;


use constant GZIP => '#GZIP#';
my $ERROR_OK = 0;
my $ERROR_WARNING = 1;
my $ERROR_CRITICAL = 2;
my $ERROR_UNKNOWN = 3;

our $ExitCode = $ERROR_OK;
our $ExitMsg = "OK";
my(%ERRORS, $TIMEOUT);
%ERRORS = ( OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 );
$TIMEOUT = 60;

$| = 1;

eval "require Win32;";
#eval "require Net::Domain qw(hostname hostdomain hostfqdn);";
eval "require Net::Domain;";
{
  local $^W = 0; # shut up!
  eval "require 'syscall.ph'";
  eval "require 'sys/resource.ph'";
}

sub new {
  my $class = shift;
  my $params = shift;
  my $self = bless {} , $class;
  return $self->init($params);
}

#
#  Read a hash with parameters
#
sub init {
  my $self = shift;
  my $params = shift;
  my($sec, $min, $hour, $mday, $mon, $year) = (localtime)[0, 1, 2, 3, 4, 5];
  $year += 1900; $mon += 1;
  $self->{tracefile} = $self->system_tempdir().'/check_logfiles.trace';
  $self->{trace} = -e $self->{tracefile} ? 1 : 0;
  $self->{seekfilesdir} = $params->{seekfilesdir} || '#SEEKFILES_DIR#';
  $self->{protocolsdir} = $params->{protocolsdir} || '#PROTOCOLS_DIR#';
  $self->{scriptpath} = $params->{scriptpath} || '#TRUSTED_PATH#';
  $self->{protocolretention} = ($params->{protocolretention} || 7) * 24 * 3600;
  $self->{macros} = $params->{macros};
  $self->{timeout} = $params->{timeout};
  $self->{pidfile} = $params->{pidfile};
  $self->{perfdata} = "";
  $self->{searches} = [];
  $self->{selectedsearches} = $params->{selectedsearches} || [];
  $self->{dynamictag} = $params->{dynamictag} || "";
  $self->{cmdlinemacros} = $params->{cmdlinemacros} || {};
  $self->{reset} = $params->{reset} || 0;
  $self->{unstick} = $params->{unstick} || 0;
  $self->{rununique} = $params->{rununique} || 0;
  $self->default_options({ prescript => 1, smartprescript => 0,
      supersmartprescript => 0, postscript => 1, smartpostscript => 0,
      supersmartpostscript => 0, report => 'short', maxlength => 4096,
      seekfileerror => 'critical', logfileerror => 'critical', 
      maxmemsize => 0, rotatewait => 0,
  });
  if ($params->{cfgfile}) {
    if (ref($params->{cfgfile}) eq "ARRAY") {
      # multiple cfgfiles found in a config dir
      my @tmp_searches = ();
      $self->{cfgbase} = $params->{cfgbase} || "check_logfiles";
      foreach my $cfgfile (@{$params->{cfgfile}}) {
        $self->{cfgfile} = $cfgfile;
        if (! $self->init_from_file()) {
          return undef;
        }
        push(@tmp_searches, @{$self->{searches}});
        $self->{searches} = [];
      }
      my %seen = ();
      # newer searches replace searches with the same tag
      @tmp_searches = reverse map { 
        if (! exists $seen{$_->{tag}}) {
          $seen{$_->{tag}}++;
          $_;
        } else {
          ();
        }
      } reverse @tmp_searches;
      $self->{searches} = \@tmp_searches;
      my $uniqueseekfile = undef;
      my $uniqueprotocolfile = undef;
      foreach (@{$self->{searches}}) {
        $_->{cfgbase} = "check_logfiles";
        next if $_->{tag} eq "prescript";
        next if $_->{tag} eq "postscript";
        $_->construct_seekfile();
      }
      #$self->{cfgbase} = (split /\./, basename($params->{cfgfile}->[0]))[0];
      $self->{cfgbase} = "check_logfiles";
    } elsif ($params->{cfgfile} =~ /%0A/) {
      # this must be an encoded flat file
      $self->{cfgfile} = $params->{cfgfile};
      $self->{cfgbase} = "flatfile";
      if (! $self->init_from_file()) {
        return undef;
      }
    } else {
      $self->{cfgfile} = $params->{cfgfile};
      $self->{cfgbase} = (split /\./, basename($self->{cfgfile}))[0];
      if (! $self->init_from_file()) {
        return undef;
      }
    } 
    # if there is a dynamictag parameter then replace template names with
    # template_dynamictagtag
    if (scalar(@{$self->{selectedsearches}})) {
      @{$self->{searches}} = map {
        my $srch = $_;
        if (grep { $srch->{tag} eq $_ } @{$self->{selectedsearches}}) {
          # gilt sowohl fuer normale searches
          $srch;
        } elsif ($srch->{template} && grep { $srch->{template} eq $_ } @{$self->{selectedsearches}}) {
          # als auch fuer template (tag ist hier bereits template."_".tag,
          # wobei tag auf der kommandozeile uebergeben wurde)
          $srch;
        } elsif (grep { $_ =~ /[*?]/ && $srch->{tag} =~ /$_/ } @{$self->{selectedsearches}}) {
          # --selectedsearches "regexp,regexp"
          $srch;
        } elsif ($srch->{tag} eq "prescript") {
          $srch;
        } elsif ($srch->{tag} eq "postscript") {
          $srch;
        } else {
          $self->trace("skipping non-selected search %s", $srch->{tag});
          ();
        }
      } @{$self->{searches}};
    }
  } else {
    $self->{cfgbase} = $params->{cfgbase} || "check_logfiles";
    # first the global options (from the commandline in this case)
    $self->refresh_options($params->{options});
    $self->init_macros;
    foreach (@{$params->{searches}}) {
      $_->{seekfilesdir} = $self->{seekfilesdir};
      $_->{scriptpath} = $self->{scriptpath};
      %{$_->{macros}} = %{$self->{macros}};
      $_->{tracefile} = $self->{tracefile};
      $_->{cfgbase} = $self->{cfgbase};
      if (my $search = Nagios::CheckLogfiles::Search->new($_)) {
        # maybe override default search options with global ones (ex. report)
        $search->refresh_default_options($self->get_options('report,seekfileerror,logfileerror'));
        push(@{$self->{searches}}, $search);
      } else {
        $ExitCode = $ERROR_UNKNOWN;
        $ExitMsg = sprintf "cannot create %s search %s",
            $_->{type}, $_->{tag};
        return undef;
      }
    }  
  }
  if (defined(&Win32::GetShortPathName) && ($^O =~ /Win/)) {
    # if this is true windows (not cygwin) and if the path exists
    # then transform it to a short form. undef if path does not exist.
    if (my $tmpshortpath = &Win32::GetShortPathName($self->{protocolsdir})) {
      $self->{protocolsdir} = $tmpshortpath;
    }
  }
  if ($self->get_option('report') !~ /^(long|short|html)$/) {
    $ExitCode = $ERROR_UNKNOWN;
    $ExitMsg = sprintf "UNKNOWN - output must be short, long or html";
    return undef;
  }
  $self->{protocolfile} = 
      sprintf "%s/%s.protocol-%04d-%02d-%02d-%02d-%02d-%02d",
      $self->{protocolsdir}, $self->{cfgbase}, 
      $year, $mon, $mday, $hour, $min, $sec;
  $self->{protocololdfiles} = sprintf "%s/%s.protocol-*-*-*-*-*-*",
      $self->{protocolsdir}, $self->{cfgbase};
  $self->{protocolfh} = new IO::File;
  $self->{protocolwritten} = 0;
  $self->{allerrors} = { OK => 0, WARNING => 0, CRITICAL => 0, UNKNOWN => 0 };
  # if parameters update
  if (@{$self->{searches}}) {
    $self->{exitcode} = $ExitCode;
    $self->{exitmessage} = $ExitMsg;
    return $self;
  } else {
    $ExitCode = $ERROR_UNKNOWN;
    $ExitMsg = sprintf "UNKNOWN - configuration incomplete";
    return undef;
  }
}

sub init_from_file {
  my $self = shift;
  my $abscfgfile;
  #
  #  variables from the config file.
  #
  our($seekfilesdir, $protocolsdir, $scriptpath, $protocolretention,
      $prescript, $prescriptparams ,$prescriptstdin, $prescriptdelay,
      $postscript, $postscriptparams, $postscriptstdin, $postscriptdelay,
      @searches, @logs, $tracefile, $options, $report, $timeout, $pidfile);
  our $MACROS = {};
  if ($^O =~ /MSWin/) {
    $ENV{HOME} = $ENV{USERPROFILE};
  }
  if ($self->{cfgbase} eq "flatfile") {
    $self->{cfgfile} =~ s/\%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;
    eval $self->{cfgfile};
    if ($@) {
      $ExitCode = $ERROR_UNKNOWN;
      $ExitMsg = sprintf "UNKNOWN - syntax error %s", (split(/\n/, $@))[0];
      return undef;
    }
  } else {
    if (-f $self->{cfgfile}) {
      $abscfgfile = $self->{cfgfile};
    } elsif (-f $self->{cfgfile}.'.cfg') {
      $abscfgfile = $self->{cfgfile}.'.cfg';
    } elsif (-f $ENV{HOME}.'/'.$self->{cfgfile}) {
      $abscfgfile = $ENV{HOME}.'/'.$self->{cfgfile};
    } elsif (-f $ENV{HOME}.'/'.$self->{cfgfile}.'.cfg') {
      $abscfgfile = $ENV{HOME}.'/'.$self->{cfgfile}.'.cfg';
    } else {
      $ExitCode = $ERROR_UNKNOWN;
      $ExitMsg = sprintf "UNKNOWN - can not load configuration file %s", 
          $self->{cfgfile};
      return undef;
    }
    $abscfgfile = File::Spec->rel2abs($abscfgfile) 
        unless File::Spec->file_name_is_absolute($abscfgfile);
    eval {
      require $abscfgfile;
    };
    if ($@) {
      $ExitCode = $ERROR_UNKNOWN;
      $ExitMsg = sprintf "UNKNOWN - syntax error %s", (split(/\n/, $@))[0];
      return undef;
    }
    # We might need this for a pidfile
    $self->{abscfgfile} = $abscfgfile;
    # autodetect a good place for a seekfilesdir
    # abscfgfile usially is in path/etc
    # 1. path/var/tmp
    # 2. path/tmp
    if ($seekfilesdir && $seekfilesdir eq "autodetect") {
      my $basedir = dirname(dirname($abscfgfile));
      if (-d $basedir.'/var/tmp' && -w $basedir.'/var/tmp') {
        $seekfilesdir = $basedir.'/var/tmp/check_logfiles';
        mkdir($seekfilesdir);
      } elsif (-d $basedir.'/tmp' && -w $basedir.'/tmp') {
        $seekfilesdir = $basedir.'/tmp/check_logfiles';
        mkdir($seekfilesdir);
      } else {
        $ExitCode = $ERROR_UNKNOWN;
        $ExitMsg = sprintf "UNKNOWN - unable to autodetect an adequate seekfilesdir";
        return undef;
      }
    }
    if ($protocolsdir && $protocolsdir eq "autodetect") {
      my $basedir = dirname(dirname($abscfgfile));
      if (-d $basedir.'/var/tmp' && -w $basedir.'/var/tmp') {
        $protocolsdir = $basedir.'/var/tmp';
      } elsif (-d $basedir.'/tmp' && -w $basedir.'/tmp') {
        $protocolsdir = $basedir.'/tmp';
      } else {
        $protocolsdir = $self->system_tempdir();
      }
    }
    if ($scriptpath && $scriptpath eq "autodetect") {
      my @path = ();
      my $basedir = dirname(dirname($abscfgfile));
      if (-d $basedir.'/local/lib/nagios/plugins') {
        push(@path, $basedir.'/local/lib/nagios/plugins');
      }
      if (-d $basedir.'/lib/nagios/plugins') {
        push(@path, $basedir.'/lib/nagios/plugins');
      }
      $scriptpath = join(($^O =~ /MSWin/) ? ';' : ':', @path);
    }
  } 
  $self->{tracefile} = $tracefile if $tracefile;
  $self->{trace} = -e $self->{tracefile} ? 1 : 0;
  # already done one level above $self->{cfgbase} = (split /\./, basename($self->{cfgfile}))[0];
  $self->{seekfilesdir} = $seekfilesdir if $seekfilesdir;
  $self->{protocolsdir} = $protocolsdir if $protocolsdir;
  $self->{scriptpath} = $scriptpath if $scriptpath;
  $self->{protocolretention} = ($protocolretention * 24 * 3600) if $protocolretention;
  $self->{prescript} = $prescript if $prescript;
  $self->{prescriptparams} = $prescriptparams if $prescriptparams;
  $self->{prescriptstdin} = $prescriptstdin if $prescriptstdin;
  $self->{prescriptdelay} = $prescriptdelay if $prescriptdelay;
  $self->{postscript} = $postscript if $postscript;
  $self->{postscriptparams} = $postscriptparams if $postscriptparams;
  $self->{postscriptstdin} = $postscriptstdin if $postscriptstdin;
  $self->{postscriptdelay} = $postscriptdelay if $postscriptdelay;
  $self->{macros} = $MACROS if $MACROS;
  $self->{timeout} = $timeout if $timeout;
  $self->{pidfile} = $pidfile if $pidfile;
  $self->{privatestate} = {};
  $self->init_macros;
  $self->refresh_options($options);
  if (@logs) {
    #
    # Since version 1.4 the what/where-array is called @searches.
    # To stay compatible, @logs is still recognized.
    #
    @searches = @logs;
  }
  if ($self->{options}->{prescript}) {
    $_->{scriptpath} = $self->{scriptpath};
    %{$_->{macros}} = %{$self->{macros}};
    $_->{tracefile} = $self->{tracefile};
    $_->{cfgbase} = $self->{cfgbase};
    $_->{script} = $self->{prescript};
    $_->{scriptparams} = $self->{prescriptparams};
    $_->{scriptstdin} = $self->{prescriptstdin};
    $_->{scriptdelay} = $self->{prescriptdelay};   
    $_->{options} = sprintf "%s%sscript",
        $self->{options}->{supersmartprescript} ? "super" : "",
        $self->{options}->{smartprescript} ? "smart" : "";
    $_->{privatestate} = $self->{privatestate};
    my $search = Nagios::CheckLogfiles::Search::Prescript->new($_);
    push(@{$self->{searches}}, $search); 
  }
  foreach (@searches) {
    $_->{seekfilesdir} = $self->{seekfilesdir};
    $_->{scriptpath} = $self->{scriptpath};
    %{$_->{macros}} = %{$self->{macros}};
    $_->{tracefile} = $self->{tracefile};
    $_->{cfgbase} = $self->{cfgbase};
    if ((exists $_->{template}) && ! $self->{dynamictag}) {
      # skip templates if they cannot be tagged
      next;
    }
    $_->{dynamictag} = $self->{dynamictag};
    if (my $search = Nagios::CheckLogfiles::Search->new($_)) {
      $search->refresh_options($self->get_options('report,seekfileerror,logfileerror'));
      push(@{$self->{searches}}, $search);
      $_->{privatestate}->{$search->{tag}} = $search->{privatestate};
    } else {
      $ExitCode = $ERROR_UNKNOWN;
      $ExitMsg = sprintf "cannot create %s search %s",
          $_->{type}, $_->{tag};
      return undef;
    }
  }
  if ($self->{options}->{postscript}) {
    $_->{scriptpath} = $self->{scriptpath};
    %{$_->{macros}} = %{$self->{macros}};
    $_->{tracefile} = $self->{tracefile};
    $_->{cfgbase} = $self->{cfgbase};
    $_->{script} = $self->{postscript};
    $_->{scriptparams} = $self->{postscriptparams};
    $_->{scriptstdin} = $self->{postscriptstdin};
    $_->{scriptdelay} = $self->{postscriptdelay};   
    $_->{options} = sprintf "%s%sscript",
        $self->{options}->{supersmartpostscript} ? "super" : "",
        $self->{options}->{smartpostscript} ? "smart" : "";
    $_->{privatestate} = $self->{privatestate};
    my $search = Nagios::CheckLogfiles::Search::Postscript->new($_);
    push(@{$self->{searches}}, $search); 
  }
  return $self;
}

sub run {
  my $self = shift;
  if ($self->{reset}) {
    foreach my $search (@{$self->{searches}}) {
      if ($search->{tag} ne "prescript" && $search->{tag} ne "postscript") {
        $search->rewind();
      }
    }
    return $self;
  }
  if ($self->{unstick}) {
    foreach my $search (@{$self->{searches}}) {
      if ($search->{tag} ne "prescript" && $search->{tag} ne "postscript") {
        $search->unstick();
      }
    }
    return $self;
  }
  if ($self->{rununique}) {
    $self->{pidfile} = $self->{pidfile} || $self->construct_pidfile();
    if (! $self->check_pidfile()) {
      $self->trace("Exiting because another check is already running");
      printf STDERR "Exiting because another check is already running\n";
      exit 3;
    }
  }
  if ($self->get_option('rotatewait')) {
    $self->await_while_rotate();
  }
  foreach my $search (@{$self->{searches}}) {
    if (1) { # there will be a timesrunningout variable
      if ($search->{tag} eq "postscript") {
        $search->{macros}->{CL_SERVICESTATEID} = $self->{exitcode};
        $search->{macros}->{CL_SERVICEOUTPUT} = $self->{exitmessage};
        $search->{macros}->{CL_LONGSERVICEOUTPUT} = 
            $self->{long_exitmessage} || $self->{exitmessage};
        $search->{macros}->{CL_SERVICEPERFDATA} = $self->{perfdata};
        $search->{macros}->{CL_PROTOCOLFILE} = $self->{protocolfile};
        if ($search->{options}->{supersmartscript}) {
          # 
          #  Throw away everything found so far. Supersmart postscripts
          #  have the last word.
          #
          $self->reset_result();        
        }       
      }      
      $search->run();
      if (($search->{tag} eq "prescript") && 
          ($search->{options}->{supersmartscript}) &&
          ($search->{exitcode} > 0)) {
        #
        #  Prepare for a premature end. A failed supersmart prescript
        #  will abort the whole script.
        #
        $self->reset_result();
        $self->trace("failed supersmart prescript. aborting...");
      }
      $_->{privatestate}->{$search->{tag}} = $search->{privatestate};
      if ($search->{options}->{protocol}) {
        if (scalar(@{$search->{matchlines}->{CRITICAL}}) ||
            scalar(@{$search->{matchlines}->{WARNING}}) ||
            scalar(@{$search->{matchlines}->{UNKNOWN}})) {
          if ($self->{protocolfh}->open($self->{protocolfile}, "a")) {
            foreach (qw(CRITICAL WARNING UNKNOWN)) {
              if (@{$search->{matchlines}->{$_}}) {
                $self->{protocolfh}->print(sprintf "%s Errors in %s (tag %s)\n",
                    $_, $search->{logbasename}, $search->{tag});
                foreach (@{$search->{matchlines}->{$_}}) {
                  $self->{protocolfh}->printf("%s\n", $_);
                }
              }
            }
            $self->{protocolfh}->close();
            $self->{protocolwritten} = 1;
          }
        }
      }
      if ($search->{options}->{count}) {
        foreach (qw(OK WARNING CRITICAL UNKNOWN)) {
          $self->{allerrors}->{$_} += scalar(@{$search->{matchlines}->{$_}});
          if ($search->{lastmsg}->{$_}) {
            $self->{lastmsg}->{$_} = $search->{lastmsg}->{$_};
          }
        }
      }
      $self->formulate_result();
      if (($search->{tag} eq "prescript") && 
          ($search->{options}->{supersmartscript}) &&
          ($search->{exitcode} > 0)) {
        #
        #  Failed supersmart prescript. I'm out...
        #
        last;
      } elsif (($search->{tag} eq "postscript") && 
          ($search->{options}->{supersmartscript})) {
        my $codestr = {reverse %ERRORS}->{$search->{exitcode}};
        ($self->{exitmessage}, $self->{perfdata}) = 
            split(/\|/, $search->{lastmsg}->{$codestr}, 2);
        $self->{exitcode} = $search->{exitcode};
      }
    }
  }
  $self->cleanup_protocols();
  return $self;
}

sub await_while_rotate {
  my $self = shift;
  my($sec, $min, $hour, $mday, $mon, $year) = (localtime)[0, 1, 2, 3, 4, 5];
  if (($min == 0 || $min == 15 || $min == 30 || $min == 45) && $sec < 15) {
    $self->trace("waiting until **:**:15");
    foreach (1..(15 - $sec)) {
      sleep 1;
    }
  }
}

sub formulate_result {
  my $self = shift;
  #
  #  create the summary from all information collected so far
  #
  $self->{hint} = sprintf "(%s", join(", ", grep { $_ }
    ($self->{allerrors}->{CRITICAL} ? 
        sprintf "%d errors", $self->{allerrors}->{CRITICAL} : undef,
    $self->{allerrors}->{WARNING} ? 
        sprintf "%d warnings", $self->{allerrors}->{WARNING} : undef,
    $self->{allerrors}->{UNKNOWN} ? 
        sprintf "%d unknown", $self->{allerrors}->{UNKNOWN} : undef));
  if ($self->{protocolwritten}) {
    $self->{hint} .= sprintf " in %s)", basename($self->{protocolfile});
  } else {
    $self->{hint} .= ")";
  }
  foreach my $level (qw(CRITICAL WARNING UNKNOWN OK)) {
    $self->{exitcode} = $ERRORS{$level};
    if (($level ne "OK") && ($self->{allerrors}->{$level})) {
      $self->{exitmessage} = sprintf "%s - %s - %s %s", $level, $self->{hint},
          $self->{lastmsg}->{$level}, 
          ($self->{allerrors}->{$level} == 1 ? "" : "...");
      last;
    } else {
      $self->{exitmessage} = sprintf "OK - no errors or warnings";
    }
  }
  $self->{perfdata} = join (" ", 
      map { $_->formulate_perfdata(); if ($_->{perfdata}) {$_->{perfdata}} else {()} }
      @{$self->{searches}});
  if ($self->get_option('report') ne "short") {
    $self->formulate_long_result();
  }
}

sub formulate_long_result {
  my $self = shift;
  my $maxlength = $self->get_option('maxlength');
  $self->{long_exitmessage} = "";
  my $prefix = ($self->get_option('report') eq "html") ?
      "<table style=\"border-collapse: collapse;\">" : "";
  my $suffix = ($self->get_option('report') eq "html") ?
      "</table>" : "";
  my $messagelen = length($prefix) + length($suffix) +
      length($self->{exitmessage});
  my $line = "";
   
  foreach my $search (@{$self->{searches}}) {
    next if $search->{tag} eq 'postscript';
    if (scalar(@{$search->{matchlines}->{CRITICAL}}) ||
        scalar(@{$search->{matchlines}->{WARNING}}) ||
        scalar(@{$search->{matchlines}->{UNKNOWN}})) {
      if ($self->get_option('report') eq "html") {
        $line =
            sprintf "<tr valign=\"top\"><td class=\"service%s\">tag %s</td></tr>",
                ((scalar(@{$search->{matchlines}->{CRITICAL}}) && "CRITICAL") ||
                 (scalar(@{$search->{matchlines}->{WARNING}}) && "WARNING") ||
                 (scalar(@{$search->{matchlines}->{UNKNOWN}}) && "UNKNOWN")),
                $search->{tag};
      } else {
        $line =
            sprintf "tag %s %s\n",
                $search->{tag},
                ((scalar(@{$search->{matchlines}->{CRITICAL}}) && "CRITICAL") ||
                 (scalar(@{$search->{matchlines}->{WARNING}}) && "WARNING") ||
                 (scalar(@{$search->{matchlines}->{UNKNOWN}}) && "UNKNOWN"));
      }
      if ($messagelen + length($line) < $maxlength) {
        $self->{long_exitmessage} .= $line;
        $messagelen += length($line);
      } else {
        last;
      }
      foreach my $level (qw(CRITICAL WARNING UNKNOWN)) {
        foreach my $message (@{$search->{matchlines}->{$level}}) {
          if ($self->get_option('report') eq "html") {
            $message =~ s/</&lt;/g;
            $message =~ s/>/&gt;/g;
            $line =
                sprintf "<tr valign=\"top\"><td nowrap width=\"100%%\" class=\"service%s\" style=\"border: 1px solid black;\">%s</td></tr>",
                $level, $message;
          } else {
            $line = sprintf "%s\n", $message;
          }
          if ($messagelen + length($line) < $maxlength) {
            $self->{long_exitmessage} .= $line;
            $messagelen += length($line);
          } else {
            last;
          }
        }
      }
    }
  }
  if ($self->{long_exitmessage}) {
    $self->{long_exitmessage} = sprintf "%s%s%s\n",
        $prefix, $self->{long_exitmessage}, $suffix;
  }
}

sub reset_result {
  my $self = shift;
  $self->{allerrors} = { OK => 0, WARNING => 0, CRITICAL => 0, UNKNOWN => 0 };
  foreach my $search (@{$self->{searches}}) {
    next if $search->{tag} eq 'postscript';
    next if $search->{tag} eq 'prescript';
    $search->{matchlines} = {
        OK => [],
        WARNING => [],
        CRITICAL => [],
        UNKNOWN => [],
    }
  }
}

sub reset {
  my $self = shift;
  $self->{allerrors} = { OK => 0, WARNING => 0, CRITICAL => 0, UNKNOWN => 0 };
  foreach my $level (qw(OK CRITICAL WARNING UNKNOWN)) {
    $self->{lastmsg}->{$level} = "";
  }
  foreach my $search (@{$self->{searches}}) {
    $search->reset();
  }
}

sub cleanup_protocols {
  my $self = shift;
  #
  #  cleanup old protocol files
  #
  #
  if ($self->{protocololdfiles} =~ /[^\\][ ]/) {
    # because Core::glob splits the argument on whitespace
    $self->{protocololdfiles} =~ s/( )/\\$1/g;
  }
  foreach my $oldprotocolfile (glob "$self->{protocololdfiles}") {
    if ((stat $oldprotocolfile)[9] < (time - $self->{protocolretention})) {
      $self->trace("deleting old protocol %s", $oldprotocolfile);
      unlink $oldprotocolfile;
    }
  }
}

sub init_macros {
  my $self = shift;
  my($sec, $min, $hour, $mday, $mon, $year) = (localtime)[0, 1, 2, 3, 4, 5];
  my $cw = $^O =~ /MSWin/ ? 0 : 
      strftime("%V", $sec, $min, $hour, $mday, $mon, $year, -1, -1, -1);
  $year += 1900; $mon += 1;
  #
  #  Set default values for the built-in macros.
  #
  my $DEFAULTMACROS = {
      CL_SERVICEDESC => $self->{cfgbase},
      CL_DATE_YYYY => sprintf("%04d", $year),
      CL_DATE_YY => substr($year,2,2),
      CL_DATE_MM => sprintf("%02d", $mon),
      CL_DATE_DD => sprintf("%02d", $mday),
      CL_DATE_HH => sprintf("%02d", $hour),
      CL_DATE_MI => sprintf("%02d", $min),
      CL_DATE_SS => sprintf("%02d", $sec),
      CL_DATE_TIMESTAMP => sprintf("%10d", time),
      CL_DATE_CW => sprintf("%02d", $cw),
      CL_NSCA_SERVICEDESC => $self->{cfgbase},
      CL_NSCA_HOST_ADDRESS => "127.0.0.1",
      CL_NSCA_PORT => 5667,
      CL_NSCA_TO_SEC => 10,
      CL_NSCA_CONFIG_FILE => "/usr/local/nagios/etc/send_nsca.cfg",
  };
  if (defined(&Win32::LoginName)) {
    $DEFAULTMACROS->{CL_USERNAME} = &Win32::LoginName();
    $DEFAULTMACROS->{CL_HAS_WIN32} = 1;
  } else {
    $DEFAULTMACROS->{CL_USERNAME} = scalar getpwuid $>;
    $DEFAULTMACROS->{CL_HAS_WIN32} = 0;
  }
  if (defined(&Net::Domain::hostname)) {
    $DEFAULTMACROS->{CL_HOSTNAME} = &Net::Domain::hostname();
    $DEFAULTMACROS->{CL_DOMAIN} = &Net::Domain::hostdomain();
    $DEFAULTMACROS->{CL_FQDN} = &Net::Domain::hostfqdn();
    $DEFAULTMACROS->{CL_HAS_NET_DOMAIN} = 1;
  } else {
    $DEFAULTMACROS->{CL_HOSTNAME} = POSIX::uname();
    $DEFAULTMACROS->{CL_DOMAIN} = "localdomain";
    $DEFAULTMACROS->{CL_FQDN} = POSIX::uname().'.'.'localdomain';
    $DEFAULTMACROS->{CL_HAS_NET_DOMAIN} = 0;
  }
#printf STDERR "%s\n", Data::Dumper::Dumper($DEFAULTMACROS);
  $DEFAULTMACROS->{CL_IPADDRESS} =
      scalar gethostbyname($DEFAULTMACROS->{CL_HOSTNAME}) ?
      inet_ntoa(scalar gethostbyname($DEFAULTMACROS->{CL_HOSTNAME})) :
      '127.0.0.1';
  #
  #  Add self-defined macros to the defaultmacros structure or overwrite
  #  already defined macros.
  #
  if ($self->{macros}) {
    foreach (keys %{$self->{macros}}) {
      $DEFAULTMACROS->{$_} = $self->{macros}->{$_};
    }
  }
  #
  #  Add self-defined macros from the command line 
  #  --macro CL_KAAS="so a kaas" --macro CL_SCHMARRN="so a schmarrn"
  #
  if ($self->{cmdlinemacros}) {
    foreach (keys %{$self->{cmdlinemacros}}) {
      $DEFAULTMACROS->{$_} = $self->{cmdlinemacros}->{$_};
    }
  }
  #
  #  Escape the most commonly used special characters so they will no longer
  #  be treated like special characters in a pattern.
  #
  $self->{macros} = $DEFAULTMACROS;
  return $self;
}

#
#  Resolve macros in a string. 
#  If a second parameter is given, then this string is meant as a regular expression.
#  Escape special characters accordingly.
#
sub resolve_macros {
  my $self = shift;
  my $pstring = shift;
  while ($$pstring =~ /\$(.+?)\$/g) {
    my $maybemacro = $1;
    if (exists $self->{macros}->{$maybemacro}) {
      my $macro = $self->{macros}->{$maybemacro};
      $$pstring =~ s/\$$maybemacro\$/$macro/;
    }
  }
}


sub resolve_macros_in_pattern {
  my $self = shift;
  my $pstring = shift;
  while ($$pstring =~ /\$(.+?)\$/g) {
  # das alte bleibt hier stehen als denkmal der schande
  #while ($$pstring =~ /.*\$(\w+)\$.*/g) { 
    my $maybemacro = $1;
    if (exists $self->{macros}->{$maybemacro}) {
      my $macro = $self->{macros}->{$maybemacro};
       #
      #  Escape the most commonly used special characters so they will no longer
      #  be treated like special characters in a pattern.
      #
      $macro =~ s|/|\\/|g;
      $macro =~ s|\-|\\-|g;
      $macro =~ s|\.|\\.|g;
      $$pstring =~ s/\$$maybemacro\$/$macro/;
    }
  }
}

sub default_options {
  my $self = shift;
  my $defaults = shift;
  $self->{defaultoptions} = {};
  while (my($key, $value) = each %{$defaults}) {
    $self->{options}->{$key} = $value;
    $self->{defaultoptions}->{$key} = $value;
  }
}

sub set_options {
  my $self = shift;
  my $options = shift;
  while (my($key, $value) = each %{$options}) {
    $self->{options}->{$key} = $value if $value;
  }
}

sub set_option {
  my $self = shift;
  my $option = shift;
  my $value = shift;
  $self->{options}->{$option} = $value if defined $value;
}

sub get_option {
  my $self = shift;
  my $option = shift;
  return exists $self->{options}->{$option} ?
      $self->{options}->{$option} : undef;
}

sub get_options {
  my $self = shift;
  my $list = shift;
  if (! $list) {
    return $self->{options};
  } else {
    my %h = map {($_, $self->{options}->{$_})} split(',', $list);
    return \%h;
  }
}

sub get_non_default_options {
  my $self = shift;
  my $list = shift;
  if (! $list) {
    my %h = map {
      ($_, $self->{options}->{$_})
    } grep {
      ! exists $self->{defaultoptions}->{$_} ||
          "$self->{defaultoptions}->{$_}" ne "$self->{options}->{$_}";
    } keys %{$self->{options}};
    return \%h;
  } else {
    my %h = map {
      ($_, $self->{options}->{$_})
    } grep {
      ! exists $self->{defaultoptions}->{$_} ||
          "$self->{defaultoptions}->{$_}" ne "$self->{options}->{$_}";
    } split(',', $list);
    return \%h;
  }
}

sub refresh_default_options {
  my $self = shift;
  my $options = shift;
  if ($options) {
    if (ref($options) eq 'HASH') { # already as hash
      foreach my $option (keys %{$options}) {
        my $optarg = $options->{$option};
        if (! exists $self->{defaultoptions}->{$option} ||
            "$self->{defaultoptions}->{$option}" eq "$self->{options}->{$option}") {
          $self->{options}->{$option} = $optarg;
        }
      }
    }
  }
}

sub refresh_options {
  my $self = shift;
  my $options = shift;
  if ($options) {
    if (ref($options) eq 'HASH') { # already as hash
      foreach my $option (keys %{$options}) {
        my $optarg = $options->{$option};
        foreach my $defoption (keys %{$self->{options}}) {
          if ($option eq $defoption) {
            $self->{options}->{$defoption} = $optarg;
          }
        }
      }
    } else { # comes as string
      foreach my $option (split /,/, $options) {
        my $optarg = undef;
        $option =~ s/^\s+//;
        $option =~ s/\s+$//;
        if ($option =~ /(.*)=(.*)/) {
          $option = $1;
          $optarg = $2;
          $optarg =~ s/^"//;
          $optarg =~ s/"$//;
          $optarg =~ s/^'//;
          $optarg =~ s/'$//;
        }
        foreach my $defoption (keys %{$self->{options}}) {
          if ($option eq $defoption) {
            if (defined $optarg) {
              # example: sticky=3600,syslogclient="winhost1.dom"
              $self->{options}->{$defoption} = $optarg;
            } else {
              $self->{options}->{$defoption} = 1;
            }
          } elsif ($option eq 'no'.$defoption) {
            $self->{options}->{$defoption} = 0;
          }
        }
      } 
    }
  } 
  # reset [smart][pre|post]script options if no script should be called 
  foreach my $option (qw(script prescript postscript)) {
    if (exists $self->{options}->{'supersmart'.$option}) {
      $self->{options}->{'smart'.$option} = 1
          if $self->{options}->{'supersmart'.$option};
    }
    if (exists $self->{options}->{'smart'.$option}) {
      $self->{options}->{$option} = 1
          if $self->{options}->{'smart'.$option};
    }
    if (exists $self->{options}->{$option}) {
      if (($self->{options}->{$option}) && ! exists $self->{$option}) {
        $self->{options}->{$option} = 0;
        $self->{options}->{'smart'.$option} = 0;
        $self->{options}->{'supersmart'.$option} = 0;
      }
    }
  }
  if ($self->{options}->{sticky}) {
    if ($self->{options}->{sticky} > 1) {
      $self->{maxstickytime} = $self->{options}->{sticky};
      $self->{options}->{sticky} = 1;
    } else {
      # durch mehrmaliges refresh (seitens des CheckLogfiles-Objekts kann maxstickytime
      # zerschossen werden
      if (! exists $self->{maxstickytime} || $self->{maxstickytime} == 0) {
        $self->{maxstickytime} = 3600 * 24 * 365 * 10;
      }
    }
  }
  if ($self->{options}->{syslogclient}) {
#    $self->{prefilter} = $self->{options}->{syslogclient};
  }
}

sub trace {
  my $self = shift;
  my $format = shift;
  $self->{tracebuffer} = [] unless exists $self->{tracebuffer};
  push(@{$self->{tracebuffer}}, @_);
  if ($self->{verbose}) {
    printf("%s: ", scalar localtime);
    printf($format, @_);
  }
  if ($self->{trace}) {
    my $logfh = new IO::File;
    $logfh->autoflush(1);
    if ($logfh->open($self->{tracefile}, "a")) {
      $logfh->printf("%s: ", scalar localtime);
      $logfh->printf($format, @_);
      $logfh->printf("\n");
      $logfh->close();
    }
  }
}

sub action {
  my $self = shift;
  my $script = shift;
  my $scriptparams = shift;
  my $scriptstdin = shift;
  my $scriptdelay = shift;
  my $smart = shift;
  my $privatestate = shift;
  my $success = 0;
  my $rc = 0;
  my $exitvalue;
  my $signalnum;
  my $dumpedcore;
  my $output;
  my $pid = 0;
  my $wait = 0;
  my $strerror = (qw(OK WARNING CRITICAL UNKNOWN))
      [$self->{macros}->{CL_SERVICESTATEID}];
  my $cmd;
  my @stdinformat = ();
  foreach my $macro (keys %{$self->{macros}}) {
    my $envmacro = $macro;
    if ($envmacro =~ /^CL_/) {
      $envmacro =~ s/^CL_/CHECK_LOGFILES_/;
    } else {
      $envmacro = "CHECK_LOGFILES_".$macro;
    }
    $ENV{$envmacro} = defined($self->{macros}->{$macro}) ? 
        $self->{macros}->{$macro} : "";
  }
  $ENV{CHECK_LOGFILES_SERVICESTATE} = (qw(OK WARNING CRITICAL UNKNOWN))
      [$ENV{CHECK_LOGFILES_SERVICESTATEID}];
  if (ref $script eq "CODE") {
    $self->trace("script is of type %s", ref $script);
    if (ref($scriptparams) eq "ARRAY") {
      foreach (@{$scriptparams}) {
        $self->resolve_macros(\$_) if $_;
      }
    }
    my $stdoutvar;
    *SAVEOUT = *STDOUT;
    eval {
      our $CHECK_LOGFILES_PRIVATESTATE = $privatestate;
      open OUT ,'>',\$stdoutvar;
      *STDOUT = *OUT;
      $exitvalue = &{$script}($scriptparams, $scriptstdin);
    };
    *STDOUT = *SAVEOUT;
    if ($@) {
      $output = $@;
      $success = 0;
      $rc = -1;
      $self->trace("script said: %s", $output);
    } else {
      #$output = $stdoutvar || "";
      $output = defined $stdoutvar ?  $stdoutvar :  "";
      chomp $output;
      $self->trace("script said: %s", $output);
      if ($smart) {
        if (($exitvalue =~ /^\d/) && ($exitvalue >= 0 && $exitvalue <= 3)) {
          $success = 1;
          $rc = $exitvalue;
          $self->trace("script %s exits with code %d", $script, $rc);
        } else {
          $success = 1;
          $rc = -4;
          $self->trace("script %s failed for unknown reasons", $script);
        }
      } else {
        $success = 1;
        $rc = $exitvalue;
        $output = $self->{macros}->{CL_SERVICEOUTPUT};
      }
    }
  } else {
    my $pathsep = ($^O =~ /MSWin/) ? ';' : ':';
    foreach my $dir (split(/$pathsep/, $self->{scriptpath})) {
      if ( -x $dir.'/'.$script ) {
        $self->trace(sprintf "found script in %s/%s", $dir, $script);
        $cmd = sprintf "%s/%s", $dir, $script;
        if ($^O =~ /MSWin/) {
          $cmd =~ s/\//\\/g;
          if ($cmd =~ /\s/) {
            if (defined(&Win32::GetShortPathName)) {
              $cmd = &Win32::GetShortPathName($cmd);
            } else {
              $cmd = sprintf "\"%s\"", $cmd;
            }
          }
        } else {
          # need to escape blanks
          if ($cmd =~ /\s/) {
            $cmd =~ s/([ ])/\\$1/g;
          }
        }
        last;
      }
    }
    if ($cmd) {
      if (defined $scriptparams) {
        $self->resolve_macros(\$scriptparams);
        $cmd = sprintf "%s %s", $cmd, $scriptparams;
      }
      $self->trace(sprintf "execute %s", $cmd);
      if (defined $scriptstdin) {
        my $pid = 0;
        my $wait = 0;
        my $maxlines = 100;
        if (! ref($scriptstdin eq "ARRAY")) {
          $scriptstdin = [$scriptstdin];
        }
        foreach (@{$scriptstdin}) {
          $self->resolve_macros(\$_);
        }
        @stdinformat = @{$scriptstdin};
        #  if the format string was defined using single quotes, the escape
        #  characters must be expanded.
        $stdinformat[0] =~ s/\\t/\t/g;
        $stdinformat[0] =~ s/\\n/\n/g;
        # if there is a % in CL_SERVICEOUTPUT we have to escape it
        $stdinformat[0] =~ s/%/%%/g;
        $SIG{'PIPE'} = sub {};
        $SIG{'CHLD'} = sub {};
        my($chld_out, $chld_in);
        $pid = open2($chld_out, $chld_in, $cmd);
        $self->trace("stdin is <<EOF");
        $self->trace(@stdinformat);
        $self->trace("EOF");
        $chld_in->printf(@stdinformat);
        $chld_in->close();
        $output = $chld_out->getline() || "";
        while ($maxlines-- > 0) {
          # sucking the remaining output to avoid sigpipe
          $chld_out->getline() || last;
        }
        chomp $output;
        $chld_out->flush();
        $chld_out->close();
        if ($^O =~ /MSWin/) {
          # unfortunately waitpid in rare cases returns -1 on windows
          $wait = wait;
        } else {
          $wait = waitpid $pid, 0;
        }
        $exitvalue  = $? >> 8;
        $signalnum  = $? & 127;
        $dumpedcore = $? & 128;
        if (($signalnum == 13) && ($maxlines < 0)) {
          $signalnum = 0;
          # the script printed more than the allowed 100 lines of output.
          # closing the descriptor $chld_out caused a SIGPIPE which will
          # be accepted here.
        }
      } else {
        my @output = `$cmd`;
        # find the first non-empty line
        @output = map { chomp; $_; } grep !/^$/, @output;
        $output = $output[0] || "";
        $exitvalue  = $? >> 8;
        $signalnum  = $? & 127;
        $dumpedcore = $? & 128;
      }
      $self->trace("script said: %s", $output);
      if ($wait != $pid) {
        $success = 0;
        $rc = -5;
        $self->trace("wait %d != %d", $wait, $pid);
      } elsif ($signalnum) {
        $success = 0;
        $rc = -2;
        $self->trace("script %s received signal %d", $script, $signalnum);
        $self->trace("script %s exits with code %d", $script, $rc);
      } elsif ($dumpedcore) {
        $success = 0;
        $rc = -3;
        $self->trace("script %s failed with core dump", $script);
      } elsif ($smart) {
        if ($exitvalue >= 0 && $exitvalue <= 3) {
          $success = 1;
          $rc = $exitvalue;
          $self->trace("script %s exits with code %d", $script, $rc);
        } else {
          $success = 0;
          $rc = -4;
          $self->trace("script %s failed for unknown reasons", $script);
        }
      } else {
        $success = 1;
        $rc = $exitvalue;
        $output = $self->{macros}->{CL_SERVICEOUTPUT};
      }
    } else {
      $self->trace(sprintf "could not find %s", $script);
      $success = 0;
      $rc = -1;
    }
  }
  if ($scriptdelay) {
    $self->trace(sprintf "sleeping for %d seconds", $scriptdelay);
    sleep $scriptdelay;
  }
  map { /^CHECK_LOGFILES/ && delete $ENV{$_}; } keys %{$ENV};
  if($output) {
    # remove ticks in case the script was badly programmed
    # this is ugly and should be left to the scripts author
    $output =~ s/^"//;
    $output =~ s/"$//g;
  }
  return ($success, $rc, $output)
}


sub getfilefingerprint {
  my $self = shift;
  my $file = shift;
  if (-f $file) {
    if ($self->get_option('randominode')) {
      return "00:00";
    } elsif ($^O eq "MSWin32") {
      my $magic;
      if (ref $file) {
        my $pos = $file->tell();
        $file->seek(0, 0);
        $magic = $file->getline() || "this_was_an_empty_file";
        $file->seek(0, $pos);
      } else {
        my $fh = new IO::File;
        $fh->open($file, "r");
        $magic = $fh->getline() || "this_was_an_empty_file";
        $fh->close();
      }
      if ($self->{options}->{encoding}) {
        $magic =~ tr/\x80-\xFF//d;
        $magic =~ tr/\x00-\x1F//d;
      }
      $self->trace("magic: %s", $magic);
      #return(md5_base64($magic));
      return(unpack("H*", $magic));
      # use the creation time as unique identifier
      # haaaahaaaaaa win32 creation time is a good joke
      # google for "tunneling"
      return sprintf "0:%d", (stat $file)[10];
      #return "0:0";
    } else {
      return sprintf "%d:%d", (stat $file)[0], (stat $file)[1];
    }
  } else {
    return "0:0";
  }
}


sub getfilesize {
  my $self = shift;
  my $file = shift;
  return (-f $file) ? (stat $file)[7] : 0;
}

sub getfileisreadable {
  my $self = shift;
  my $file = shift;
  if ($^O =~ /MSWin/) {
    # -r is not reliable when working with cacls
    my $fh = new IO::File;
    if ($fh->open($file, "r")) {
      $fh->close();
      return 1;
    } else {
      return undef;
    }
  } elsif (-r $file) {
    return 1;
  } else {
    use filetest 'access';
    $self->trace("stat (%s) failed, try access instead", $file);
    if (-r $file) {
      return 1;
    } else { # i'm catholic. i believe in miracles.
      my $fh = new IO::File;
      if ($fh->open($file, "r")) {
        $fh->close();
        return 1;
      } else {
        return 0;
      }
    }
  }
}

sub getfileisexecutable {
  my $self = shift;
  my $file = shift;
  if ($^O =~ /MSWin/) {
    printf STDERR "not yet\n";
  } elsif (-x $file) {
    return 1;
  } else {
    use filetest 'access';
    $self->trace("stat (%s) failed, try access instead", $file);
    if (-x $file) {
      return 1;
    } else { 
      return 0;
    }
  } 
} 

sub old_getfileisreadable {
  my $self = shift;
  my $file = shift;
  my $fh = new IO::File;
  if ($^O =~ /MSWin/) {
    if ($fh->open($file, "r")) {
      $fh->close();
      return 1;
    } else {
      return undef;
    }
  } elsif (($^O eq "linux") || ($^O eq "cygwin")) {
    if (! -r $file) {
      use filetest 'access';
      $self->trace("stat (%s) failed, try access instead", $file);
      return -r $file;
    }
    return -r $file;
  } else { 
    return -r $file;
  }
}

sub system_tempdir {
  my $self = shift;
  if ($^O =~ /MSWin/) {
    return $ENV{TEMP} if defined $ENV{TEMP};
    return $ENV{TMP} if defined $ENV{TMP};
    return File::Spec->catfile($ENV{windir}, 'Temp')
        if defined $ENV{windir};
    return 'C:\Temp';
  } else {
    return "/tmp";
  }
}

sub construct_pidfile {
  my $self = shift;
  $self->{pidfilebase} = $self->{abscfgfile};
  $self->{pidfilebase} =~ s/\//_/g;
  $self->{pidfilebase} =~ s/\\/_/g; 
  $self->{pidfilebase} =~ s/:/_/g;
  $self->{pidfilebase} =~ s/\s/_/g;
  $self->{pidfilebase} =~ s/\.cfg$//g;
  return sprintf "%s/%s.pid", $self->{seekfilesdir},
      $self->{pidfilebase};
}

sub write_pidfile {
  my $self = shift;
  if (! -d dirname($self->{pidfile})) {
    eval "require File::Path;";
    if (defined(&File::Path::mkpath)) {
      import File::Path;
      eval { mkpath(dirname($self->{pidfile})); };
    } else {
      my @dirs = ();
      map { 
          push @dirs, $_;
          mkdir(join('/', @dirs)) 
              if join('/', @dirs) && ! -d join('/', @dirs);
      } split(/\//, dirname($self->{pidfile}));
    }
  }
  my $fh = new IO::File;
  $fh->autoflush(1);
  if ($fh->open($self->{pidfile}, "w")) {
    $fh->printf("%s", $$);
    $fh->close();
  } else {
    $self->trace("Could not write pidfile %s", $self->{pidfile});
    die "pid file could not be written";
  }
}

sub check_pidfile {
  my $self = shift;
  my $fh = new IO::File;
  if ($fh->open($self->{pidfile}, "r")) {
    my $pid = $fh->getline();
    $fh->close();
    if (! $pid) {
      $self->trace("Found pidfile %s with no valid pid. Exiting.", 
          $self->{pidfile});
      return 0;
    } else {
      $self->trace("Found pidfile %s with pid %d", $self->{pidfile}, $pid);
      kill 0, $pid;
      if ($! == Errno::ESRCH) {
        $self->trace("This pidfile is stale. Writing a new one");
        $self->write_pidfile();
        return 1;
      } else {
        $self->trace("This pidfile is held by a running process. Exiting");
        return 0;
      }
    }
  } else {
    $self->trace("Found no pidfile. Writing a new one");
    $self->write_pidfile();
    return 1;
  }
}

sub run_as_daemon {
  my $self = shift;
  my $delay = shift;
  if ($^O =~ /MSWin/) {
    if ($ENV{PROMPT}) { # i was called from a shell
      # vielleicht irgendwas mit detach
      die "not yet implemented";
    } else {
      eval "require Win32::Daemon;";
      if (defined(&Win32::Daemon::StartService)) {
        import Win32::Daemon;
        my $svc_callback = sub {
          my( $event, $context ) = @_;
          #
          # entgegen der DRECKSDOKU enthaelt $event NICHT den Status
          # 
          $event = Win32::Daemon::State();
          $context->{last_event} = $event;
          if ($event == SERVICE_RUNNING()) {
            # main loop
            $self->trace("Entering main loop");
            do {
              $self->run();
              $self->trace(sprintf "%s%s\n%s", $self->{exitmessage},
                  $self->{perfdata} ? "|".$self->{perfdata} : "",
                  $self->{long_exitmessage} ?
                  $self->{long_exitmessage}."\n" : "");
              $self->reset();
              foreach (1..$delay) {
                if (Win32::Daemon::State() == SERVICE_RUNNING()) {
                  sleep 1;
                } else {
                  last;
                }
              }
            } while(Win32::Daemon::State() == SERVICE_RUNNING());
            $self->trace("Leaving main loop");
          } elsif ($event == SERVICE_START_PENDING()) {
            # Initialization code
            $self->trace("Service initialized");
            $context->{last_state} = SERVICE_RUNNING();
            Win32::Daemon::State(SERVICE_RUNNING());
          } elsif ($event == SERVICE_PAUSE_PENDING()) {
            $self->trace("Service makes a break");
            $context->{last_state} = SERVICE_PAUSED();
            Win32::Daemon::State(SERVICE_PAUSED());
          } elsif ($event == SERVICE_CONTINUE_PENDING()) {
            $self->trace("Service continues");
            $context->{last_state} = SERVICE_RUNNING();
            Win32::Daemon::State(SERVICE_RUNNING());
          } elsif ($event == SERVICE_STOP_PENDING()) {
            $self->trace("Service stops");
            $context->{last_state} = SERVICE_STOPPED();
            $self->trace("Daemon exiting...");
            Win32::Daemon::State(SERVICE_STOPPED());
            Win32::Daemon::StopService();
          } else {
            # Take care of unhandled states by setting the State()
            # to whatever the last state was we set...
            $self->trace("Service got an unhandled call");
            Win32::Daemon::State( $context->{last_state} );
          }
          return();
        };
        Win32::Daemon::RegisterCallbacks($svc_callback);
        my %context = (
            count   =>  0,
            start_time => time(),
            keep_going => 0,
            make_a_break => 0,
        );
        # Start the service passing in a context and
        # indicating to callback using the "Running" event
        # every 2000 milliseconds (2 seconds).
        Win32::Daemon::StartService(\%context, 2000);
      } else {
        die "omeiomeiomei nix Win32::Daemon";
      }
    }
  } else {
    # pidfile must be created before the chdir because it is based on the
    # cfgfile which can be a relative path
    $self->{pidfile} = $self->{pidfile} || $self->construct_pidfile();
    if (! $self->check_pidfile()) {
      $self->trace("Exiting because another daemon is already running");
      printf STDERR "Exiting because another daemon is already running\n";
      exit 3;
    }
    if (! POSIX::setsid()) {
      $self->trace("Cannot detach from controlling terminal");
      printf STDERR "Cannot detach from controlling terminal\n";
      exit 3;
    }
    $self->set_memory_limit();
    chdir '/';
    exit if (fork());
    exit if (fork());
    open STDIN, '+>/dev/null';
    open STDOUT, '+>&STDIN';
    open STDERR, '+>&STDIN';
    my $keep_going = 1;
    $self->trace(sprintf "Daemon running with pid %d", $$);
    foreach my $signal (qw(HUP INT TERM QUIT)) {
      $SIG{$signal}  = sub {
        $self->trace("Caught SIG%s:  exiting gracefully", $signal);
        $keep_going = 0;
      };
    }
    $self->trace("Entering main loop");
    do {
      $self->run();
      $self->write_pidfile();
      $self->trace(sprintf "%s%s\n%s", $self->{exitmessage},
          $self->{perfdata} ? "|".$self->{perfdata} : "",
          $self->{long_exitmessage} ? $self->{long_exitmessage}."\n" : "");
      $self->reset();
      foreach (1..$delay) {
        if ($keep_going) {
          sleep 1;
        } else {
          last;
        }
      }
    } while($keep_going);
    -f $self->{pidfile} && unlink $self->{pidfile};
    $self->trace("Daemon exiting...");
  }
}

sub install_windows_service {
  my $self = shift;
  my $servicename = shift || 'check_logfiles';
  my $cfgfile = shift;
  my $username = shift;
  my $password = shift;
  if ($^O =~ /MSWin/) {
    eval "require Win32::Daemon;";
    if (defined(&Win32::Daemon::StartService)) {
      import Win32::Daemon;
      my $fullpath = Win32::GetFullPathName($0);
      my ($cwd, $base, $ext) = ( $fullpath =~ /^(.*\\)(.*)\.(.*)$/ ) [0..2] ;
      my $servicepath = ($ext eq 'exe') ?
        "\"$fullpath\"" : "\"$^X\"";
      my $serviceparameters = ($ext eq 'exe') ?
        "--daemon --config \"$cfgfile\"" :
        " \"$fullpath\" --daemon --config \"$cfgfile\"";
      my $service = {
        machine => '',
        name => $servicename,
        display => $servicename,
        path => $servicepath,
        parameters => $serviceparameters,
        user => ($username || ''),
        password => ($password || ''),
        description => 'This is the Nagios plugin check_logfiles',
      };
      if (Win32::Daemon::CreateService($service)) {
        $self->{exitmessage} = 'Successfully added service';
        $self->{exitcode} = 0;
      } else {
        $self->{exitmessage} = 'Failed to add service: '.
          Win32::FormatMessage(Win32::Daemon::GetLastError());
        $self->{exitcode} = 3;
      }
    } else {
      die "nix Win32::Daemon, nix Service, nix install";
    }
  } else {
    $self->{exitmessage} = 'You just installed a Windows service on a Unix machine. Good luck.';
    $self->{exitcode} = 0;
  }
}

sub deinstall_windows_service {
  my $self = shift;
  my $servicename = shift || 'check_logfiles';
  if ($^O =~ /MSWin/) {
    eval "require Win32::Daemon;";
    if (defined(&Win32::Daemon::StartService)) {
      import Win32::Daemon;
      if (Win32::Daemon::DeleteService('', $servicename)) {
        $self->{exitmessage} = 'Successfully deinstalled service';
        $self->{exitcode} = 0;
      } else {
        $self->{exitmessage} = 'Failed to deinstall service: '.
          Win32::FormatMessage(Win32::Daemon::GetLastError());
        $self->{exitcode} = 3;
      }
    }
  } else {
    $self->{exitmessage} = 'Congrats. You just deinstalled a Windows service on a Unix machine.';
    $self->{exitcode} = 0;
  }
}


# We won't allow check_logfiles to consume 70GB of memory any more :-)
sub set_memory_limit {
  my $self = shift;
  my $limit = $self->get_option("maxmemsize"); # megabytes
  if (! $limit) {
    return;
  } elsif ($limit < 200) {
    $self->trace("I won't run with at least 200MB memory");
    printf STDERR "I won't run with at least 200MB memory\n";
    exit 3;
  } elsif ($^O eq "solaris" && ! defined(&SYS_setrlimit)) {
      # From /usr/include/sys/syscall.h and /usr/include/sys/resource.h
      eval 'sub SYS_setrlimit () {128;}';
      eval 'sub SYS_getrlimit () {129;}';
      eval 'sub RLIMIT_AS () {6;}';
  } elsif (! defined(&SYS_setrlimit)) {
    $self->trace("I dont't know how to set resource limits");
    printf STDERR "I dont't know how to set resource limits\n";
    exit 3;
  }
  $SIG{'SEGV'} = sub {
    # usually the perl interpreter aborts after a failed mmap with a
    # "Out of memory" message. Do not expect to execute a signal handler.
    printf "I received a SIGSEGV\n";
    exit 3;
  };
  my $soft_as_limit = int(1024 * 1024 * $limit);
  my $hard_as_limit = int(1024 * 1024 * $limit);
  # L! = native long unsigned int
  my $limits = pack "L!L!", $soft_as_limit, $hard_as_limit;
  if (syscall(&SYS_setrlimit, &RLIMIT_AS, $limits) == -1) {
    $self->trace("Cannot set address space limits (%s)", "$!");
    printf STDERR "Cannot set address space limits (%s)\n", "$!";
    exit 3;
  } else {
    syscall(&SYS_getrlimit, &RLIMIT_AS, $limits);
    my ($new_soft_as_limit, $new_hard_as_limit) = unpack "L!L!", $limits;
    if ($new_soft_as_limit != $soft_as_limit) {
      $self->trace("Cannot set address space limits (!=)");
      printf STDERR "Cannot set address space limits (!=)\n";
      exit 3;
    } else {
      $self->trace("Setting address space limits to %.2fMB", $limit);
    }
  }
}


package Nagios::CheckLogfiles::Search;

use strict;
use Exporter;
use File::Basename;
use POSIX qw(SSIZE_MAX);
#use Unicode::Normalize;
#use Encode;
use vars qw(@ISA);

use constant OK => 0;
use constant WARNING => 1;
use constant CRITICAL => 2;
use constant UNKNOWN => 3;

@ISA = qw(Nagios::CheckLogfiles);

sub new {
  my $self = bless {}, shift;
  my $params = shift;
  $self->{tag} = $params->{tag} || 'default';
  $self->{template} = $params->{template} if $params->{template};
  $self->{dynamictag} = $params->{dynamictag} if $params->{dynamictag};
  if (exists $self->{template} && exists $self->{dynamictag}) {
    $self->{tag} = $self->{template}.'_'.$self->{dynamictag};
  } else {
    $self->{tag} = $params->{tag} || 'default';
  }
  $self->{type} = $params->{type};
  $self->{logfile} = $params->{logfile};
  $self->{rotation} = $params->{rotation};
  $self->{script} = $params->{script};
  $self->{scriptparams} = $params->{scriptparams};
  $self->{scriptstdin} = $params->{scriptstdin};
  $self->{scriptdelay} = $params->{scriptdelay};
  $self->{cfgbase} = $params->{cfgbase} || "check_logfiles";
  $self->{seekfilesdir} = $params->{seekfilesdir} || $self->system_tempdir();
  $self->{archivedir} = $params->{archivedir};
  $self->{scriptpath} = $params->{scriptpath};
  $self->{macros} = $params->{macros};
  $self->{tracefile} = $params->{tracefile};
  $self->{prefilter} = $params->{prefilter};
  $self->{trace} = -e $self->{tracefile} ? 1 : 0;
  if (exists $params->{tivolipatterns}) {
    my $tivoliparams = { };
    my $tivolipatterns = [];
    my $tivoliformatfiles = [];
    my $tivoliformatstrings = [];
    if (ref($params->{tivolipatterns}) ne 'ARRAY') {
      $tivolipatterns = [$params->{tivolipatterns}];
    } else {
      push(@{$tivolipatterns}, @{$params->{tivolipatterns}});
    }
    foreach my $pattern (@{$tivolipatterns}) {
      if (scalar(@{[split /\n/, $pattern]}) == 1) {
        push(@{$tivoliparams->{formatfile}}, $pattern);
      } else {
        #push(@{$tivoliparams->{formatstring}}, $pattern);
        # erstmal nur skalar moeglich
        $tivoliparams->{formatstring} = $pattern;
      }
    }
    if (exists $params->{tivolimapping}) {
      foreach (keys %{$params->{tivolimapping}}) {
        $tivoliparams->{severity_mappings}->{lc $_} = 0 if 
          $params->{tivolimapping}->{$_} =~ /(?i)ok/;
        $tivoliparams->{severity_mappings}->{lc $_} = 1 if 
          $params->{tivolimapping}->{$_} =~ /(?i)warning/;
        $tivoliparams->{severity_mappings}->{lc $_} = 2 if 
          $params->{tivolimapping}->{$_} =~ /(?i)critical/;
        $tivoliparams->{severity_mappings}->{lc $_} = 3 if 
          $params->{tivolimapping}->{$_} =~ /(?i)unknown/;
        $tivoliparams->{severity_mappings}->{lc $_} =
          $params->{tivolimapping}->{$_} if 
          $params->{tivolimapping}->{$_} =~ /\d/;
      }
    }
    if ($self->{tivoli}->{object} = Nagios::Tivoli::Config::Logfile->new(
          $tivoliparams )) {
    } else {
      die "could not create tivoli object from $params->{tivolipatterns}";
    }
  }
  if (! $self->{type}) {
    if ($self->{rotation}) {
      $self->{type} = "rotating";
    } else {
      $self->{type} = "simple";
    }
  }
  $self->{privatestate} = {};
  my $class = sprintf "Nagios::CheckLogfiles::Search::%s",
     join "::", map {
       (uc substr($_, 0, 1)).substr($_, 1);
     } split(/::/, $self->{type});
  bless $self, $class;
  if (! $self->can("init")) {
    #
    #  Maybe $class was not defined in this file. Try to find 
    #  the external module.
    #
    my $module = $class.".pm";
    $module =~ s/::/\//g;
    foreach (@INC) {
      if (-f $_."/$module") {
        require $module;
        bless $self, $class;
        last;
      }
    }
  }
  if ($self->can("init")) {
    if ($self->init($params)) {
      return $self;
    } else {
      return undef;
    }
  } else {
    return undef;
  }
}

#
#  Read a hash with parameters
#
sub init {
  my $self = shift;
  my $params = shift;
  $self->{laststate} = {};
  $self->{relevantfiles} = [];
  $self->{preliminaryfilter} = { SKIP => [], NEED => [] };
  $self->{matchlines} = { OK => [], WARNING => [], CRITICAL => [], UNKNOWN => [] };
  $self->{lastmsg} = { OK => "", WARNING => "", CRITICAL => "", UNKNOWN => "" };
  $self->{patterns} = { OK => [], WARNING => [], CRITICAL => [], UNKNOWN => [] };
  $self->{patternfuncs} = { OK => [], WARNING => [], CRITICAL => [], UNKNOWN => [] };
  $self->{negpatterns} = { OK => [], WARNING => [], CRITICAL => [], UNKNOWN => [] };
  $self->{negpatterncnt} = { OK => [], WARNING => [], CRITICAL => [], UNKNOWN => [] };
  $self->{exceptions} = { OK => [], WARNING => [], CRITICAL => [], UNKNOWN => [] };
  $self->{threshold} = { OK => 0, WARNING => 0, CRITICAL => 0, UNKNOWN => 0 };
  $self->{thresholdcnt} = { OK => 0, WARNING => 0, CRITICAL => 0, UNKNOWN => 0 };
  $self->{patternkeys} = { OK => {}, WARNING => {}, CRITICAL => {}, UNKNOWN => {} };
  $self->{filepatterns} = {};
  $self->{hasinversepat} = 0;
  $self->{likeavirgin} = 0;
  $self->{linesread} = 0;
  $self->{linenumber} = 0; # used for context
    $self->{perfdata} = "";
  $self->{max_readsize} = 1024 * 1024 * 128;
  # sysread can only read SSIZE_MAX bytes in one operation.
  # this is often (1024 * 1024 * 1024 * 2) - 1 = 2GB - 1
  # if we need to read from a non-seekable filehandle more than this
  # amount of data, then we have to perform multiple reads.
  # because the $bytes variable must hold the result of such a read and
  # its size is limited by available memory, it is divided by 16
  # so each read request does not overburden the sysread call and
  # does not inflate the process to more than 128MB
  #
  # options
  #
  $self->default_options({ script => 0, smartscript => 0, supersmartscript => 0,
      protocol => 1, count => 1, syslogserver => 0, logfilenocry => 1,
      perfdata => 1, case => 1, sticky => 0, syslogclient => 0,
      savethresholdcount => 1, encoding => 0, maxlength => 0, 
      lookback => 0, context => 0, allyoucaneat => 0, randominode => 0,
      preferredlevel => 0,
      warningthreshold => 0, criticalthreshold => 0, unknownthreshold => 0,
      report => 'short',
      seekfileerror => 'critical', logfileerror => 'critical', 
      archivedirregexp => 0,
  });
  $self->refresh_options($params->{options});
  #
  #  Dynamic logfile names may contain macros.
  #
  if (exists $self->{template} && exists $self->{dynamictag}) {
    $self->{macros}->{CL_TAG} = $self->{dynamictag};
    $self->{macros}->{CL_tag} = lc $self->{dynamictag};
    $self->{macros}->{CL_TEMPLATE} = $self->{template};
  } else {
    $self->resolve_macros(\$self->{tag});
    $self->{macros}->{CL_TAG} = $self->{tag};
    # http://www.nagios-portal.org/wbb/index.php?page=Thread&threadID=18392
    # this saves a lot of time when you are working with oracle alertlogs
    $self->{macros}->{CL_tag} = lc $self->{tag};
  }
  $self->{logfile_before_resolving} = $self->{logfile};
  $self->resolve_macros(\$self->{logfile});
  $self->{macros}->{CL_LOGFILE} = $self->{logfile};
  $self->{logbasename} = basename($self->{logfile});
  $self->{archivedir} = exists $params->{archivedir} ? $params->{archivedir} :
    dirname($self->{logfile});
  $self->resolve_macros(\$self->{archivedir});
  #
  #  Preliminary filter
  #
  if ($self->{prefilter}) {
    my $pattern = $self->{prefilter};
    $self->resolve_macros_in_pattern(\$pattern);
    $pattern = '(?i)'.$pattern unless $self->{options}->{case};
    $self->addfilter(1, $pattern);
  }
  if ($self->{options}->{syslogclient}) {
    my $pattern = $self->{options}->{syslogclient};
    $self->resolve_macros_in_pattern(\$pattern);
    $pattern = '(?i)'.$pattern unless $self->{options}->{case};
    $self->addfilter(1, $pattern);
  }
  if ($self->{options}->{syslogserver}) {
    my $pattern = '($CL_HOSTNAME$|localhost)';
    $self->resolve_macros_in_pattern(\$pattern);
    $pattern = '(?i)'.$pattern unless $self->{options}->{case};
    $self->addfilter(1, $pattern);
  }
  #
  # the guy who begged me for the encoding option never wrote me a mail again.
  # this means for me, encoding works perfect. if it does not work for you
  # then it's not my problem.
  #
  if ($self->{options}->{encoding}) {
    #require Encode qw(encode decode);
    require Encode;
  }
  #
  #  Setup the structure describing what to search for.
  #
  foreach my $level (qw(OK CRITICAL WARNING UNKNOWN)) {
    #
    #  if a single pattern was given as a scalar, force it into an array
    #  and resolve macros.
    #
    if (exists $params->{(lc $level).'patterns'}) {
      if (ref($params->{(lc $level).'patterns'}) eq 'HASH') {
        map {
          my $value = $params->{(lc $level).'patterns'}->{$_};
          $self->{patternkeys}->{$level}->{$value} = $_;
        } keys %{$params->{(lc $level).'patterns'}};
        my $tmphash = $params->{(lc $level).'patterns'};
        $params->{(lc $level).'patterns'} = [];
        @{$params->{(lc $level).'patterns'}} = values %{$tmphash};
      } elsif (ref($params->{(lc $level).'patterns'}) eq 'ARRAY') {
      } else {
        $params->{(lc $level).'patterns'} =
            [$params->{(lc $level).'patterns'}];
      }
    }
    if (exists $params->{(lc $level).'exceptions'}) {
      if (ref($params->{(lc $level).'exceptions'}) eq 'HASH') {
        $params->{(lc $level).'exceptions'} =
            values %{$params->{(lc $level).'exceptions'}};
        my $tmphash = $params->{(lc $level).'exceptions'};
        $params->{(lc $level).'exceptions'} = [];
        @{$params->{(lc $level).'exceptions'}} = values %{$tmphash};
      } elsif (ref($params->{(lc $level).'exceptions'}) eq 'ARRAY') {
      } else {
        $params->{(lc $level).'exceptions'} =
            [$params->{(lc $level).'exceptions'}];
      }
    }
  }
  if (exists $params->{patternfiles}) {
    if (ref($params->{patternfiles}) ne 'ARRAY') {
      $params->{patternfiles} = [$params->{patternfiles}];
    }
    foreach my $patternfile (@{$params->{patternfiles}}) {
      our($criticalpatterns, $warningpatterns,
          $criticalexceptions, $warningexceptions);
      ($criticalpatterns, $warningpatterns,
          $criticalexceptions, $warningexceptions) = (undef, undef, undef, undef);
      eval {
        do $patternfile;
      };
      if ($@) {
        printf STDERR "%s\n", $@;
        $self->addevent(3, $@);
      } else {
        my $filepatterns = {};
        $filepatterns->{criticalpatterns} = $criticalpatterns
            if $criticalpatterns;
        $filepatterns->{warningpatterns} = $warningpatterns
            if $warningpatterns;
        $filepatterns->{criticalexceptions} = $criticalexceptions
            if $criticalexceptions;
        $filepatterns->{warningexceptions} = $warningexceptions
            if $warningexceptions;
        foreach my $level (qw(ok warning critical unknown)) {
          # normalize
          if (exists $filepatterns->{$level.'patterns'}) {
            if (ref($filepatterns->{$level.'patterns'}) eq 'HASH') {
              map {
                my $value = $filepatterns->{$level.'patterns'}->{$_};
                $self->{patternkeys}->{$level}->{$value} = $_;
              } keys %{$filepatterns->{$level.'patterns'}};
              my $tmphash = $filepatterns->{$level.'patterns'};
              $filepatterns->{$level.'patterns'} = [];
              @{$filepatterns->{$level.'patterns'}} = values %{$tmphash};
            } elsif (ref($filepatterns->{$level.'patterns'}) eq 'ARRAY') {
            } else {
              $filepatterns->{$level.'patterns'} = 
                  [$filepatterns->{$level.'patterns'}];
            }
          }
          if (exists $filepatterns->{$level.'exceptions'}) {
            if (ref($filepatterns->{$level.'exceptions'}) eq 'HASH') {
              map {
                my $value = $filepatterns->{$level.'exceptions'}->{$_};
                $self->{patternkeys}->{$level}->{$value} = $_;
              } keys %{$filepatterns->{$level.'exceptions'}};
              my $tmphash = $filepatterns->{$level.'exceptions'};
              $filepatterns->{$level.'exceptions'} = [];
              @{$filepatterns->{$level.'exceptions'}} = values %{$tmphash};
            } elsif (ref($filepatterns->{$level.'exceptions'}) eq 'ARRAY') {
            } else {
              $filepatterns->{$level.'exceptions'} =
                  [$filepatterns->{$level.'exceptions'}];
            }
          }
          if (exists $params->{$level.'patterns'}) {
            if (exists $filepatterns->{$level.'patterns'}) {
              unshift(@{$params->{$level.'patterns'}},
                  @{$filepatterns->{$level.'patterns'}});
            }
          } else {
            if (exists $filepatterns->{$level.'patterns'}) {
              @{$params->{$level.'patterns'}} = 
                  @{$filepatterns->{$level.'patterns'}};
            }
          }
          if (exists $params->{$level.'exceptions'}) {
            if (exists $filepatterns->{$level.'exceptions'}) {
              unshift(@{$params->{$level.'exceptions'}},
                  @{$filepatterns->{$level.'exceptions'}});
            }
          } else {
            if (exists $filepatterns->{$level.'exceptions'}) {
              @{$params->{$level.'exceptions'}} = 
                  @{$filepatterns->{$level.'exceptions'}};
            }
          }
        }
      }
    }
  }
  foreach my $level (qw(OK CRITICAL WARNING UNKNOWN)) {
    #
    #  if a single pattern was given as a scalar, force it into an array
    #  and resolve macros.
    #
    if (exists $params->{(lc $level).'patterns'}) {
      @{$self->{patterns}->{$level}} = @{$params->{(lc $level).'patterns'}};
      foreach my $pattern (@{$self->{patterns}->{$level}}) {
        my $key = $self->{patternkeys}->{$level}->{$pattern};
        $self->resolve_macros_in_pattern(\$pattern);
        $self->{patternkeys}->{$level}->{$pattern} = $key;
      }
      #
      #  separate the pattern arrays. patterns beginning with a "!" will raise
      #  an error if they cannot be found.
      #  this type of pattern also needs a counter for the matches because after
      #  scanning the logfiles we must also check for a "not-found" condition.
      #
      @{$self->{negpatterns}->{$level}} = map {
        if (substr($_, 0, 1) eq "!") {
          push(@{$self->{negpatterncnt}->{$level}}, 0);
          substr($_, 1)
        } else { () }
      } @{$self->{patterns}->{$level}};
      if (scalar(@{$self->{negpatterns}->{$level}})) {
        $self->{hasinversepat} = 1;
        @{$self->{patterns}->{$level}} = map {
          if (substr($_, 0, 1) ne "!") { $_ } else { () }
        } @{$self->{patterns}->{$level}};
      }
      #
      #  prepend the patterns with (?i) if the case insensitivity option is set 
      #
      if (! $self->{options}->{case}) {
        foreach my $pattern (@{$self->{patterns}->{$level}}) {
          $pattern = '(?i)'.$pattern;
        }
        foreach my $pattern (@{$self->{negpatterns}->{$level}}) {
          $pattern = '(?i)'.$pattern;
        }
      }
      #
      #  ignore the match unless a minimum of threshold occurrances were found
      #
      if ((! $self->{options}->{(lc $level).'threshold'}) &&
          ($params->{(lc $level).'threshold'})) {
        $self->{options}->{(lc $level).'threshold'} =
            $params->{(lc $level).'threshold'};
      }
      if ($self->{options}->{(lc $level).'threshold'}) {
        $self->{threshold}->{$level} = $self->{options}->{(lc $level).'threshold'} - 1;
      } else {
        $self->{threshold}->{$level} = 0;
      }
      foreach my $pattern (@{$self->{patterns}->{$level}}) {
        push(@{$self->{patternfuncs}->{$level}},
            eval "sub { local \$_ = shift; return m/\$pattern/o; }");
      }
    }
    if (exists $params->{(lc $level).'exceptions'}) {
      push(@{$self->{exceptions}->{$level}}, @{$params->{(lc $level).'exceptions'}});
      foreach my $pattern (@{$self->{exceptions}->{$level}}) {
        $self->resolve_macros_in_pattern(\$pattern);
      }
      if (! $self->{options}->{case}) {
        foreach my $pattern (@{$self->{exceptions}->{$level}}) {
          $pattern = '(?i)'.$pattern;
        }
      }
    }
  }
  foreach my $level (qw(CRITICAL WARNING UNKNOWN)) {
    foreach my $pattern (@{$self->{negpatterns}->{$level}}) {
      push(@{$self->{negpatterncnt}->{$level}}, 0);
    }
  }
  if (exists $self->{tivoli}->{object}) {
    $self->{patterns} = { OK => [], WARNING => [],
        CRITICAL => ['.*'], UNKNOWN => [] };
    push(@{$self->{patternfuncs}->{OK}}, sub { return undef; });
    push(@{$self->{patternfuncs}->{WARNING}}, sub { return undef; });
    push(@{$self->{patternfuncs}->{UNKNOWN}}, sub { return undef; });
    push(@{$self->{patternfuncs}->{CRITICAL}}, eval "sub { local \$_ = shift; return m/.*/o; }");
    $self->{tivoli}->{object}->set_format_mappings(
      hostname => $self->{macros}->{CL_HOSTNAME},
      fqhostname => $self->{macros}->{CL_FQDN},
      origin => $self->{macros}->{CL_IPADDRESS},
      FILENAME => (ref($self) eq 'Nagios::CheckLogfiles::Search::Eventlog') ?
          'EventLog' : $self->{macros}->{CL_LOGFILE},
          # oder SysLogD
      LABEL => $self->{macros}->{CL_HOSTNAME}, # NON-TME
    );
  }
  $self->construct_seekfile();
  $self->{NH_detection} = ($^O =~ /MSWin/) ? 0 : 1;
  return $self;
}

sub construct_seekfile {
  my $self = shift;
  # since 2.0 the complete path to the logfile is mapped to the seekfilename
  if ($self->{logfile} ne $self->{logfile_before_resolving}) {
    $self->{seekfilebase} = $self->{logfile_before_resolving};
    $self->{seekfilebase} =~ s/\$/_/g;
  } else {
    $self->{seekfilebase} = $self->{logfile};
  }
  $self->{seekfilebase} =~ s/\//_/g;
  $self->{seekfilebase} =~ s/\\/_/g;
  $self->{seekfilebase} =~ s/:/_/g;
  $self->{seekfilebase} =~ s/\s/_/g;
  $self->{seekfiletag} = $self->{tag};
  $self->{seekfiletag} =~ s/\//_/g;
  $self->{seekfile} = sprintf "%s/%s.%s.%s", $self->{seekfilesdir},
      $self->{cfgbase}, $self->{seekfilebase},
      $self->{tag} eq "default" ? "seek" : $self->{seekfiletag};
  $self->{pre3seekfile} = sprintf "/tmp/%s.%s.%s",
      $self->{cfgbase}, $self->{seekfilebase},
      $self->{tag} eq "default" ? "seek" : $self->{seekfiletag};
  $self->{pre2seekfile} = sprintf "%s/%s.%s.%s", $self->{seekfilesdir},
      $self->{cfgbase}, $self->{logbasename},
      $self->{tag} eq "default" ? "seek" : $self->{seekfiletag};
}

sub force_cfgbase {
  # this is for the -F option. after initialization the seek/protocolfiles
  # must be reset to cfgbase of the base configfile is used
  my $self = shift;
  $self->{cfgbase} = shift;
  $self->construct_seekfile();
}

sub prepare {
  my $self = shift;
  return $self;
}

sub finish {
  my $self = shift;
  return $self;
}

sub rewind {
  my $self = shift;
  $self->loadstate();
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
  $self->addevent(0, "reset");
  $self->{newstate}->{logoffset} = 0;
  $self->{newstate}->{logtime} = 0;
  $self->savestate();
  return $self;
}

sub unstick {
  my $self = shift;
  $self->loadstate();
  foreach (keys %{$self->{laststate}}) {
    $self->{newstate}->{$_} = $self->{laststate}->{$_};
  }
  $self->addevent(0, "unstick");
  $self->trace("remove the sticky error with --unstick");
  $self->{laststate}->{laststicked} = 0;
  $self->savestate();
  return $self;
}

sub run {
  my $self = shift;
  $self->trace(sprintf "==================== %s ==================", $self->{logfile});
  $self->prepare();
  $self->loadstate();
  $self->analyze_situation();
  if ($self->{logrotated} || $self->{logmodified} || $self->{hasinversepat}) {
    # be lazy and examine files only if necessary
    $self->collectfiles();
  }
  if ($self->{hasinversepat} || scalar(@{$self->{relevantfiles}})) {
    $self->scan();
  } else {
    $self->trace("nothing to do");
    # $state keeps the old values
    foreach (keys %{$self->{laststate}}) {
      $self->{newstate}->{$_} = $self->{laststate}->{$_};
    }
    $self->trace("keeping %s", $self->{newstate}->{servicestateid}) 
        if $self->{newstate}->{servicestateid}; # maybe this was the 1st time
  }
  $self->savestate();
  $self->finish();
  $self->formulate_perfdata();
}

=item loadstate()

    Load the last session's state. 
    The state is defined by
    - the position where the last search stopped
    - the time when the logfile was last touched then.
    - device and inode of the logfile (since version 1.4)
    If there is no state file, then this must be the first run of check_logfiles.
    In this case take the current file length as the stop position, so nothing will
    actually be done.
    
=cut
sub loadstate {
  my $self = shift;
  if (-f $self->{seekfile}) {
    $self->{likeavirgin} = 0;
    $self->trace(sprintf "found seekfile %s", $self->{seekfile});
    our $state = {};
    #eval {
      do $self->{seekfile};
    #};
    if ($@) {
      # found a seekfile with the old syntax
      $self->trace(sprintf "seekfile has old format %s", $@);
      my $seekfh = new IO::File;
      $seekfh->open($self->{seekfile}, "r");
      $self->{laststate} = {
          logoffset => $seekfh->getline() || 0,
          logtime => $seekfh->getline() || 0,
          devino => $seekfh->getline(),
          logfile => $self->{logfile},
      };
      chomp $self->{laststate}->{logoffset} if $self->{laststate}->{logoffset};
      chomp $self->{laststate}->{logtime} if $self->{laststate}->{logtime};
      chomp $self->{laststate}->{devino} if $self->{laststate}->{devino};
      $seekfh->close();
    } else {
      # found a new format seekfile
      $self->{laststate} = $state;
    }
    if (! $self->{laststate}->{logfile}) {
      $self->{laststate}->{logfile} = $self->{logfile};
    }
    if (! $self->{laststate}->{devino}) {
      # upgrade vom < 1.4 on the fly
      $self->{laststate}->{devino} = $self->getfilefingerprint($self->{logfile});
    }
    if (! $self->{laststate}->{servicestateid}) {
      $self->{laststate}->{servicestateid} = 0;
    }
    if (! $self->{laststate}->{serviceoutput}) {
      $self->{laststate}->{serviceoutput} = "OK";
    }
    foreach my $level (qw(CRITICAL WARNING UNKNOWN)) {
      if (exists $self->{laststate}->{thresholdcnt}->{$level}) {
        $self->{thresholdcnt}->{$level} =
            $self->{laststate}->{thresholdcnt}->{$level};
      } 
    }
    $self->trace("LS lastlogfile = %s", $self->{laststate}->{logfile});
    $self->trace("LS lastoffset = %u / lasttime = %d (%s) / inode = %s",
        $self->{laststate}->{logoffset}, $self->{laststate}->{logtime},
        scalar localtime($self->{laststate}->{logtime}),
        $self->{laststate}->{devino});
  } else {
    $self->trace("try pre2seekfile %s instead", $self->{pre2seekfile});
    if (-f $self->{pre2seekfile}) {
      $self->trace("pre-2.0 seekfile %s found. rename it to %s",
          $self->{pre2seekfile}, $self->{seekfile});
      mkdir $self->{seekfilesdir} if ! -d $self->{seekfilesdir};
      rename $self->{pre2seekfile}, $self->{seekfile};
      $self->trace("and call load_state again");
      $self->loadstate() if -f $self->{seekfile};
      return $self;
    }
    $self->trace("try pre3seekfile %s instead", $self->{pre3seekfile});
    if (-f $self->{pre3seekfile}) {
      $self->trace("pre-3.0 seekfile %s found. rename it to %s",
          $self->{pre3seekfile}, $self->{seekfile});
      mkdir $self->{seekfilesdir} if ! -d $self->{seekfilesdir};
      rename $self->{pre3seekfile}, $self->{seekfile};
      $self->trace("and call load_state again");
      $self->loadstate() if -f $self->{seekfile};
      return $self;
    }
    $self->{likeavirgin} = 1;
    $self->trace("no seekfile %s found", $self->{seekfile});
    if (-e $self->{logfile}) {
      $self->trace(sprintf "but logfile %s found", $self->{logfile});
      #  Fake a "the logfile was not touched" situation.
      $self->trace('eat all you can') if $self->{options}->{allyoucaneat};
      $self->{laststate} = {
          logoffset => ($self->{options}->{allyoucaneat} ?
              0 : $self->getfilesize($self->{logfile})),
          logtime => (stat $self->{logfile})[10],
          devino => $self->getfilefingerprint($self->{logfile}),
          logfile => $self->{logfile},
          servicestateid => 0,
          serviceoutput => "OK",
      };
    } else {
      $self->trace("and no logfile found");
      #  This is true virginity 
      $self->{laststate} = {
          logoffset => 0,
          logtime => 0,
          devino => "0:0",
          logfile => $self->{logfile},
          servicestateid => 0,
          serviceoutput => "OK",
      };
    }
    $self->trace("ILS lastlogfile = %s", $self->{laststate}->{logfile});
    $self->trace("ILS lastoffset = %u / lasttime = %d (%s) / inode = %s",
        $self->{laststate}->{logoffset}, $self->{laststate}->{logtime},
        scalar localtime($self->{laststate}->{logtime}), $self->{laststate}->{devino});
  }
  if (exists $self->{laststate}->{privatestate}) {
    $self->{privatestate} = $self->{laststate}->{privatestate};
    $self->trace("found private state %s", 
        Data::Dumper::Dumper($self->{privatestate}));
  }
  if (! $self->{laststate}->{runcount}) {
    $self->{laststate}->{runcount} = 1;
  } else {
    $self->{laststate}->{runcount}++;
  }
  if (! $self->{laststate}->{runtime}) {
    $self->{laststate}->{runtime} = 0;
  }
  $self->{privatestate}->{lastruntime} = $self->{laststate}->{runtime};
  $self->{privatestate}->{runcount} = $self->{laststate}->{runcount};
  $self->{privatestate}->{logfile} = $self->{macros}->{CL_LOGFILE};
  $self->{macros}->{CL_LAST_RUNTIME} = $self->{privatestate}->{lastruntime};
  $self->{macros}->{CL_RUN_COUNT} = $self->{privatestate}->{runcount};
  return $self;
}


=item savestate()

    Save a session's state. We need this for the next run of check_logfiles.
    Here we remember, how far we read the logfile, when it was last modified
    and what it's inode was.

=cut
sub savestate {
  my $self = shift;
  my $seekfh = new IO::File;
  my $now = time;
  $@ = undef; # reset this. when a pre-3.0 statefile was read, this is set
  $self->searchresult(); # calculate servicestateid and serviceoutput
  if ($self->{options}->{sticky}) {
    if ($self->get_option('report') ne 'short') {
      $self->{newstate}->{matchlines} = $self->{matchlines};
    }
    if ($self->{laststate}->{servicestateid}) {
      $self->trace("an error level of %s is sticking at me",
          $self->{laststate}->{servicestateid});
      $self->trace("and now i have %s",
          $self->{newstate}->{servicestateid});
      if ($self->{newstate}->{servicestateid}) {
        $self->{newstate}->{laststicked} = $now;
        $self->trace("refresh laststicked");
        # dont forget to count the sticky error
        if ($self->get_option('report') ne 'short') {
          foreach my $level (qw(OK WARNING CRITICAL UNKNOWN)) {
            my $servicestateid =
                {'OK'=>0,'WARNING'=>1,'CRITICAL'=>2,'UNKNOWN'=>3}->{$level};
            foreach my $event (
                reverse @{$self->{laststate}->{matchlines}->{$level}}) {
              $self->addfirstevent($servicestateid, $event);
            }
          }
        } else {
          $self->addfirstevent($self->{laststate}->{servicestateid},
              $self->{laststate}->{serviceoutput});
        }
        if (($self->{newstate}->{servicestateid} == 1) && 
            ($self->{laststate}->{servicestateid} == 2)) {
          # if this was a warning and we already have a sticky critical
          # save the critical as the sticky exitcode
          $self->{newstate}->{servicestateid} =
              $self->{laststate}->{servicestateid};
          # and keep the critical message as output
          $self->{newstate}->{serviceoutput} =
              $self->{laststate}->{serviceoutput};
        }
      } else {
        if ($self->{options}->{sticky} > 1) {
          # we had a stick error, then an ok pattern and no new error
          $self->trace("sticky error was resetted");
          $self->{newstate}->{laststicked} = 0;
          $self->{newstate}->{servicestateid} = 0;
          $self->{newstate}->{serviceoutput} = "";
          if ($self->get_option('report') ne 'short') {
            delete $self->{newstate}->{matchlines};
          }
        } else {
          # newstate is 0 because nothing happened in this scan
          # after maxstickytime do not carry on with this error.
          if (($now - $self->{laststate}->{laststicked}) >
              $self->{maxstickytime}) {
            $self->trace("maxstickytime %d expired", $self->{maxstickytime});
            $self->{newstate}->{laststicked} = 0;
            $self->{newstate}->{servicestateid} = 0;
            $self->{newstate}->{serviceoutput} = "";
            if ($self->get_option('report') ne 'short') {
              delete $self->{newstate}->{matchlines};
            }
          } else {
            $self->{newstate}->{laststicked} = 
                $self->{laststate}->{laststicked};
            $self->{newstate}->{servicestateid} = 
                $self->{laststate}->{servicestateid};
            $self->{newstate}->{serviceoutput} = 
                $self->{laststate}->{serviceoutput};
            $self->trace("stay sticky until %s", 
                scalar localtime ($self->{newstate}->{laststicked}
                + $self->{maxstickytime})); 
            if ($self->get_option('report') ne 'short') {
              foreach my $level (qw(OK WARNING CRITICAL UNKNOWN)) {
                my $servicestateid =
                  {'OK'=>0,'WARNING'=>1,'CRITICAL'=>2,'UNKNOWN'=>3}->{$level};
                foreach my $event (
                    reverse @{$self->{laststate}->{matchlines}->{$level}}) {
                  $self->addfirstevent($servicestateid, $event);
                }
              }
            } else {
              $self->addevent($self->{newstate}->{servicestateid},
                  $self->{newstate}->{serviceoutput});
            }
          }          
        }
      }
    } else {
      $self->trace("no sticky error from last run");
      if ($self->{newstate}->{servicestateid}) {
        $self->{newstate}->{laststicked} = $now;
        $self->trace("stick until %s", 
            scalar localtime ($self->{newstate}->{laststicked} + 
            $self->{maxstickytime}));      
      }      
    }
  }  
  # save threshold counts if a threshold exists for a level
  if ($self->{options}->{savethresholdcount}) {
    foreach my $level (qw(CRITICAL WARNING UNKNOWN)) {
      if ($self->{threshold}->{$level}) {
        $self->{newstate}->{thresholdcnt}->{$level} =
            $self->{thresholdcnt}->{$level};
      }
    } 
  }
  $self->{newstate}->{tag} = $self->{tag};
  $self->{newstate}->{privatestate} = $self->{privatestate};
  $self->{newstate}->{runcount} = $self->{laststate}->{runcount};
  $self->{newstate}->{runtime} = $now;
  # check if the file can be written
  if (! -d $self->{seekfilesdir}) {
    eval {
      use File::Path;
      mkpath $self->{seekfilesdir};
    };
  }
  if ($@ || ! -w $self->{seekfilesdir}) {
    $self->addevent($self->get_option('seekfileerror'), 
        sprintf "cannot write status file %s! check your filesystem (permissions/usage/integrity) and disk devices", $self->{seekfile});
    return $self;
  }
  if ($seekfh->open($self->{seekfile}, "w")) {
    my $dumpstate = Data::Dumper->new([$self->{newstate}], [qw(state)]);
    #printf("save %s\n", $dumpstate->Dump());
    $dumpstate = Data::Dumper->new([$self->{newstate}], [qw(state)]);
    $seekfh->printf("%s\n", $dumpstate->Dump());
    $seekfh->printf("\n1;\n");
    $seekfh->close();
    $self->trace("keeping position %u and time %d (%s) for inode %s in mind", 
        $self->{newstate}->{logoffset}, $self->{newstate}->{logtime},
        scalar localtime($self->{newstate}->{logtime}), 
        $self->{newstate}->{devino});
  } else {
    $self->{options}->{count} = 1;
    $self->addevent($self->get_option('seekfileerror'), 
        sprintf "cannot write status file %s! check your filesystem (permissions/usage/integrity) and disk devices", $self->{seekfile});
  }
  return $self;
}

sub formulate_perfdata {
  my $self = shift;
  if ($self->{options}->{perfdata}) {
    if (exists $self->{template} && $self->{dynamictag}) {
      $self->{perftag} = $self->{template};
    } else {
      $self->{perftag} = $self->{tag};
    }
    $self->{perfdata} = 
        sprintf "%s_lines=%d %s_warnings=%d %s_criticals=%d %s_unknowns=%d",
        $self->{perftag}, $self->{linesread},
        $self->{perftag}, scalar(@{$self->{matchlines}->{WARNING}}),
        $self->{perftag}, scalar(@{$self->{matchlines}->{CRITICAL}}),
        $self->{perftag}, scalar(@{$self->{matchlines}->{UNKNOWN}});
  }
}

sub addevent {
  my $self = shift;
  my $level = shift;
  my $errormessage = shift;
  if (! defined $errormessage || $errormessage eq '') {
    $errormessage = '_(null)_';
  }
  if ($self->{options}->{maxlength}) {
    $errormessage = substr $errormessage, 0, $self->{options}->{maxlength};
  }
  if ($level =~ /^\d/) {
    $level = (qw(OK WARNING CRITICAL UNKNOWN))[$level];
  } else {
    $level = uc $level;
  }
  push(@{$self->{matchlines}->{$level}}, $errormessage);
  $self->{lastmsg}->{$level} =
      ${$self->{matchlines}->{$level}}[$#{$self->{matchlines}->{$level}}];
}

sub update_context {
  my $self = shift;
  my $follow = shift;
  my $line = shift;
  
}

sub addfirstevent {
  my $self = shift;
  my $level = shift;
  my $errormessage = shift;
  if ($level =~ /^\d/) {
    $level = (qw(OK WARNING CRITICAL UNKNOWN))[$level];
  }
  unshift(@{$self->{matchlines}->{$level}}, $errormessage);
  $self->{lastmsg}->{$level} = 
      ${$self->{matchlines}->{$level}}[$#{$self->{matchlines}->{$level}}];
}

#
#  Read through all files found during analyze_situation and compare
#  the contents with patterns declared critical or warning or....
#
sub scan {
  my $self = shift;
  my $actionfailed = 0;
  my $resetted = 0;
  my $needfilter = scalar(@{$self->{preliminaryfilter}->{NEED}});
  my $skipfilter = scalar(@{$self->{preliminaryfilter}->{SKIP}});
  foreach my $logfile (@{$self->{relevantfiles}}) {
    $self->trace("moving to position %u in %s", $self->{laststate}->{logoffset},
        $logfile->{filename});
    if ($logfile->{seekable}) {
      $logfile->{fh}->seek($self->{laststate}->{logoffset}, 0);
    } else {
      my $buf;
      my $needtoread;
      $logfile->{offset} = 0;
      if ($self->{laststate}->{logoffset} > $self->{max_readsize}) {
        $needtoread = $self->{max_readsize};
        $self->trace("i cannot sysread %u bytes. begin with %u bytes",
            $self->{laststate}->{logoffset}, $needtoread);
      } else {
        $needtoread = $self->{laststate}->{logoffset};
      }
      while ($logfile->{offset} < $self->{laststate}->{logoffset}) {
        $self->trace("i start at offset %u", $logfile->{offset});
        my $bytes = $logfile->{fh}->sysread($buf, $needtoread);
        if (! defined $bytes) {
          $self->trace("read error at position %u", $logfile->{offset});
          last;
        } elsif ($bytes == 0) {
          # this should not happen, but at least it is an exit 
          # from an endless loop.
          $self->trace("i read %d bytes. looks like EOF at position %u",
              $bytes, $logfile->{offset});
          last;
        } else {
          $self->trace("i read %d bytes", $bytes);
          $logfile->{offset} += $bytes;
          if (($self->{laststate}->{logoffset} - $logfile->{offset}) >
              $self->{max_readsize}) {
            $needtoread = $self->{max_readsize};
            $self->trace("i cannot sysread %u bytes. continue with %u bytes",
                $self->{laststate}->{logoffset} - $logfile->{offset},
                $needtoread);
          } else {
            $needtoread = $self->{laststate}->{logoffset} - $logfile->{offset};
            $self->trace("i will sysread %u bytes.", $needtoread);
          }
        }
      }
      $self->trace("fake seek positioned at offset %u", $logfile->{offset});
    }
    while (my $line = $logfile->{fh}->getline()) {
      my $filteredout = 0;
      $self->{linesread}++;
      if (! $logfile->{seekable}) { $logfile->{offset} += length($line) }
      if ($self->{options}->{encoding}) {
        # i am sure this is completely unreliable
        $line = Encode::encode("ascii", 
            Encode::decode($self->{options}->{encoding}, $line));
        # the input stream is somewhat binary, so chomp doesn't know
        # it neads to remove \r\n on windows.
        $line =~ s/$1/\n/g if $line =~ /(\r\n?|\n\r?)/;
      }
      chomp($line);
      #
      #  If for example the prefilter option was set, check if the line 
      #  needs to be further examined. Only lines which match the needed filter
      #  can pass.
      #
      if ($needfilter) {
        foreach my $filter (@{$self->{preliminaryfilter}->{NEED}}) {
          if ($line !~ /$filter/) {
            $self->trace(sprintf "no need for %s", $line);
            $filteredout = 1;
            last;
          }
        }
      }
      #
      #  Skip lines with blacklist patterns
      #
      if ($skipfilter) {
        foreach my $filter (@{$self->{preliminaryfilter}->{SKIP}}) {
          if ($line =~ /$filter/) {
            $self->trace(sprintf "skip unwanted %s", $line);
            $self->trace(sprintf "because matching %s", $filter);
            $filteredout = 1;
            last;
          }
        }        
      }
      next if $filteredout;
      $self->{linenumber}++;
      $self->update_context(0, $line); # store this line as before
      my $matches = {};
      foreach my $nagioslevel (qw(CRITICAL WARNING UNKNOWN)) {
        my $level = $nagioslevel; # because it needs to be modified
        my $outplayed = 0;
        $matches->{$level} = [];
        foreach my $exception (@{$self->{exceptions}->{$level}}) {
          if ($line =~ /$exception/) {
            $self->trace("exception %s found. aborting.", $exception);
            $outplayed = 1;
            last;
          }
        }
        next if $outplayed;
        my $patcnt = -1;
        #foreach my $pattern (@{$self->{patterns}->{$level}}) {          
        #  $patcnt++;
        #  printf STDERR "-->%s\n<<<%s\n", $line, $pattern;
        #  if ($line =~ /$pattern/) {
        #    push(@{$matches->{$level}}, $patcnt);
        #  }
        #}
        foreach my $patternfunc (@{$self->{patternfuncs}->{$level}}) {
          $patcnt++;
          if (&${patternfunc}($line)) {
            push(@{$matches->{$level}}, $patcnt);
          }
        }
      }
      # now we have a structure with all the matches for this line
      # new option preferredlevel=critical
      if ($self->{options}->{preferredlevel}) {
        my $preferredlevel = uc $self->{options}->{preferredlevel};
        if (scalar(@{$matches->{$preferredlevel}}) > 0) {
          # es gibt z.b. einen criticaltreffer und critical ist preferred
          # d.h. alle anderen level fliegen raus
          foreach my $level (qw(CRITICAL WARNING UNKNOWN)) {
            $matches->{$level} = [] unless $level eq $preferredlevel;
          }
        }
        
      }
      foreach my $nagioslevel (qw(CRITICAL WARNING UNKNOWN)) {
        my $level = $nagioslevel; # because it needs to be modified
        foreach my $patcnt (@{$matches->{$level}}) {
          my $pattern = @{$self->{patterns}->{$level}}[$patcnt];

            $self->trace("MATCH %s %s with %s", $level, $pattern, $line);
            if ($self->{threshold}->{$level}) {
              if ($self->{thresholdcnt}->{$level} < 
                  $self->{threshold}->{$level}) {
                $self->trace("skip match and the next %d",
                    $self->{threshold}->{$level} - 
                    $self->{thresholdcnt}->{$level});
                $self->{thresholdcnt}->{$level}++;
                next;
              } else {
                $self->{thresholdcnt}->{$level} = 0;
              }
            }
            if ($self->{tivoli}->{object}) {
              $self->{tivoli}->{match} = 
                  $self->{tivoli}->{object}->match($line);
              $self->{privatestate}->{tivolimatch} = $self->{tivoli}->{match};
              $level = (qw(OK WARNING CRITICAL UNKNOWN))[$self->{tivoli}->{match}->{exit_code}];
              next if $self->{tivoli}->{match}->{format_name} eq 'NO MATCHING RULE';
              $line = $self->{tivoli}->{match}->{subject};
            } else {
              $self->{privatestate}->{matchingpattern} = $pattern;
            }
            if ($self->{options}->{script}) {
              $self->{macros}->{CL_SERVICESTATE} = $level;
              $self->{macros}->{CL_SERVICESTATEID} = $ERRORS{$level};
              $self->{macros}->{CL_SERVICEOUTPUT} = $line;
              $self->{macros}->{CL_PATTERN_PATTERN} = $pattern;
              $self->{macros}->{CL_PATTERN_NUMBER} = $patcnt;
              if (exists $self->{patternkeys}->{$level}->{$pattern} &&
                  defined $self->{patternkeys}->{$level}->{$pattern}) {
                $self->{macros}->{CL_PATTERN_KEY} = 
                    $self->{patternkeys}->{$level}->{$pattern}
              } else {
                $self->{macros}->{CL_PATTERN_KEY} = "unknown_pattern";
              }
              my ($actionsuccess, $actionrc, $actionoutput) =
                  $self->action($self->{script}, $self->{scriptparams},
                  $self->{scriptstdin}, $self->{scriptdelay},
                  $self->{options}->{smartscript}, $self->{privatestate});
              if (! $actionsuccess) {
                # note the script failure. multiple failures will generate
                # one single event in the end.
                $actionfailed = 1;
                $self->addevent($level, $line);
              } elsif ($self->{options}->{supersmartscript}) {
                # completely replace the matched line with the script output
                $self->addevent($actionrc, $actionoutput);
              } elsif ($self->{options}->{smartscript}) {
                # both matched line and script output are events
                $self->addevent($level, $line);
                $self->addevent($actionrc, $actionoutput);
              } else {
                # dumb scripts generate no events. only the matched line.
                $self->addevent($level, $line);
              }
            } else {
              $self->addevent($level, $line);
            }
            if ($self->{tivoli}->{object}) {
              delete $self->{privatestate}->{tivolimatch};
            }
          #}
        }
        #  count patterns which raise an alert only if they were not found.
        my $patcnt = -1;
        foreach my $pattern (@{$self->{negpatterns}->{$level}}) {
          $patcnt++;
          if ($line =~ /$pattern/) {
            $self->{negpatterncnt}->{$level}->[$patcnt]++;
            $self->trace("negative pattern %s found.", $pattern);
          }
        }
      }
      # maybe a okpattern wipes out the history
      foreach my $pattern (@{$self->{patterns}->{OK}}) {          
        if ($line =~ /$pattern/) {
          $self->trace("remedy pattern %s wipes out previous errors",
              $pattern);
          $self->{options}->{sticky}++ if $self->{options}->{sticky};
          # such a remedypattern neutralizes previous error
          $self->{matchlines}->{WARNING} = [];
          $self->{matchlines}->{CRITICAL} = [];
          $self->{matchlines}->{UNKNOWN} = [];
          last;
        }
      }   
    }
    #
    #  if there are more files to come, start searching at the beginning
    #  of each file.
    #  only the first (oldest) file will be positioned at an offset.
    #
    $self->{laststate}->{logoffset} = 0;
    $self->{newstate}->{logoffset} = $logfile->{seekable} ?
        $logfile->{fh}->tell() : $logfile->{offset};
    $self->{newstate}->{logtime} = (stat $logfile->{fh})[9] if $logfile->{statable};
    $self->{newstate}->{devino} = $self->getfilefingerprint($logfile->{fh});
    $self->trace("stopped reading at position %u",
        $self->{newstate}->{logoffset});
  }
  #
  #  if patterns beginning with ! were not found, treat this as an alert.
  #
  if ($self->{hasinversepat}) {
    foreach my $level (qw(CRITICAL WARNING)) {
      my $patcnt = -1;
      foreach my $pattern (@{$self->{negpatterns}->{$level}}) {
        $patcnt++;
        if ($self->{negpatterncnt}->{$level}->[$patcnt] == 0) {
          if ($self->{options}->{script}) {
            $self->{macros}->{CL_SERVICESTATEID} = $ERRORS{$level};
            $self->{macros}->{CL_SERVICEOUTPUT} = sprintf("MISSING: %s", $pattern);
            $self->{macros}->{CL_PATTERN_NUMBER} = $patcnt;
            my ($actionsuccess, $actionrc, $actionoutput) =
                $self->action($self->{script}, $self->{scriptparams},
                $self->{scriptstdin}, $self->{scriptdelay},
                $self->{options}->{smartscript}, $self->{privatestate});
            if (! $actionsuccess) {
              $actionfailed = 1;
              $self->addevent($level, sprintf("MISSING: %s", $pattern));
            } elsif ($self->{options}->{supersmartscript}) {
              $self->addevent($actionrc, $actionoutput);
            } elsif ($self->{options}->{smartscript}) {
              $self->addevent($level, sprintf("MISSING: %s", $pattern));
              $self->addevent($actionrc, $actionoutput);
            } else {
              $self->addevent($level, sprintf("MISSING: %s", $pattern));
            }
          } else {
            $self->addevent($level, sprintf("MISSING: %s", $pattern));
          }
        }
      }
    }
    #
    #  no files were examined, so no positioning took place. 
    #  keep the old status.
    #
    if (scalar @{$self->{relevantfiles}} == 0) {
      $self->{newstate}->{logoffset} = $self->{laststate}->{logoffset};
      $self->{newstate}->{logtime} = $self->{laststate}->{logtime};
      $self->{newstate}->{devino} = $self->{laststate}->{devino};
    }
  }
  #
  #  now the heavy work is done. logfiles were searched and matching lines
  #  were found and noted.
  #  close the open file handles and store the current position in a seekfile.
  #
  foreach my $logfile (@{$self->{relevantfiles}}) {
    $logfile->{fh}->close();
  }
  if ((scalar @{$self->{relevantfiles}} > 0) && ($self->{logfile} ne
      @{$self->{relevantfiles}}[$#{$self->{relevantfiles}}]->{filename})) {
    #
    #  only rotated files were examined and a new logfile was not created yet.
    #  next time we hopefully will have a new logfile, so start at position 0.
    #  set the lastlogtime to now, and don't care no longer for the past.
    #
    $self->trace("rotated logfiles examined but no current logfile found");
    $self->{newstate}->{logoffset} = 0;
    $self->{newstate}->{logtime} = time;
  }
  if ($actionfailed) {
    $self->{options}->{count} = 1;
    push(@{$self->{matchlines}->{WARNING}},
        sprintf "could not execute %s", $self->{script});
  }
}

sub addfilter {
  my $self = shift;
  my $need = shift;
  my $pattern = shift;
  if ($need) {
    push(@{$self->{preliminaryfilter}->{NEED}}, $pattern);  
  } else {
    push(@{$self->{preliminaryfilter}->{SKIP}}, $pattern);     
  }
}

sub searchresult {
  my $self = shift;
  if (scalar @{$self->{matchlines}->{CRITICAL}}) {
    $self->{newstate}->{servicestateid} = 2;
    $self->{newstate}->{serviceoutput} = 
        ${$self->{matchlines}->{CRITICAL}}[$#{$self->{matchlines}->{CRITICAL}}];
  } elsif (scalar @{$self->{matchlines}->{WARNING}}) {
    $self->{newstate}->{servicestateid} = 1;
    $self->{newstate}->{serviceoutput} = 
        ${$self->{matchlines}->{WARNING}}[$#{$self->{matchlines}->{WARNING}}];
  } elsif (scalar @{$self->{matchlines}->{UNKNOWN}}) {
    $self->{newstate}->{servicestateid} = 3;
    $self->{newstate}->{serviceoutput} = 
        ${$self->{matchlines}->{UNKNOWN}}[$#{$self->{matchlines}->{UNKNOWN}}];
  } else {
    $self->{newstate}->{servicestateid} = 0;
    $self->{newstate}->{serviceoutput} = "";
  }
  if ($self->{option}->{sticky} && $self->get_option('report') ne 'short') {
    # damit long/html output erhalten bleibt und nicht nur der letzte treffer
    $self->{newstate}->{matchlines} = $self->{matchlines};
  }
}

sub reset {
  my $self = shift;
  $self->{matchlines} = { OK => [], WARNING => [], CRITICAL => [], UNKNOWN => [] };
  $self->{lastmsg} = { OK => "", WARNING => "", CRITICAL => "", UNKNOWN => "" };
  $self->{negpatterncnt} = { OK => [], WARNING => [], CRITICAL => [], UNKNOWN => [] };
  $self->{thresholdcnt} = { OK => 0, WARNING => 0, CRITICAL => 0, UNKNOWN => 0 };
  #$self->{preliminaryfilter} = { SKIP => [], NEED => [] };
  $self->{perfdata} = "";
  foreach my $level (qw(CRITICAL WARNING UNKNOWN)) {
    foreach my $pat (@{$self->{negpatterns}->{$level}}) {
      push(@{$self->{negpatterncnt}->{$level}}, 0);
    }
  }
  if (exists $self->{template} && exists $self->{dynamictag}) {
    $self->{macros}->{CL_TAG} = $self->{dynamictag};
    $self->{macros}->{CL_TEMPLATE} = $self->{template};
  } else {
    #$self->resolve_macros(\$self->{tag});
    $self->{macros}->{CL_TAG} = $self->{tag};
  }
  delete $self->{lastlogoffset};
  delete $self->{lastlogtime};
  delete $self->{lastlogoffset};
  delete $self->{lastlogfile};
  delete $self->{newlogoffset};
  delete $self->{newlogtime};
  delete $self->{newdevino};
  delete $self->{newlogfile};
  $self->{relevantfiles} = [];
  $self->{logrotated} = 0;
  $self->{logmodified} = 0;
  $self->{linesread} = 0;
  $self->{relevantfiles} = [];
  if (exists $self->{options}->{sticky}) {
    $self->{options}->{sticky} = 1 if ($self->{options}->{sticky} > 1);
  }
  return $self;
}


package Nagios::CheckLogfiles::Search::Simple;

use strict;
use Exporter;
use File::Basename;
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

sub analyze_situation {
  my $self = shift;
  $self->{logrotated} = 0;
  $self->{logmodified} = 0;
  
  if (! -e $self->{logfile}) {
    #
    #  the logfile was deleted and no new events occurred since.
    #  todo: no collection, but reset counters, incl. timestamp
    #  with the modified flag we force a call to collectfiles where 
    #  [no]logfilenocry will be considered.
    $self->{logmodified} = 1;
    $self->trace(sprintf "there is no logfile %s at this moment",
        $self->{logfile});
    $self->{laststate}->{logoffset} = 0;
  } elsif (! $self->getfileisreadable($self->{logfile})) {
    $self->{logmodified} = 1;
    $self->trace(sprintf "first noticed that logfile %s is unreadable",
        $self->{logfile});
  } elsif ($self->{laststate}->{devino} ne 
        $self->getfilefingerprint($self->{logfile})) {
    # the inode changed (! the old inode could have been reused)
    # or maybe this is the first time this logfile was seen
    $self->trace(sprintf "this is not the same logfile %s %s != %s",
        $self->{logfile}, $self->{laststate}->{devino},
        $self->getfilefingerprint($self->{logfile}));
    $self->{logmodified} = 1;
    $self->{laststate}->{logoffset} = 0;
    $self->trace(sprintf "reset to offset 0");
  } elsif ($self->getfilesize($self->{logfile}) > 
        $self->{laststate}->{logoffset}) {
    #
    #  the logfile grew.
    #  this is the normal behaviour. in rare cases the logfile could have been
    #  rotated/recreated and grown very fast.
    $self->trace(sprintf "the logfile grew to %d",
        $self->getfilesize($self->{logfile}));
    if ($self->{likeavirgin}) {
      # if the logfile grew because we initialized the plugin with an offset of 0, position
      # at the end of the file and skip this search. otherwise lots of outdated messages could
      # match and raise alerts.
      if ($self->{options}->{allyoucaneat}) {
        $self->trace("allyoucaneat the virgin");
        $self->{laststate}->{logoffset} = 0;
        $self->{logmodified} = 1; # normally, virgins are not scanned. force it.
      } else {
        $self->{laststate}->{logoffset} = $self->getfilesize($self->{logfile});
      }
    } else {
      $self->{logmodified} = 1;
      # this is only relevant if
      # 1.a new logfile is created using the same inode as the deleted logfile
      # 2.the new logfile grew beyond the size of the last logfile before check_logfile ran
      #if ($self->{firstline} ne $self->{laststate}->{firstline}) {
      #  $self->trace(sprintf "a new logfile grew beyond the end of the last logfile");
      #  $self->{laststate}->{logoffset} = 0;
      #}
    }
  } elsif ($self->getfilesize($self->{logfile}) == 0) {
    #
    #  the logfile was either truncated or deleted and touched.
    #  nothing to do except reset the position
    $self->{logmodified} = 0;
    $self->{laststate}->{logoffset} = 0;  
    $self->{laststate}->{logtime} = (stat $self->{logfile})[9];
    $self->trace("logfile has been truncated");
  } elsif ($self->getfilesize($self->{logfile}) < 
        $self->{laststate}->{logoffset}) {
    #
    #  logfile shrunk. either it was truncated or it was
    #  rotated and a new logfile was created.
    $self->trace(sprintf "the logfile shrunk from %d to %d",
        $self->{laststate}->{logoffset}, $self->getfilesize($self->{logfile}));
    $self->{logmodified} = 1;
    $self->{laststate}->{logoffset} = 0;
    $self->trace(sprintf "reset to offset 0");
  } elsif ($self->getfilesize($self->{logfile}) == 
        $self->{laststate}->{logoffset}) {
    $self->trace(sprintf "the logfile did not change");
  } else {
    $self->trace("I HAVE NO IDEA WHAT HAPPENED");
  }
  return $self;
}

sub collectfiles {
  my $self = shift;
  my @rotatedfiles = ();
  if ($self->{logmodified}) {
    my $fh = new IO::File;
    # cygwin lets you open files even after chmodding them to 0000, so double check with -r
    if ($self->getfileisreadable($self->{logfile})) {
      $fh->open($self->{logfile}, "r");
      $self->trace("opened logfile %s", $self->{logfile});
      push(@rotatedfiles, 
          { filename => $self->{logfile}, fh => $fh, seekable => 1, statable => 1 });
      $self->trace("logfile %s (modified %s / accessed %s / inode %d / inode changed %s)",
          $self->{logfile},
          scalar localtime((stat $self->{logfile})[9]),
          scalar localtime((stat $self->{logfile})[8]),
          (stat $self->{logfile})[1],
          scalar localtime((stat $self->{logfile})[10]));
    } else {
      if (-e $self->{logfile}) {
        #  permission problem
        $self->trace("insufficient permissions to open logfile %s",
            $self->{logfile});
        $self->addevent($self->get_option('logfileerror'),
            sprintf "insufficient permissions to open logfile %s",
            $self->{logfile});
      } else {
        if ($self->{options}->{logfilenocry}) {
          # logfiles which are not rotated but deleted and re-created may be missing
          #  maybe a rotation situation, a typo in the configfile,...
          $self->trace("could not find logfile %s", $self->{logfile});
          $self->addevent('UNKNOWN', sprintf "could not find logfile %s",
              $self->{logfile});
        } else {
          # dont care.
          $self->trace("could not find logfile %s, but that's ok",
              $self->{logfile});  
        }
      }
    }
  }
  $self->trace(sprintf "relevant files: %s", join(", ", map { basename $_->{filename} } @rotatedfiles));
  $self->{relevantfiles} = \@rotatedfiles;
}


package Nagios::CheckLogfiles::Search::Rotating;

use strict;
use Exporter;
use File::Basename;
use vars qw(@ISA);

use constant OK => 0;
use constant WARNING => 1;
use constant CRITICAL => 2;
use constant UNKNOWN => 3;

@ISA = qw(Nagios::CheckLogfiles::Search);

sub new {
  my $self = bless {}, shift;
  # sollte mal raus, da gibts kein sub dazu.
  # hier kommt eh keiner her, weil eins hoeher geblesst wird
  # $self->rotationpattern();
  return $self->init(shift);
}
 
sub analyze_situation {
  my $self = shift;
  $self->{logrotated} = 0;
  $self->{logmodified} = 0;
  if (! $self->{NH_detection}) {
    if (! -e $self->{logfile}) {
      #
      #  if no logfile exists, then probably it was rotated and no new logs
      #  were written since.
      #  find files which were modified after $lasttime. the most recent one
      #  is probably the former logfile. position at $lastoffset. 
      #  if this configurations does not care for rotations, there is nothing
      #  we can do here.
      #
      $self->{logrotated} = 1;
      $self->{logmodified} = 1;
      $self->trace(sprintf "there is no logfile %s at this moment",
          $self->{logfile});
    } elsif ($self->{laststate}->{devino} ne
          $self->getfilefingerprint($self->{logfile})) {
      # the inode changed (! the old inode could be reused)
      $self->trace(sprintf "this is not the same logfile %s != %s",
          $self->{laststate}->{devino},
          $self->getfilefingerprint($self->{logfile}));
      $self->{logrotated} = 1;
      $self->{logmodified} = 1;
    } elsif ($self->getfilesize($self->{logfile}) > 
          $self->{laststate}->{logoffset}) {
      #
      #  the logfile grew.
      #  this is the normal behaviour. in rare cases the logfile could have been
      #  rotated/recreated and grown very fast.
      $self->trace(sprintf "the logfile grew to %d",
          $self->getfilesize($self->{logfile}));
      if ($self->{likeavirgin}) {
        # if the logfile grew because we initialized the plugin with an offset of 0, position
        # at the end of the file and skip this search. otherwise lots of outdated messages could
        # match and raise alerts.
        $self->{laststate}->{logoffset} = $self->getfilesize($self->{logfile});
      } else {
        $self->{logmodified} = 1;
      }
    } elsif ($self->getfilesize($self->{logfile}) == 0) {
      #
      #  the logfile was either truncated or deleted and touched.
      #  nothing to do except reset the position
      $self->{logrotated} = 1;  
      $self->{laststate}->{logtime} = (stat $self->{logfile})[9];
    } elsif ($self->getfilesize($self->{logfile}) < 
          $self->{laststate}->{logoffset}) {
      #
      #  logfile shrunk. either it was truncated or it was
      #  rotated and a new logfile was created.
      $self->trace(sprintf "the logfile shrunk from %d to %d",
          $self->{laststate}->{logoffset}, $self->getfilesize($self->{logfile}));
      $self->{logmodified} = 1;
      $self->{logrotated} = 1;
    } elsif ($self->getfilesize($self->{logfile}) == 
          $self->{laststate}->{logoffset}) {
      $self->trace(sprintf "the logfile did not change");
    } else {
      $self->trace("I HAVE NO IDEA WHAT HAPPENED");
    }
    return $self;
  } else {
    # Nigel Harnimans mtime-based algorithm
    my $filetime = (stat $self->{logfile})[9];
    my $lastfiletime = $self->{laststate}->{logtime};
  
    if (! -e $self->{logfile}) {
      #
      #  if no logfile exists, then probably it was rotated and no new logs
      #  were written since.
      #  find files which were modified after $lasttime. the most recent one
      #  is probably the former logfile. position at $lastoffset.
      #  if this configurations does not care for rotations, there is nothing
      #  we can do here.
      #
      $self->{logrotated} = 1;
      $self->{logmodified} = 1;
      $self->trace(sprintf "there is no logfile %s at this moment",
          $self->{logfile});
    } elsif ($self->{laststate}->{devino} ne
          $self->getfilefingerprint($self->{logfile})) {
      # the inode changed (! the old inode could be reused)
      $self->trace(sprintf "this is not the same logfile %s != %s",
          $self->{laststate}->{devino},
          $self->getfilefingerprint($self->{logfile}));
      $self->{logrotated} = 1;
      $self->{logmodified} = 1;
  
      # Ok, we need to make some changes here to handle a situation where the
      # inode is not changed on file rotation (since the writing app need
      # continuity)
      # 1)    The last modified time is the same as that of the previously scanned 
      #       log file. Therefore it is the same file. No rotation or modification
      # 2)    The last modified time is different, and the file is zero bytes:
      #       - Modified = false
      #       - Rotated = true
      # 3)    The last modified time is different, and the file is not zero bytes
      #       and is less than previous:
      #       - Modified = true
      #       - Rotated = true
      # 4)    The last modified time is different, and the file is not zero bytes
      #       and is more than previous:
      #       - Modified = true
      #       - Rotated = true (we can't actually tell, so need to play safe)
    } elsif ($filetime == $lastfiletime) {
      $self->trace(sprintf "Log file has the same modified time: %s ",
          scalar localtime($filetime));
      $self->{laststate}->{logtime} = $filetime;
    } elsif ($filetime != $lastfiletime) {
      $self->trace(sprintf "Log file modified time: %s, last modified time: %s",
          scalar localtime($filetime),
          scalar localtime($lastfiletime));
      if ($self->getfilesize($self->{logfile}) == 0) {
        $self->trace(sprintf "Log file is zero bytes");
        $self->{logrotated} = 1;
      } else {
        $self->trace(sprintf "Log file is not zero bytes");
        $self->{logrotated} = 1;
        $self->{logmodified} = 1;
      }
    } else {
      $self->trace("I HAVE NO IDEA WHAT HAPPENED");
    }
    $self->trace(sprintf "Log offset: %i",
        $self->{laststate}->{logoffset});
    return $self;
  }
}

 
sub collectfiles {
  my $self = shift;
  my @rotatedfiles = ();
  if ($self->{logrotated} && $self->{rotation}) {
    $self->trace("looking for rotated files in %s with pattern %s",
        $self->{archivedir}, $self->{filenamepattern});


    if ($self->get_option('archivedirregexp')) {
      my $volume = undef;
      my @catdirs = ();
      my @dirs = split(/\//, $self->{archivedir});
      foreach my $i (1..(scalar(@dirs) - $self->get_option('archivedirregexp'))) {
          push(@catdirs, shift @dirs);
      }
      my $searchdir = join('/', @catdirs);
      File::Find::find(sub {
        if (/^$self->{filenamepattern}/ && -f $_) {
          push(@rotatedfiles, $File::Find::name);
        }
      }, $searchdir);
    } else {
      opendir(DIR, $self->{archivedir});
      @rotatedfiles = map {
          sprintf "%s/%s", $self->{archivedir}, $_;
      } grep /^$self->{filenamepattern}/, readdir(DIR);
      closedir(DIR);
    }


    #opendir(DIR, $self->{archivedir});
    #@rotatedfiles = map { 
    #    sprintf "%s/%s", $self->{archivedir}, $_; 
    #} grep /^$self->{filenamepattern}/, readdir(DIR);
    #closedir(DIR);
    
#    opendir(DIR, $self->{archivedir});
    # read the filenames from DIR, match the filenamepattern, check the file age
    # open the file and return the handle
    # sort the handles by modification time
    #@rotatedfiles = sort { (stat $a->{fh})[9] <=> (stat $b->{fh})[9] } map {
    @rotatedfiles = sort { $a->{modtime} <=> $b->{modtime} } map {
      #if (/^$self->{filenamepattern}/) {
        #my $archive = sprintf "%s/%s", $self->{archivedir}, $_;
        my $archive = $_;
        $self->trace("archive %s matches (modified %s / accessed %s / inode %d / inode changed %s)", $archive,
            scalar localtime((stat $archive)[9]),
            scalar localtime((stat $archive)[8]),
            (stat $archive)[1],
            scalar localtime((stat $archive)[10]));
        if ((stat $archive)[9] >=
            $self->{laststate}->{logtime}) {
          $self->trace("archive %s was modified after %s", $archive,
              scalar localtime($self->{laststate}->{logtime}));
          my $fh = new IO::File;
          if (/.*\.gz\s*$/) {
            $self->trace("uncompressing %s with gzip -dc < %s|", $archive, 
                $archive);
            if ($fh->open('gzip -dc < '.$archive.'|')) {
              ({ filename => $archive,
                  fh => $fh, seekable => 0, statable => 0,
                  modtime => (stat $archive)[9],
                  fingerprint => $self->getfilefingerprint($archive).':'.$self->getfilesize($archive) });
            } else {
              $self->trace("archive %s cannot be opened with gzip", $archive);
              ();
            }
          } elsif (/.*\.bz2\s*$/) {
            $self->trace("uncompressing %s with bzip2 -d < %s|", $archive, 
                $archive);
            if ($fh->open('bzip2 -d < '.$archive.'|')) {
              ({ filename => $archive,
                  fh => $fh, seekable => 0, statable => 0,
                  modtime => (stat $archive)[9],
                  fingerprint => $self->getfilefingerprint($archive).':'.$self->getfilesize($archive) });
            } else {
              $self->trace("archive %s cannot be opened with bzip2", $archive);
              ();
            }
          } else {
            if ($fh->open($archive, "r")) {
              ({ filename => $archive,
                  fh => $fh, seekable => 1, statable => 1,
                  size => $self->getfilesize($fh),
                  modtime => (stat $archive)[9],
                  fingerprint => $self->getfilefingerprint($archive).':'.$self->getfilesize($archive) });
            } else {
              $self->trace("archive %s cannot be opened", $archive);
              ();
            }
          }
        } else {
          ();
        }
      #} else {
      #  ();
      #}
    } @rotatedfiles;
#    } readdir(DIR);
#    closedir(DIR);
    if (scalar(@rotatedfiles) == 0) {
      #
      #  although a logfile rotation was detected, no archived files were found.
      #  start seeking at position 0.
      #
      if (! $self->{NH_detection}) {
        $self->{laststate}->{logoffset} = 0;
      } else {
        # NH Commented this out, as we may find no rotated files,
        # in which case we need to use the current file offset again
      }
      $self->trace("although a logfile rotation was detected, no archived files were found");
    }
  }
  if ($self->{logmodified}) {
    my $fh = new IO::File;
    # cygwin lets you open files even after chmodding them to 0000, so double check with -r
    if ($self->getfileisreadable($self->{logfile})) {
      $fh->open($self->{logfile}, "r");
      $self->trace("opened logfile %s", $self->{logfile});
      push(@rotatedfiles, 
          { filename => $self->{logfile}, fh => $fh, seekable => 1, statable => 1,
          size => $self->getfilesize($self->{logfile}),
          fingerprint => $self->getfilefingerprint($self->{logfile}).':'.$self->getfilesize($self->{logfile}) });
      $self->trace("logfile %s (modified %s / accessed %s / inode %d / inode changed %s)",
          $self->{logfile},
          scalar localtime((stat $self->{logfile})[9]),
          scalar localtime((stat $self->{logfile})[8]),
          (stat $self->{logfile})[1],
          scalar localtime((stat $self->{logfile})[10]));
    } else {
      if (-e $self->{logfile}) {
        #  permission problem
        $self->trace("insufficient permissions to open logfile %s",
            $self->{logfile});
        $self->addevent($self->get_option('logfileerror'),
            sprintf "insufficient permissions to open logfile %s", 
            $self->{logfile});
      } else {
        if ($self->{options}->{logfilenocry}) {
          # logfiles which are not rotated but deleted and re-created may be missing
          #  maybe a rotation situation, a typo in the configfile,...
          $self->trace("could not find logfile %s", $self->{logfile});
          $self->addevent('UNKNOWN', sprintf "could not find logfile %s",
              $self->{logfile});
        } else {
          # dont care.
          $self->trace("could not find logfile %s, but that's ok", $self->{logfile});
        }
      }
    }
  }
  # now we have an array of structures each pointing to a file
  # which has been rotated since the last scan plus the current logfile.
  # the array members are sorted by modification time of the files.
  # now duplicate entries are removed. in one scenario the current logfile is
  # a symbolic link to a file which uses the same naming schema as the rotated
  # logfiles.
  $self->trace(sprintf "first relevant files: %s", join(", ", map { basename $_->{filename} } @rotatedfiles));
  my %seen = ();
  @rotatedfiles = reverse map {
    $self->trace("%s has fingerprint %s", $_->{filename}, $_->{fingerprint});
    # because of the windows dummy devino 0:0, we need to add the size
    if (exists $seen{$_->{fingerprint}}) {
      $self->trace("skipping %s (identical to %s)", 
          $_->{filename}, $seen{$_->{fingerprint}});
      ();
    } else {
      $seen{$_->{fingerprint}} = $_->{filename};
      $_;
    }
  } reverse @rotatedfiles;
  # cleanup again. this is for rotating::uniform, where the current logfile is
  # analyzed twice. with a fast-growing logfile it may happen that we find
  # the current logfile with two different fingerprints (dev:inode:size) here
  %seen = ();
  @rotatedfiles = reverse map {
    if (exists $seen{$_->{filename}}) {
      $self->trace("skipping duplicate %s (was growing during analysis)",
          $_->{filename});
      ();
    } else {
      $seen{$_->{filename}} = 1;
      $_;  
    }    
  } reverse @rotatedfiles;
  if (0 && (scalar(@rotatedfiles) == 1) &&
      ($rotatedfiles[0]->{filename} eq $self->{logfile}) &&
      ! $self->get_option('randominode')) {
    # somehow rotated (devino has changed) but there are no rotated files
    # maybe logfile was rotated=deleted and recreated
    # a very special case which i found when i wrote 087randominode.t
    $self->{laststate}->{logoffset} = 0;
  } elsif (@rotatedfiles && (exists $rotatedfiles[0]->{size}) && 
      ($rotatedfiles[0]->{size} < $self->{laststate}->{logoffset})) {
    $self->trace(sprintf "file %s is too short (%d < %d). this should not happen. reset",
        $rotatedfiles[0]->{filename},
        $rotatedfiles[0]->{size}, $self->{laststate}->{logoffset});
    if ($self->{NH_detection}) {
      # NH In this case, we have replaced the files, so set to beginning
      $self->{laststate}->{logoffset} = 0;
    } else {
      $self->{laststate}->{logoffset} = $rotatedfiles[0]->{size};
    }
  }
  $self->trace(sprintf "relevant files: %s", join(", ", map { basename $_->{filename} } @rotatedfiles));
  $self->{relevantfiles} = \@rotatedfiles;
}

sub prepare {
  my $self = shift;
  if ("LOGLOGDATE8GZ" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf '^%s[\.\-]{0,1}[0-9]{8}\.gz$',
        $self->{logbasename};
  } elsif ("LOGLOGDATE8BZ2" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf '^%s[\.\-]{0,1}[0-9]{8}\.bz2$',
        $self->{logbasename};
  } elsif ("LOGLOG0LOG1GZ" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf '^%s\.((0)|([1-9]+\.gz))$',
        $self->{logbasename};
  } elsif ("LOGLOG0GZLOG1GZ" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf '^%s\.((0)|([1-9]+[0-9]*))\.gz$',
        $self->{logbasename};
  } elsif ("LOGLOG0BZ2LOG1BZ2" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf '^%s\.((0)|([1-9]+[0-9]*))\.bz2$',
        $self->{logbasename};
  } elsif ("LOGLOG0LOG1" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf '^%s\.((0)|([1-9]+[0-9]*))$',
        $self->{logbasename};
  } elsif ("SUSE" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf "%s.*[0-9]*.gz", $self->{logbasename};
  } elsif ("DEBIAN" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf "%s.0|%s.*[0-9]*.gz",
        $self->{logbasename}, $self->{logbasename};
  } elsif ("QMAIL" eq uc($self->{rotation})) {
    $self->{filenamepattern} = "\@.*";
  } elsif ("LOGROTATE" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf "%s.*[0-9]*.gz", $self->{logbasename};
  } elsif ("SOLARIS" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf "%s.*\\.[0-9]+", $self->{logbasename};
  } elsif ("HPUX" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf "OLD%s", $self->{logbasename};
  } elsif ("BMWHPUX" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf 'OLD%s|%s\\.[A-Z][0-9]+_[0-9]+\\.gz$',
        $self->{logbasename}, $self->{logbasename};
  } elsif ("EHL" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf '^%s_%s\.\d\d\d\d_\d+_\d+_\d+_\d+_\d+$',
        $self->{macros}->{CL_HOSTNAME}, $self->{logbasename};
  } elsif ("MOD_LOG_ROTATE" eq uc($self->{rotation})) {
    $self->{filenamepattern} = sprintf 'access\.log\.\d{10}';
    bless $self, "Nagios::CheckLogfiles::Search::Rotating::Uniform";
    $self->prepare();
  } else {
    $self->{filenamepattern} = $self->{rotation};
    $self->resolve_macros_in_pattern(\$self->{filenamepattern});
  }
  return $self;
}




package Nagios::CheckLogfiles::Search::Rotating::Uniform;

use strict;
use Exporter;
use File::Basename;
use File::Find;
use vars qw(@ISA);

use constant OK => 0;
use constant WARNING => 1;
use constant CRITICAL => 2;
use constant UNKNOWN => 3;

@ISA = qw(Nagios::CheckLogfiles::Search::Rotating);

sub new {
  my $self = bless {}, shift;
  return $self->init(shift);
}

sub prepare {
  my $self = shift;
  my $params = shift;
  my @matchingfiles = ();
  if (! $self->{filenamepattern}) {
    $self->{filenamepattern} = $self->{rotation};
    $self->resolve_macros_in_pattern(\$self->{filenamepattern});
  }
  # find newest rotatingpattern = logfile

  if ($self->get_option('archivedirregexp')) {
    my $volume = undef;
    my @catdirs = ();
    my @dirs = split(/\//, $self->{archivedir});
    foreach my $i (1..(scalar(@dirs) - $self->get_option('archivedirregexp'))) {
        push(@catdirs, shift @dirs);
    }
    my $searchdir = join('/', @catdirs);
    File::Find::find(sub {
      if (/^$self->{filenamepattern}/ && -f $_) {
        push(@matchingfiles, $File::Find::name);
      }
    }, $searchdir);
    @matchingfiles = sort { $a->{modtime} <=> $b->{modtime} } map {
        my $archive = $_;
       ({ filename => $archive, modtime => (stat $archive)[9]});
    } @matchingfiles;
  } else {
    opendir(DIR, $self->{archivedir});
    @matchingfiles = sort { $a->{modtime} <=> $b->{modtime} } map {
        my $archive = $_;
       ({ filename => $archive, modtime => (stat $archive)[9]});
    } map {
        sprintf "%s/%s", $self->{archivedir}, $_;
    } grep /^$self->{filenamepattern}/, readdir(DIR);
    closedir(DIR);
  }

  #opendir(DIR, $self->{archivedir});
  #@matchingfiles = sort { $a->{modtime} <=> $b->{modtime} } map {
  #    if (/^$self->{filenamepattern}/) {
  #      my $archive = sprintf "%s/%s", $self->{archivedir}, $_;
  #     ({ filename => $archive, modtime => (stat $archive)[9]});
  #    } else {
  #      ();
  #    }
  #} readdir(DIR);
  #closedir(DIR);
  if (@matchingfiles) {
    $self->{logfile} = $matchingfiles[-1]->{filename};
    $self->{macros}->{CL_LOGFILE} = $self->{logfile};
    $self->{privatestate}->{logfile} = $self->{logfile};
    $self->trace("the newest uniform logfile i found is %s", $self->{logfile});
  } else {
    $self->{logfile} = $self->{archivedir}.'/logfilenotfound';
    $self->trace("i found no uniform logfiles in %s", $self->{archivedir});
  }
  $self->construct_seekfile();
}

sub construct_seekfile {
  my $self = shift;
  # modify seekfilename so it can be found even if the logfile has changed
  $self->{logbasename} = basename($self->{logfile});
  if ($self->get_option('archivedirregexp')) {
    $self->{seekfilebase} = '/regexpuniformlogfile';
  } else {
    $self->{seekfilebase} = dirname($self->{logfile}).'/uniformlogfile';
  }
  $self->{seekfilebase} =~ s/\//_/g;
  $self->{seekfilebase} =~ s/\\/_/g;
  $self->{seekfilebase} =~ s/:/_/g;
  $self->{seekfilebase} =~ s/\s/_/g;
  $self->{seekfile} = sprintf "%s/%s.%s.%s", $self->{seekfilesdir},
      $self->{cfgbase}, $self->{seekfilebase},
      $self->{tag} eq "default" ? "seek" : $self->{tag};
  $self->{pre3seekfile} = sprintf "/tmp/%s.%s.%s",
      $self->{cfgbase}, $self->{seekfilebase},
      $self->{tag} eq "default" ? "seek" : $self->{tag};
  $self->{pre2seekfile} = sprintf "%s/%s.%s.%s", $self->{seekfilesdir},
      $self->{cfgbase}, $self->{logbasename},
      $self->{tag} eq "default" ? "seek" : $self->{tag};
  $self->trace("rewrote uniform seekfile to %s", $self->{seekfile});
  return $self;
}
 

package Nagios::CheckLogfiles::Search::Virtual;

use strict;
use Exporter;
use File::Basename;
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
    
sub loadstate {
  my $self = shift;
  $self->{laststate}->{logoffset} = 0;
}

sub savestate {
}

sub analyze_situation {
  my $self = shift;
  $self->{logmodified} = 1; 
}

sub collectfiles {
  my $self = shift;
  my @rotatedfiles = ();
  my $fh = new IO::File;
  if ($self->getfileisreadable($self->{logfile})) {
    $fh->open($self->{logfile}, "r");
    $self->trace("opened logfile %s", $self->{logfile});
    push(@rotatedfiles,
        { filename => $self->{logfile}, fh => $fh, seekable => 1, statable => 1 });
  } else {
    if (-e $self->{logfile}) {
      #  permission problem
        $self->trace("insufficient permissions to open logfile %s", 
            $self->{logfile});
        $self->addevent($self->get_option('logfileerror'),
            sprintf "insufficient permissions to open logfile %s",
            $self->{logfile});
    } else {
      if ($self->{options}->{logfilenocry}) {
        $self->trace("could not find logfile %s", $self->{logfile});
        $self->addevent('UNKNOWN', sprintf "could not find logfile %s",
            $self->{logfile});
      } else {
        # dont care.
        $self->trace("could not find logfile %s, but that's ok",
            $self->{logfile});
      }
    }
  }
  $self->{relevantfiles} = \@rotatedfiles;
}


package Nagios::CheckLogfiles::Search::Prescript;

use strict;
use Exporter;
use File::Basename;
use vars qw(@ISA);

@ISA = qw(Nagios::CheckLogfiles::Search);

sub new {
  my $self = bless {}, shift;
  return $self->init(shift);
}

sub init {
  my $self = shift;
  my $params = shift;
  $self->{tag} = "prescript";
  $self->{scriptpath} = $params->{scriptpath};
  $self->{macros} = $params->{macros};
  $self->{tracefile} = $params->{tracefile};
  $self->{cfgbase} = $params->{cfgbase};
  $self->{logbasename} = "prescript";
  $self->{script} = $params->{script};
  $self->{scriptparams} = $params->{scriptparams};
  $self->{scriptstdin} = $params->{scriptstdin};
  $self->{scriptdelay} = $params->{scriptdelay};   
  $self->default_options({ script => 0, protocol => 0, count => 1,
      smartscript => 0, supersmartscript => 0,
      report => 'short', seekfileerror => 'critical', logfileerror => 'critical' });
  $self->{matchlines} = { OK => [], WARNING => [], CRITICAL => [], UNKNOWN => [] };
  $self->{lastmsg} = { OK => "", WARNING => "", CRITICAL => "", UNKNOWN => "" };
  $self->{trace} = -e $self->{tracefile} ? 1 : 0;
  $self->refresh_options($params->{options});
  $self->{exitcode} = 0;
  $self->{macros}->{CL_LOGFILE} = $params->{cfgbase};
  $self->{macros}->{CL_TAG} = $self->{tag};
  $self->{macros}->{CL_SERVICESTATEID} = $ERRORS{OK};
  $self->{macros}->{CL_SERVICEOUTPUT} = "OK - starting up";
  $self->{macros}->{CL_PATTERN_NUMBER} = 0;
  return $self;
}

sub run {
  my $self = shift;
  $self->trace("call (%s) prescript %s",
      $self->{options}->{smartscript} ? "smart" : "dumb", $self->{script});
  my ($actionsuccess, $actionrc, $actionoutput) =
      $self->action($self->{script}, $self->{scriptparams},
      $self->{scriptstdin}, $self->{scriptdelay},
      $self->{options}->{smartscript}, $self->{privatestate});
  if (! $actionsuccess) {
    $self->{options}->{count} = 1;
    $self->{options}->{protocol} = 1;
    $self->addevent('WARNING',
        sprintf "cannot execute %s", $self->{script});
  } elsif ($self->{options}->{smartscript}) {
    if ($actionrc) {
      $actionoutput = "prescript" if ! $actionoutput;
      $self->addevent($actionrc, $actionoutput);
    }
  }
  $self->{exitcode} = $actionrc;
}


package Nagios::CheckLogfiles::Search::Postscript;

use strict;
use Exporter;
use File::Basename;
use vars qw(@ISA);

@ISA = qw(Nagios::CheckLogfiles::Search);

sub new {
  my $self = bless {}, shift;
  return $self->init(shift);
}

sub init {
  my $self = shift;
  my $params = shift;
  $self->{tag} = "postscript";
  $self->{scriptpath} = $params->{scriptpath};
  $self->{macros} = $params->{macros};
  $self->{tracefile} = $params->{tracefile};
  $self->{cfgbase} = $params->{cfgbase};
  $self->{logbasename} = "postscript";
  $self->{script} = $params->{script};
  $self->{scriptparams} = $params->{scriptparams};
  $self->{scriptstdin} = $params->{scriptstdin};
  $self->{scriptdelay} = $params->{scriptdelay};   
  $self->{privatestate} = $params->{privatestate};   
  $self->default_options({ script => 0, protocol => 0, count => 1,
      smartscript => 0, supersmartscript => 0,
      report => 'short', seekfileerror => 'critical', logfileerror => 'critical', });
  $self->{matchlines} = { OK => [], WARNING => [], CRITICAL => [], UNKNOWN => [] };
  $self->{lastmsg} = { OK => "", WARNING => "", CRITICAL => "", UNKNOWN => "" };
  $self->{trace} = -e $self->{tracefile} ? 1 : 0;
  $self->refresh_options($params->{options});
  $self->{exitcode} = 0;
  $self->{macros}->{CL_LOGFILE} = $params->{cfgbase};
  $self->{macros}->{CL_TAG} = $self->{tag};
  $self->{macros}->{CL_SERVICESTATEID} = 0; # will be set in SUPER::run()
  $self->{macros}->{CL_SERVICEOUTPUT} = ""; # will be set in SUPER::run()
  $self->{macros}->{CL_PATTERN_NUMBER} = 0;
  return $self;
}

sub run {
  my $self = shift;
  $self->trace("call postscript %s", $self->{script});
  my ($actionsuccess, $actionrc, $actionoutput) =
      $self->action($self->{script}, $self->{scriptparams},
      $self->{scriptstdin}, $self->{scriptdelay},
      $self->{options}->{smartscript}, $self->{privatestate});
  if (! $actionsuccess) {
    $self->{options}->{count} = 1;
    $self->{options}->{protocol} = 1;
    $self->addevent('WARNING',
        sprintf "cannot execute %s", $self->{script});
    $actionrc = 2;
  } elsif ($self->{options}->{smartscript}) {
    if ($actionrc || $self->{options}->{supersmartscript}) {
      # strings containing 0 must be treated like a true value
      #$actionoutput = "postscript" if ! $actionoutput;
      $actionoutput = "postscript"
          unless $actionoutput || $actionoutput =~ /0[0\.]*/;
      $self->addevent($actionrc, $actionoutput);
    }
  }
  $self->{exitcode} = $actionrc;
}

1;
