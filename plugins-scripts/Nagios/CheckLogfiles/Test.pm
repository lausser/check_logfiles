package Nagios::CheckLogfiles::Test;

use strict;
use Exporter;
use Nagios::CheckLogfiles;
use File::Basename;
use vars qw(@ISA);

use constant OK => 0;
use constant WARNING => 1;
use constant CRITICAL => 2;
use constant UNKNOWN => 3;

@ISA = qw(Nagios::CheckLogfiles);

sub new {
  my $class = shift;
  my $params = shift;
  my $self = $class->SUPER::new($params);
  foreach my $search (@{$self->{searches}}) {
  	# adds access to the test methods
  	no strict 'refs';
  	my $isa = ref($search).'::ISA';
  	push(@{$isa}, "Nagios::CheckLogfiles::Search::Test");
  }
  return bless $self, $class;
}

sub remove_windows_plugin {
  my $self = shift;
  system("mv ../plugins-scripts/check_logfiles.unix ../plugins-scripts/check_logfiles");
}

sub make_windows_plugin {
  my $self = shift;
  system("mv ../plugins-scripts/check_logfiles ../plugins-scripts/check_logfiles.unix");
  system("cd ..; perl winconfig.pl");
}

sub reset {
  my $self = shift;
  $self->{allerrors} = { OK => 0, WARNING => 0, CRITICAL => 0, UNKNOWN => 0 };
  $self->{matchlines} = { OK => [], WARNING => [], CRITICAL => [], UNKNOWN => [] };
  foreach my $level (qw(OK CRITICAL WARNING UNKNOWN)) {
    $self->{lastmsg}->{$level} = "";
  }  
  foreach my $search (@{$self->{searches}}) {	
    $search->reset();
  }
}

sub reset_run {
  my $self = shift;
  $self->reset();
  $self->run();
}

sub get_search_by_tag {
  my $self = shift;
  my $tag = shift;
  foreach (@{$self->{searches}}) {
    if ($_->{tag} eq $tag) {
      return $_;
    }
  }
  return undef;
}

sub get_search_by_template {
  my $self = shift;
  my $tag = shift;
  foreach (@{$self->{searches}}) {
    if ($_->{template} eq $tag) {
      return $_;
    }
  }
  return undef;
}

sub expect_result {
  my $self = shift;
  my $expect = { 
      OK => shift,
      WARNING => shift,
      CRITICAL => shift,
      UNKNOWN => shift
  };
  my $exp_exit = shift;
  my $as_expected = 1;
  foreach (keys %{$expect}) {
    if (defined $expect->{$_}) {
      if ($expect->{$_} != $self->{allerrors}->{$_}) {
        $as_expected = 0;
      }
    }
  }
  if ($self->{exitcode} != $exp_exit) {
    $as_expected = 0;
  }
  return $as_expected;
}

sub has_result {
  my $self = shift;
  return join(", ", (map { 
      $self->{allerrors}->{$_} 
  } qw(OK WARNING CRITICAL UNKNOWN)), $self->{exitcode});
}

sub create_file {
  my $self = shift;
  my $file = shift;
  my $perms = shift;
  my $contents = shift;
  open CCC, ">$file";
  print CCC $contents;
  close CCC;
  chmod $perms, $file;
}

sub delete_file {
  my $self = shift;
  my $file = shift;
  unlink $file;
}

sub read_file {
  my $self = shift;
  my $file = shift;
  if (-r $file) {
  	local( $/, *FFF ) ;
  	open FFF, "<$file";
  	my $content = <FFF>;
  	close FFF;
  	return $content;
  } else {
    return "";
  }
}

package Nagios::CheckLogfiles::Search::Test;

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
  my $class = shift;
  my $params = shift;
  my $self = $class->SUPER::new($params);
printf STDERR "i %s new prefilter %s\n", $self->{tag}, $self->{prefilter};
  return bless $self, $class;
}

sub reset {
  my $self = shift;
#printf STDERR "i %s renew prefilter %s with tag %s\n", $self->{tag}, $self->{prefilter}, $self->{macros}->{CL_TAG};
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
  delete $self->{tracebuffer};
  delete $self->{laststate};
  delete $self->{matchlines};
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

sub dump_trace {
  my $self = shift;
  foreach (@{$self->{tracebuffer}}) {
    printf STDERR "%s\n", $_;
  }
}

sub delete_logfile {
  my $self = shift;
  my $rndfile;
  $self->{oldrandomfile} = $self->{randomfile};
  if (-e $self->{logfile}) {
    $self->trace(sprintf "D1 logfile %s %d", $self->{logfile},
        (stat $self->{logfile})[1]);
    unlink $self->{logfile};
    # reuse the inode immediately
    $self->{randomfile} = sprintf "%s/this_is_random.%d",
        dirname($self->{logfile}), int(rand 1000);
    $rndfile = IO::File->new();
    $rndfile->open(">$self->{randomfile}");
    $rndfile->printf("\n");
    $rndfile->close();
    sleep 1;
    #system("touch $self->{randomfile}");
    $self->trace(sprintf "D2 rndfile %d", (stat $self->{randomfile})[1]);
    if ($self->{oldrandomfile} && -f $self->{oldrandomfile}) {
      $self->trace(sprintf "D3 rndfile %d", (stat $self->{oldrandomfile})[1]);
      unlink $self->{oldrandomfile};
    }
    delete $self->{oldrandomfile};
  }
  if ($self->{rotation}) {
    $self->delete_archives();
  }
}

sub delete_seekfile {
  my $self = shift;
  if (-e $self->{seekfile}) {
    $self->trace(sprintf "D1 seekfile %s %d", $self->{seekfile},
        (stat $self->{seekfile})[1]);
    unlink $self->{seekfile};
  } else {
    $self->trace(sprintf "D2 seekfile %s", $self->{seekfile});
  }
}

sub delete_archives {
  my $self = shift;
  foreach my $archive (glob $self->{archivedir}.'/*') {
    if ($archive ne $self->{logfile}) {
      unlink $archive;
    }
  }
}

sub touch_logfile {
  my $self = shift;
  my $logfh = IO::File->new();
  $logfh->autoflush(1);
  $logfh->open($self->{logfile}, "a");
  $logfh->close();
}

sub truncate_logfile {
  my $self = shift;
  truncate($self->{logfile}, 0);
}

sub restrict_logfile {
  my $self = shift;
  if ($^O =~ /MSWin/) {
    my $winlogfile = $self->{logfile};
    $winlogfile =~ s/\//\\/g;
    my $cmd = sprintf "CACLS %s /D %s /E", $winlogfile, $self->{macros}->{CL_USERNAME};
    $self->trace("%s", $cmd);
    system($cmd);
  } else {
    chmod 0000, $self->{logfile};
  }
}

sub unrestrict_logfile {
  my $self = shift;
  if ($^O =~ /MSWin/) {
    my $winlogfile = $self->{logfile};
    $winlogfile =~ s/\//\\/g;
    my $cmd = sprintf "CACLS %s /G %s:F /E", $winlogfile, $self->{macros}->{CL_USERNAME};
    $self->trace("%s", $cmd);
    system($cmd);
  } else {
    chmod 0644, $self->{logfile};
  } 
} 

sub dump_seekfile {
  my $self = shift;
  my $seekfh = IO::File->new();
  if ($seekfh->open($self->{seekfile}, "r")) {
    while (my $line = $seekfh->getline()) {
      printf "%s", $line;
    }
    $seekfh->close();
  }
}

sub rotate {
  my $self = shift;
  my $method = shift || $self->{rotation};
  if ($method eq "SOLARIS") {
  	my $oldest = 0;
  	foreach my $archive (glob $self->{archivedir}.'/messages.*') {
  	  if ($archive =~ /messages.(\d+)/) {
  	  	if ($1 > $oldest) {
  	  	  $oldest = $1;
  	  	}
  	  }
  	}
  	foreach (reverse (0 .. $oldest)) {
  	  if (-f $self->{archivedir}.'/messages.'.$_) {
        rename $self->{archivedir}.'/messages.'.$_,
            $self->{archivedir}.'/messages.'.($_ + 1); 
            $self->trace(sprintf "i move %s to %s", $self->{archivedir}.'/messages.'.$_,
            $self->{archivedir}.'/messages.'.($_ + 1));
  	  } else {
  	    $self->trace(sprintf "i cannot find %s", $self->{archivedir}.'/messages.'.$_);
  	  }
  	}
  	$self->trace(sprintf "i move %s to %s", $self->{logfile}, $self->{archivedir}.'/messages.0');
    rename $self->{logfile}, $self->{archivedir}.'/messages.0';
  } elsif ($method eq "loglog0log1") {
    my $oldest = 0;
    my $globfiles = $self->{archivedir}.'/'.$self->{logbasename}.'.*';
    if ($globfiles =~ /[^\\][ ]/) {
      # because Core::glob splits the argument on whitespace
      $globfiles =~ s/( )/\\$1/g;
    }
    foreach my $archive (glob "$globfiles") {
      $archive = basename($archive);
      if ($archive !~ /^$self->{logbasename}\.(\d+)$/) {
        next;
      } else {
  	if ($1 > $oldest) {
  	  $oldest = $1;
  	}
      }
    }
    foreach (reverse (0 .. $oldest)) {
      if (-f $self->{archivedir}.'/'.$self->{logbasename}.'.'.$_) {
        rename $self->{archivedir}.'/'.$self->{logbasename}.'.'.$_,
        $self->{archivedir}.'/'.$self->{logbasename}.'.'.($_ + 1);
        $self->trace(sprintf "i move %s to %s", 
            $self->{archivedir}.'/'.$self->{logbasename}.'.'.$_,
            $self->{archivedir}.'/'.$self->{logbasename}.'.'.($_ + 1));
      } else {
        $self->trace(sprintf "i cannot find %s", 
            $self->{archivedir}.'/'.$self->{logbasename}.'.'.$_);
      }
    }
    $self->trace(sprintf "i move %s to %s", $self->{logfile}, $self->{archivedir}.'/'.$self->{logbasename}.'.0');
    rename $self->{logfile}, $self->{archivedir}.'/'.$self->{logbasename}.'.0';
  }
  sleep 2;
}

sub rotate_compress {
  my $self = shift;
  my $method = shift || $self->{rotation};
  if ($method eq "SOLARIS") {
    my $oldest = 0;
    $self->trace(sprintf "compressing and rotation like solaris");
    foreach my $archive (glob $self->{archivedir}.'/messages.*') {
      if ($archive =~ /messages.(\d+)/) {
        if ($1 > $oldest) {
          $oldest = $1;
        }
      }
    }
    $self->trace(sprintf "oldest archive is messages.%d", $oldest);
    foreach (reverse (0 .. $oldest)) {
      if (-f $self->{archivedir}.'/messages.'.$_) {
        $self->trace(sprintf "i found %s",
            $self->{archivedir}.'/messages.'.$_);
        rename $self->{archivedir}.'/messages.'.$_,
            $self->{archivedir}.'/messages.'.($_ + 1);
        $self->trace(sprintf "i move %s to %s modified %d,  accessed %d,  inode %d",
            $self->{archivedir}.'/messages.'.$_,
            $self->{archivedir}.'/messages.'.($_ + 1),
            (stat $self->{archivedir}.'/messages.'.($_ + 1))[9],
            (stat $self->{archivedir}.'/messages.'.($_ + 1))[8],
            (stat $self->{archivedir}.'/messages.'.($_ + 1))[10]);
        system("gzip", "-f", $self->{archivedir}.'/messages.'.($_ + 1));
        sleep 2;
        $self->trace(sprintf "i compress %s modified %d,  accessed %d,  inode %d",
            $self->{archivedir}.'/messages.'.($_ + 1),
            (stat $self->{archivedir}.'/messages.'.($_ + 1).'.gz')[9],
            (stat $self->{archivedir}.'/messages.'.($_ + 1).'.gz')[8],
            (stat $self->{archivedir}.'/messages.'.($_ + 1).'.gz')[10]);
      } elsif (-f $self->{archivedir}.'/messages.'.$_.'.gz') {
        $self->trace(sprintf "i found %s",
            $self->{archivedir}.'/messages.'.$_.'.gz');
        rename $self->{archivedir}.'/messages.'.$_.'.gz',
            $self->{archivedir}.'/messages.'.($_ + 1).'.gz';
        $self->trace(sprintf "i move %s to %s modified %d,  accessed %d,  inode %d",
            $self->{archivedir}.'/messages.'.$_.'.gz',
            $self->{archivedir}.'/messages.'.($_ + 1).'.gz',
            (stat $self->{archivedir}.'/messages.'.($_ + 1).'.gz')[9],
            (stat $self->{archivedir}.'/messages.'.($_ + 1).'.gz')[8],
            (stat $self->{archivedir}.'/messages.'.($_ + 1).'.gz')[10]);
        sleep 2;
      } else {
        $self->trace(sprintf "i cannot find %s",
            $self->{archivedir}.'/messages.'.$_);
      }
    }
    rename $self->{logfile}, $self->{archivedir}.'/messages.0';
    $self->trace(sprintf "i move %s to %s modified %d,  accessed %d,  inode %d", 
        $self->{logfile}, $self->{archivedir}.'/messages.0',
        (stat $self->{archivedir}.'/messages.0')[9],
        (stat $self->{archivedir}.'/messages.0')[8],
        (stat $self->{archivedir}.'/messages.0')[10]);

    $self->trace(sprintf "done compressing and rotation like solaris");
  }
  sleep 2;
}


sub dump_protocol {
  my $self = shift;
  foreach my $level (qw (OK WARNING CRITICAL UNKNOWN)) {
    if ($self->getmatches($level)) {
      printf STDERR "%s errors in %s\n", $level, $self->{logbasename};
      foreach ($self->getmatchmessages($level)) {
        printf STDERR "%s\n", $_;
      }
    }
  }
}

##### eventcreate
sub logger {
  my $self = shift;
  my $hostname = shift;
  my $process = shift;
  my $count = shift || 1;
  my $message = shift;
  my $raw = shift || 0;
  my $details = shift || {};
  $| = 1;
  if (($self->{type} eq "psloglist") || ($self->{type} eq "eventlog") || ($self->{type} eq "wevtutil")) {
    my $cmd;
    my $type = exists $details->{EventType} ? uc $details->{EventType} : "INFORMATION";
    my $source = exists $details->{Source} ? $details->{Source} : "check_logfiles";
    my $id = exists $details->{EventID} ? $details->{EventID} : 1;
    while ($count--) {
      if ($^O =~ /cygwin/) {
        #$cmd = sprintf '/cygdrive/c/WINDOWS/system32/eventcreate /L Application /SO %s /T %s /ID %s /D "%s" >/dev/null 2>&1',
        $cmd = sprintf '/cygdrive/c/WINDOWS/system32/eventcreate /L Application /T %s /ID %s /D "%s" >/dev/null 2>&1',
            $type, $id, $message;
      } else { # MSWin or other native windows perls
        $cmd = sprintf 'C:\WINDOWS\system32\eventcreate /L Application /SO %s /T %s /ID %s /D "%s" 1>NUL 2>&1',
            $source, $type, $id, $message;
      }
printf "exec %s\n", $cmd;
      system($cmd);
    }
  } else {
    $hostname ||= "localhost";
    $process ||= "check_logfiles";
    my $logfh = IO::File->new();
    $logfh->autoflush(1);
    if ($logfh->open($self->{logfile}, "a")) {
      while ($count--) {
        if (! $raw) {
    	  my($sec, $min, $hour, $mday, $mon, $year) = 
              (localtime)[0, 1, 2, 3, 4, 5];
          my $timestamp = sprintf "%3s %2d %02d:%02d:%02d",
              ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")[$mon],
              $mday, $hour, $min, $sec;
          if ($process ne 'check_logfiles') {
            # z.b. $tivtest->logger('dellsrv', 'Server Administrator:', 1, "Storage Service EventID: 1004 on PE 1850");
            # Jun 19 10:57:58 dellsrv Server Administrator: Storage Service EventID: 1004 on PE 1850
  	    $logfh->printf("%s %s %s %s\n",
  	        $timestamp, $hostname, $process, $message);
          } else {
  	    $logfh->printf("%s %s %s[%d] %s\n",
  	        $timestamp, $hostname, $process, $$, $message);
          }
        } else {
  	  $logfh->printf("%s\n", $message);
        }
      }
    }
    $logfh->close();
  }
}

sub loggercrap {
  my $self = shift;
  my $hostname = shift || "localhost";
  my $process = shift || "check_logfiles";
  my $count = shift || 1;
  my $maxmsg = rand($count) + 1;
  my $messages = [
      ["", 
          "-- MARK --",
          "last message repeated 1 time",
          "last message repeated 100 times"],
      ["in.fingerd", 
          "connect from xxx1\@umbc9.umbc.edu"],
      ["inetd", 
          "registrar/tcp: Connection from hpcae30 (160.21.33.43) at Wed Nov 29 11:10:17 2006",
          "shell/tcp: Connection from svxbs28 (160.21.33.209) at Wed Nov 29 11:15:01 2006",
          "auth/tcp: Connection from lldsm43 (160.21.33.146) at Wed Nov 29 10:24:55 2006"],
      ["sam-arcopy", 
          "[ID 287109 local7.info] info OS call error: open(/net/spams/fs02/share/PAK/aw_06/1000/E61/R-V515229N47D20OL6HP19T\334/08.06.2006_18.35_3_LB_3_A/DATA/MeasSetup/ChanPos): File is offline",
          "[ID 475690 local7.info] info OS call error: open failed: sa.912518",
          "[ID 821104 local7.info] info OS call error: open(/net/spams/fs02/share/EWE-ARCH/aw_30/E60/_Datenkorb/_G01_E060-07-03-450/_41_FV_2_iO/CCA060/FV_CCA060_CHIKOR-HO_E89x-07-03-450_E89x-07-06-400/SB_041028_DF_CCA060_E89x-07-03-450_E89x-07-06-400__E060_E070-07-09-350_E060-07-09-350.xml"
      ],
      ["devfsadm",
          "[ID 518500 daemon.error] readlink failed for /dev/vx/dsk/rootdg: Invalid argument"
      ],
      ["sshd", 
          "Invalid user delta from 194.44.247.243 ",
          "Invalid user tester from 194.44.247.243 ",
          "Failed none for hiasl from 192.168.9.11 port 4250 ssh2",
          "[ID 800047 auth.info] Connection closed by 160.21.33.116",
          "[ID 800047 auth.info] Found matching RSA key: 46:8f:0b:18:a6:ed:2a:89:b0:f7:79:9e:e5:5f:65:8d",
          "[ID 800047 auth.info] Accepted publickey for qqdda from 160.21.33.116 port 44436 ssh2",
          "[ID 800047 auth.info] Failed none for qqdda from 160.21.33.116 port 44398 ssh2",
          "[ID 800047 auth.info] subsystem request for sftp",
          "[ID 800047 auth.info] Generating new 768 bit RSA key.",
          "[ID 800047 auth.info] RSA key generation complete."],
      ["scsi",
          "[ID 799468 kern.info] ssd112 at scsi_vhci0: name g600c0ff000000000007c026394436200, bus address g600c0ff000000000007c026394436200",
          "[ID 243001 kern.info]      Target 0x2305ef: Device type not supported: Device type=0x3 Peripheral qual=0x0"],
      ["mpxio",
          "[ID 669396 kern.info] /scsi_vhci/ssd\@g600c0ff000000000007c02288cc3ff00 (ssd114) multipath status: failed, path /pci\@1d,700000/SUNW,qlc\@2/fp\@0,0 (fp4) to target address: 226000c0ffa07c02,3 is offline. Load balancing: none",
          "[ID 669396 kern.info] /scsi_vhci/ssd\@g600c0ff000000000007c02288cc3ff00 (ssd114) multipath status: degraded, path /pci\@1d,700000/SUNW,qlc\@2/fp\@0,0 (fp4) to target address: 226000c0ffa07c02,3 is online. Load balancing: none"]
  ];
  for (1..$maxmsg) {
  	my $procnum = int rand(scalar(@{$messages}));
  	my $msgnum = int rand(scalar(@{$messages->[$procnum]}) - 1) + 1;
    $self->logger(undef, $messages->[$procnum]->[0], 1, $messages->[$procnum]->[$msgnum]);
  }
  $self->trace(sprintf "%s logs %d random messages to %s", 
      $self->{tag}, $maxmsg, $self->{logfile});
  return $maxmsg;
}

sub revert_seekfile {
  my $self = shift;
  my $tmp = {};
  our $state = {};
  if (-f $self->{seekfile}) {
    $self->trace(sprintf "seekfile to revert %s found", $self->{seekfile});
    eval {
      do $self->{seekfile};
    };
    if ($@) {
      # found a seekfile with the old syntax
      $self->trace(sprintf "seekfile to revert has old format %s", $@);
      my $seekfh = new IO::File;
      $seekfh->open($self->{seekfile}, "r");
      $tmp->{lastlogoffset} = $seekfh->getline() || 0;
      $tmp->{lastlogtime} = $seekfh->getline() || 0;
      $tmp->{lastdevino} = $seekfh->getline();
      chomp $tmp->{lastlogoffset};
      chomp $tmp->{lastlogtime};
      chomp $tmp->{lastdevino};
      $seekfh->close();
      if (! $self->{lastdevino}) {
        # upgrade vom < 1.4 on the fly
        $self->{lastdevino} = (-e $self->{logfile}) ?
            sprintf ("%d:%d", (stat $self->{logfile})[0],
              (stat $self->{logfile})[1]) : "0:0";
      }
      $self->{lastlogfile} = $self->{logfile};
    } else {
      $self->trace(sprintf "seekfile to revert has new format %s", $@);
      $tmp->{lastlogoffset} = $state->{logoffset};
      $tmp->{lastlogtime} = $state->{logtime};
      $tmp->{lastdevino} = $state->{devino};
      $tmp->{lastlogfile} = $state->{logfile};
    }
    my $seekfh = new IO::File;
    if ($seekfh->open($self->{pre2seekfile}, "w")) {
      $self->trace(sprintf "writing seekfile %s in old format as %s",
          $self->{seekfile}, $self->{pre2seekfile});
      $seekfh->printf("%d\n", $tmp->{lastlogoffset});
      $seekfh->printf("%d\n", $tmp->{lastlogtime});
      $seekfh->printf("%s\n", $tmp->{lastdevino});
      $seekfh->close();
      unlink $self->{seekfile};
    }
  }
}

1;
