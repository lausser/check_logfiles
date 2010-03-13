#
# Logfile::Config::Tivoli.pm - Tivoli Config Module
#
# Purpose: Provide a convenient way for loading
#          tivoli config files and
#          return it as hash structure
#
package Nagios::Tivoli::Config::Logfile;

use strict;

sub new {
  my($this, $param ) = @_;
  my $class = ref($this) || $this;

  my $self = {
      formatfile   => '',  # format file with tivoli format definitions,
                           # can be an array of files
      formatstring => '',  # format file content as string
      severity_mappings => {},
      max_continuation_lines => 0, # in case there are %n in among the patterns
      line_buffer => [],   # for continuation lines
      line_buffer_size => 0,
  };
  bless $self, $class;

  $self->set_severity_mapping('fatal', 2);
  $self->set_severity_mapping('critical', 2);
  $self->set_severity_mapping('severe', 2);
  $self->set_severity_mapping('warning', 1);
  $self->set_severity_mapping('minor', 1);
  $self->set_severity_mapping('harmless', 0);
  $self->set_severity_mapping('unknown', 0);

  # parse parameter
  if (ref($param) eq "HASH") {
    for my $key (keys %{$param}) {
      if (!defined $self->{lc $key}) {
        printf STDERR "unrecognized parameter: %s\n", $key;
        return undef;
      } else {
        if (ref($param->{$key}) eq 'HASH') {
          $self->merge_hash($self->{$key}, $param->{$key});
        } else {
          $self->{lc $key} = $param->{$key};
        }
      }
    }
  } elsif (ref($param) eq "") {
    $self->{formatfile} = $param;
  } else {
    printf STDERR "formatfile is a required parameter\n";
  }
  if ((!defined $self->{formatfile} || $self->{formatfile} eq '') &&
      (!defined $self->{formatstring} || $self->{formatstring} eq '')) {
        printf STDERR "please either specify formatfile or formatstring\n";
    return undef;
  }
  if (defined $self->{formatstring} and $self->{formatstring} ne '') {
    $self->{_formatstring} = $self->{formatstring};
  } else {
    $self->{_formatstring} = $self->_read($self->{formatfile});
  }
  if (! $self->{_formatstring}) {
    return undef;
  }
  foreach (keys %{$self->{tivolimapping}}) {
    $self->set_severity_mapping($_, $self->{tivolimapping}->{$_});
  }
  if ($self->_parse) {
    #Data::Dumper::Dumper($self->{formats});
    return $self;
  } else {
    printf STDERR ("parsing failed, see previous messages...");
    return undef;
  }
}

sub _read {
  my $self     = shift;
  my $filename = shift;
  my $content;
  if (ref($filename) eq 'ARRAY') {
    for my $file (@{$filename}) {
      $content .= $self->_read($file);
    }
  } else {
    if (open FMT, $filename) {
      while(<FMT>) {
        $content .= $_;
      }
      close FMT;
    } else {
      printf STDERR "unable to read file %s: %s\n", $filename, $!;
      return undef;
    }
  }
  return($content);
}

sub _parse {
  my $self = shift;
  my $format;
  my $lineno = 0;
  for my $line (split /\n/, $self->{_formatstring}) {
    $lineno++;
    chomp $line;
    $line = $1 if $line =~ /^\s*(.*?)\s*$/;

    next if $line =~ m/^\/\//;
    next if $line eq "";

    if ($line =~ m/^FORMAT/) {
      my($name, $follows, $followname) = 
          $line =~ m/^FORMAT\s+(.*?)\s*(|FOLLOWS\s+(.*?))$/;
      $format= Nagios::Tivoli::Config::Logfile::Format->new({
          name => $name,
          lineno => $lineno,
          severity_mappings => $self->{severity_mappings},
      });
      if (defined $followname) {
        my @follows = split /\s*,\s*/, $followname;
        for my $follow (@follows) {
          if (my $follow_format = $self->get_format_by_name($follow)) {
            $format->inherit($follow_format);
          }
        }
        $format->{follows} = \@follows;
      }
    } elsif ($line =~ m/^END/) {
      if (!defined $format) {
        printf STDERR "found format end without beginning\n";
        return 0;
      }
      if (!defined $format->{pattern}) {
        if (!exists $format->{follows}) {
          printf STDERR "found format without pattern\n";
          return 0;
        }
      }
      $self->add_format($format);
    } elsif (defined $format) {
      if (!defined $format->{pattern}) {
        # %s Specifies a variable string.
        # %t Specifies a variable date of the form 'MMM DD hh:mm:ss'
        # %s+ Specifies one or more variable strings that
        #     are separated by spaces.
        # %s* Specifies zero or more strings separated by white space.
        # %n Specifies a new line (CR).
        #    This applies only to the following adapters:
        #    tecad_logfile_aix4-r1, tecad_logfile_hpux10,
        #    tecad_logfile_linux_ix86, tecad_logfile_linux-ppc,
        #    tecad_logfile_linux-s390, tecad_logfile_solaris2,
        #    and tecad_win.
        $format->{tiv_pattern} = $line;
        $format->{patternlines} = 0;
        if ($line =~ /%n/) {
          $format->{patternlines}++ while $line =~ /%n/g;
          $format->{pattern} = [map { $self->translate_pattern($_) } split /%n/, $line];
          $self->{max_continuation_lines} = $format->{patternlines} unless
              $format->{patternlines} <= $self->{max_continuation_lines};
        } else {
          $format->{pattern} = $self->translate_pattern($line);
        }
      } elsif ($line =~ m/^-(.*?)\s+(.*)$/i) {
        $format->add_variable($1, $2);
      } elsif ($line =~ m/^(.*?)\s+"*(.*?)"*\s*$/) {
        $format->add_slot($1, $2);
      }
    } else {
      printf STDERR "%s is outside of a format definition\n", $line;
      return 0;
    }
  }
  return 1;
}

sub translate_pattern {
  my $self = shift;
  my $tiv_pattern = shift;
  $tiv_pattern =~ s/\\/\\\\/g;          # quote \
  $tiv_pattern =~ s/\(/\\(/g;           # quote (
  $tiv_pattern =~ s/\)/\\)/g;           # quote )
  $tiv_pattern =~ s/%\[\d+\]s/%s/g;     # replace %[2]s with just %s
  $tiv_pattern =~ s/\[/\\[/g;           # quote [
  $tiv_pattern =~ s/\]/\\]/g;           # quote ]
  $tiv_pattern =~ s/\?/\\?/g;           # quote ?
  $tiv_pattern =~ s/\|/\\|/g;           # quote |
  $tiv_pattern =~ s/\-/\\-/g;           # quote -
  #$tiv_pattern =~ s/%s\+/\(.+?\)/g;     # %s+  becomes .+?
  #$tiv_pattern =~ s/%s\*/\(.*?\)/g;     # %s*  becomes .*?
  #$tiv_pattern =~ s/%s/\(\[^\\s\]+?\)/g;  # %s   becomes [^\s]+?
  $tiv_pattern =~ s/%s\+/\([^\\s]*?.+[^\\s]*?\)/g; # %s+ becomes [^\s]*?.+[^\s]*?
  $tiv_pattern =~ s/%s\*\s*$/\(.*\)/g;     # last %s*  becomes .* eats the rest
  $tiv_pattern =~ s/%s\*/\(.*?\)/g;     # %s*  becomes .*? eats as much as necessary
  $tiv_pattern =~ s/%s/\(\[^\\s\]+\)/g;  # %s   becomes [^\s]+?
  #$tiv_pattern =~ s/%n/\\n/g;           # %n   becomes \n
  $tiv_pattern =~ s/[ ]+/\\s\+/g;           # blanks become \s+
  $tiv_pattern =~ s/%n//g;           # %n   becomes \n
  $tiv_pattern =~ s/%t/\(\\w\{3\}\\s+\\d\{1,2\}\\s+\\d\{1,2\}\:\\d\{1,2\}\:\\d\{1,2\}\)/g;
  return $tiv_pattern;
}

sub match {
  my $self = shift;
  my $line = shift;
  if ($self->{line_buffer_size} < $self->{max_continuation_lines} + 1) {
    push(@{$self->{line_buffer}}, $line);
    $self->{line_buffer_size}++;
  } else {
    shift @{$self->{line_buffer}};
    push(@{$self->{line_buffer}}, $line);
  }
#printf STDERR "try: %s\n", $line;
  foreach my $format (reverse @{$self->{'formats'}}) {
    next if ! $format->{can_match};
    #if (($format->{name} ne '*DISCARD*') &&
    #    (! $format->has_slots() || ! $format->get_slot('severity'))) {
    #  next; # ungueltiges format
    #}
    my @matches = ();
#printf STDERR "format %s\n", $format->{name};
#printf STDERR "match /%s/\n", $format->{pattern};
    if (my @matches = $self->match_pattern($line, $format)) {
      my $hit = Nagios::Tivoli::Config::Logfile::Hit->new({
          format => $format,
          logline => $line,
          matches => \@matches,
          format_mappings => $self->{format_mappings},
          severity_mappings => $self->{severity_mappings},
      });
#printf STDERR "hit: %s\n", $line;
      if ($format->{name} eq '*DISCARD*') {
#printf STDERR "discard: %s %s\n", $line, Data::Dumper::Dumper($hit);
        last;
      } else {
#printf STDERR "hit2: %s // %s\n", $hit->{subject}, $format->{name};
        return({
          exit_code   => $hit->get_nagios_severity(),
          severity    => $hit->{severity},
          format_name => $hit->{format_name},
          subject     => $hit->{subject},
          logline     => $line,
          slots       => $hit->{slots},
        });
      }
    }
  }
#printf STDERR "mis: %s\n", $line;
  return({
    exit_code   => $self->get_severity_mapping('HARMLESS'),
    severity    => 'HARMLESS',
    format_name => 'NO MATCHING RULE',
    subject     => 'NO MATCHING RULE',
    logline     => $line,
    slots       => { },
  });
}

sub match_pattern {
  my $self = shift;
  my $line = shift;
  my $format = shift;
  my $pattern = $format->{pattern};
  if (ref($pattern) eq 'ARRAY') {
    my @all_matches = ();
    # 
    my $patterns = scalar(@{$pattern});
    if ($patterns > $self->{line_buffer_size}) {
      # zu wenig zeilen vorhanden
      return ();
    } else {
      my $startidx = $self->{line_buffer_size} - $patterns;
      my $idx = 0;
      while ($idx < $patterns) {
        # pattern[$idx] matched ${$self->{line_buffer}}[$startidx + $idx] ?
        if (my @matches = 
            ${$self->{line_buffer}}[$startidx + $idx] =~ /$pattern->[$idx]/) {
          $idx++;
          push(@all_matches, @matches);
        } else {
          last;
        }
      }
      if ($idx == $patterns) {
        return @all_matches;
      } else {
        return ();
      }
    }
  } else {
    #my @matches = $line =~ /$pattern/;
    my @matches = $format->{matchfunc}($line);
    return @matches;
  }
}

# inherit
#
# copy variable and slot definitions of a followed format to the current format
#
sub inherit {
  my $self = shift;
  my $ancestor = shift;
  $self->merge_hash($self->{variables}, $ancestor->{variables});
  $self->merge_hash($self->{slots}, $ancestor->{slots});
}

# get_severity_mapping
#
# get the numerical nagios level for a tivoli level
#
sub get_severity_mapping {
  my $self = shift;
  my $tivoli_severity = lc shift;
  return $self->{severity_mappings}->{$tivoli_severity};
}

# set_severity_mapping
#
# set the numerical nagios level for a tivoli level
#
sub set_severity_mapping {
  my $self = shift;
  my $tivoli_severity = lc shift;
  my $nagios_severity = shift;
  $self->{severity_mappings}->{$tivoli_severity} = $nagios_severity;
}

# set_format_mappings
#
# set runtime values for LABEL, DEFAULT,...
#
sub set_format_mappings {
    my $self = shift;
    my %mappings = @_;
    foreach (keys %mappings) {
      $self->{format_mappings}->{$_} = $mappings{$_};
    }
}

sub add_format {
  my $self = shift;
  my $format = shift;
  if (($format->{name} ne '*DISCARD*') &&
      (! $format->has_slots() || ! $format->get_slot('severity'))) {
      #printf STDERR "FORMAT %s skipped\n", $format->{name};
    $format->{can_match} = 0;
  } else {
    $format->{can_match} = 1;
  }
  push(@{$self->{formats}}, $format);
}

sub get_format_by_name {
  my $self = shift;
  my $name = shift;
  foreach (@{$self->{formats}}) {
    return $_ if $_->{name} eq $name;
  }
  return undef;
}

sub merge_hash {
    my $self  = shift;
    my $hash1 = shift;
    my $hash2 = shift;

    for my $key (keys %{$hash2}) {
        $hash1->{$key} = $hash2->{$key};
    }
    return($hash1);
}


package Nagios::Tivoli::Config::Logfile::Format;

use strict;
use warnings;
use Carp;
use vars qw(@ISA);

@ISA = qw(Nagios::Tivoli::Config::Logfile);

sub new {
  my($this, $param ) = @_;
  my $class = ref($this) || $this;

  my $self = {
      name => '',
      lineno => 0,
      slots => {},
      variables => {},
      severity_mappings => {},
  };
  bless $self, $class;

  if (ref($param) eq "HASH") {
    for my $key (keys %{$param}) {
      if (!defined $self->{lc $key}) {
        carp("unrecognized parameter: $key");
      } else {
        if (ref($param->{$key}) eq 'HASH') {
          $self->merge_hash($self->{$key}, $param->{$key});
        } else {
          $self->{lc $key} = $param->{$key};
        }
      }
    }
  }
  if (!defined $self->{name}) {
    die "please either specify formatfile or formatstring";
  }
  $self->add_match_closure();
  return $self;
}

sub add_slot {
  my $self = shift;
  my $slot = shift;
  my $value = shift;
  $self->{slots}->{$slot} = $value;
}

sub get_slot {
  my $self = shift;
  my $slot = shift;
  return $self->{slots}->{$slot};
}

sub has_slots {
  my $self = shift;
  return scalar (keys %{$self->{slots}});
}

sub add_variable {
  my $self = shift;
  my $variable = shift;
  my $value = shift;
  $self->{variables}->{$variable} = $value;
}

sub get_variable {
  my $self = shift;
  my $variable = shift;
  return $self->{variables}->{$variable};
}

sub has_variables {
  my $self = shift;
  return scalar (keys %{$self->{variables}});
}

sub add_match_closure {
  my $self = shift;
  # creates a function which keeps the compiled version of self->pattern
  $self->{matchfunc} = eval "sub { local \$_ = shift; return m/\$self->{pattern}/o; }";
}


package Nagios::Tivoli::Config::Logfile::Hit;

use strict;
use warnings;
use Carp;
use vars qw(@ISA);

@ISA = qw(Nagios::Tivoli::Config::Logfile::Format);

sub new {
  my($this, $param ) = @_;
  my $class = ref($this) || $this;

  my $self = {
      format => $param->{format},
      logline => $param->{logline},
      format_mappings => $param->{format_mappings},
      severity_mappings => $param->{severity_mappings},
      matches => {},
      variables => {},
      slots => {},
  };
  bless $self, $class;
  my $matchcnt = 1;
  map { $self->{matches}->{$matchcnt++} = $_; } @{$param->{matches}};
  $self->init();
  return $self;
}

sub init {
  my $self = shift;
  $self->{severity} = $self->{format}->{slots}->{severity};
  $self->{format_name} = $self->{format}->{name};
  $self->merge_hash($self->{variables}, $self->{format}->{variables});
  $self->merge_hash($self->{slots}, $self->{format}->{slots});
  # resolve pattern groups in internal variables
  foreach my $var (keys %{$self->{variables}}) {
    if ($self->{variables}->{$var} =~ /^\$(\d+)/) {
      if (defined $self->{matches}->{$1}) {
        $self->{variables}->{$var} = $self->{matches}->{$1};
      } else {
        printf STDERR "cannot replace \$%d in var %s\n", $1, $var;
      }
    }
  }
  # resolve pattern groups and format reserved words in slots
  foreach my $slot (keys %{$self->{slots}}) {
    if ($self->{slots}->{$slot} =~ /^\$(\d+)/) {
      if (defined $self->{matches}->{$1}) {
        $self->{slots}->{$slot} = $self->{matches}->{$1};
      } else {
        printf STDERR "cannot replace \$%d in slot %s\n", $1, $slot;
      }
    } elsif ($self->{slots}->{$slot} eq 'DEFAULT') {
      if ($slot eq 'hostname') {
        $self->{slots}->{$slot} = $self->{format_mappings}->{hostname};
      } elsif ($slot eq 'fqhostname') {
        $self->{slots}->{$slot} = $self->{format_mappings}->{fqhostname};
      } elsif ($slot eq 'origin') {
        $self->{slots}->{$slot} = $self->{format_mappings}->{origin};
      } else {
        $self->{slots}->{$slot} = 'check_logfiles';
      }
    } elsif ($self->{slots}->{$slot} eq 'LABEL') {
      $self->{slots}->{$slot} = $self->{format_mappings}->{LABEL};
    } elsif ($self->{slots}->{$slot} eq 'FILENAME') {
      $self->{slots}->{$slot} = $self->{format_mappings}->{FILENAME};
    } else {
    }
  }
  foreach my $slot (keys %{$self->{slots}}) {
    if ($self->{slots}->{$slot} =~ /PRINTF/i) {
      $self->{slots}->{$slot} = $self->printf($self->{slots}->{$slot});
    }
  }
  $self->{subject} = $self->{slots}->{msg} || $self->{logline};
  #delete $self->{slots}->{msg};
}

sub printf {
  my $self = shift;
  my $text = shift;
  my @printf = $text =~ m/printf\("(.*?)"\s*,\s*(.*)\)/i;
  my $result = $text;
  my @replacements;
  for my $key (split /\s*,\s*/, $printf[1]) {
    if (defined $self->{variables}->{$key}) {
      push @replacements, $self->{variables}->{$key};
    } elsif (defined $self->{slots}->{$key}) {
      push @replacements, $self->{slots}->{$key};
    } else {
      print STDERR "$key not found\n";
      push @replacements,  '';
    }
  }
  eval {
      $result = sprintf($printf[0], @replacements);
  };
  return($result);
}

sub get_nagios_severity {
  my $self = shift;
  return $self->get_severity_mapping($self->{slots}->{severity});
}

1;
