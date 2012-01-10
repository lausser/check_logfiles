use strict;
use File::Basename;
use Getopt::Long qw(:config no_ignore_case getopt_compat);

#  --with-seekfiles-dir=PATH sets directory for the state files (default=/tmp)
#  --with-protocols-dir=PATH sets directory for the protocol files (default=/tmp)
#  --with-trusted-path=PATH sets trusted path for executables called by scripts (default=/bin:/sbin:/usr/bin:/usr/sbin)
#  --with-perl=PATH        sets path to perl executable
#  --with-gzip=PATH        sets path to gzip executable

my($opt_with_seekfiles_dir, $opt_with_protocols_dir, $opt_with_trusted_path, 
    $opt_with_perl, $opt_with_gzip);
my $release = "#RELEASE#";

if (! GetOptions(
    "with-seekfiles-dir=s" => \$opt_with_seekfiles_dir,
    "with-protocols-dir=s" => \$opt_with_protocols_dir,
    "with-trusted-path=s" => \$opt_with_trusted_path,
    "with-perl=s" => \$opt_with_perl,
    "with-gzip=s" => \$opt_with_gzip,
  )) {
  printf "nonono\n";
  exit;
}

$opt_with_seekfiles_dir = 'C:\TEMP' if ! $opt_with_seekfiles_dir;
$opt_with_protocols_dir = 'C:\TEMP' if ! $opt_with_protocols_dir;
$opt_with_trusted_path = '' if ! $opt_with_trusted_path;
$opt_with_perl = 'C:\strawberry\perl\bin\perl' if ! $opt_with_perl;
$opt_with_gzip = '' if ! $opt_with_gzip;
if (open CHECKLOGFILES, ">./plugins-scripts/check_logfiles") {
  printf CHECKLOGFILES "#! %s -w\n", $opt_with_perl;
  if (open CHECKLOGFILESPM, './plugins-scripts/Nagios/Tivoli/Config/Logfile.pm') {
    while(<CHECKLOGFILESPM>) {
      s/^1;//g;
      s/#SEEKFILES_DIR#/$opt_with_seekfiles_dir/g;
      s/#PROTOCOLS_DIR#/$opt_with_protocols_dir/g;
      s/#TRUSTED_PATH#/$opt_with_trusted_path/g;
      s/#PACKAGE_VERSION#/$release/g;
      printf CHECKLOGFILES "%s", $_;
    }
    close CHECKLOGFILESPM;
  }
  if (open CHECKLOGFILESPM, './plugins-scripts/Nagios/CheckLogfiles.pm') {
    while(<CHECKLOGFILESPM>) {
      s/^1;//g;
      s/#SEEKFILES_DIR#/$opt_with_seekfiles_dir/g;
      s/#PROTOCOLS_DIR#/$opt_with_protocols_dir/g;
      s/#TRUSTED_PATH#/$opt_with_trusted_path/g;
      s/#PACKAGE_VERSION#/$release/g;
      printf CHECKLOGFILES "%s", $_;
    }
    close CHECKLOGFILESPM;
  }
  if (open CHECKLOGFILESPM, './plugins-scripts/Nagios/CheckLogfiles/Search/Psloglist.pm') {
    while(<CHECKLOGFILESPM>) {
      s/^1;//g;
      s/#SEEKFILES_DIR#/$opt_with_seekfiles_dir/g;
      s/#PROTOCOLS_DIR#/$opt_with_protocols_dir/g;
      s/#TRUSTED_PATH#/$opt_with_trusted_path/g;
      s/#PACKAGE_VERSION#/$release/g;
      printf CHECKLOGFILES "%s", $_;
    }
    close CHECKLOGFILESPM;
  }
  if (open CHECKLOGFILESPM, './plugins-scripts/Nagios/CheckLogfiles/Search/Dumpel.pm') {
    while(<CHECKLOGFILESPM>) {
      s/^1;//g;
      s/#SEEKFILES_DIR#/$opt_with_seekfiles_dir/g;
      s/#PROTOCOLS_DIR#/$opt_with_protocols_dir/g;
      s/#TRUSTED_PATH#/$opt_with_trusted_path/g;
      s/#PACKAGE_VERSION#/$release/g;
      printf CHECKLOGFILES "%s", $_;
    }
    close CHECKLOGFILESPM;
  }
  if (open CHECKLOGFILESPM, './plugins-scripts/Nagios/CheckLogfiles/Search/Eventlog.pm') {
    while(<CHECKLOGFILESPM>) {
      s/^1;//g;
      s/#SEEKFILES_DIR#/$opt_with_seekfiles_dir/g;
      s/#PROTOCOLS_DIR#/$opt_with_protocols_dir/g;
      s/#TRUSTED_PATH#/$opt_with_trusted_path/g;
      s/#PACKAGE_VERSION#/$release/g;
      printf CHECKLOGFILES "%s", $_;
    }
    close CHECKLOGFILESPM;
  }
  if (open CHECKLOGFILESPM, './plugins-scripts/Nagios/CheckLogfiles/Search/Dummy.pm') {
    while(<CHECKLOGFILESPM>) {
      s/^1;//g;
      s/#SEEKFILES_DIR#/$opt_with_seekfiles_dir/g;
      s/#PROTOCOLS_DIR#/$opt_with_protocols_dir/g;
      s/#TRUSTED_PATH#/$opt_with_trusted_path/g;
      s/#PACKAGE_VERSION#/$release/g;
      printf CHECKLOGFILES "%s", $_;
    }
    close CHECKLOGFILESPM;
  }
  if (open CHECKLOGFILESPL, './plugins-scripts/check_logfiles.pl') {
    while(<CHECKLOGFILESPL>) {
      s/^1;//g;
      s/#SEEKFILES_DIR#/$opt_with_seekfiles_dir/g;
      s/#PROTOCOLS_DIR#/$opt_with_protocols_dir/g;
      s/#TRUSTED_PATH#/$opt_with_trusted_path/g;
      s/#PACKAGE_VERSION#/$release/g;
      printf CHECKLOGFILES "%s", $_;
    }
    close CHECKLOGFILESPL;
  }
  close CHECKLOGFILES;
}
