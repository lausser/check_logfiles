#!/usr/bin/perl -w
#
# ~/check_logfiles/test/071biggzrotation.t
#
#  Test the capability of finding rotated logfiles.
#

use strict;
use Test::More tests => 3;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

if ($^O =~ /MSWin/) {
  # in a desperate attempt...
  $ENV{PATH} = $ENV{PATH}.';C:\Programme\cygwin\bin;C:\cygwin\bin';
}

my $cl = Nagios::CheckLogfiles::Test->new({
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "bigssh",
              logfile => TESTDIR."/var/adm/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user",
              rotation => "SOLARIS",
            }
        ]    });
my $bigssh = $cl->get_search_by_tag("bigssh");
$bigssh->delete_logfile();
$bigssh->delete_seekfile();
$bigssh->trace("deleted logfile and seekfile");

# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$bigssh->logger(undef, undef, 2, "Failed password for invalid user1");
sleep 1;
$bigssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# now find the two criticals
$bigssh->trace("==== 2 ====");
$cl->reset();
rename "./var/adm/messages", "./var/adm/messages2";
#system("mv ./var/adm/messages ./var/adm/messages2");
$bigssh->loggercrap(undef, undef, 100);
$bigssh->logger(undef, undef, 2, "Failed password for invalid user2");
$bigssh->loggercrap(undef, undef, 100);
diag("logging big amounts of data");
$bigssh->loggercrap(undef, undef, 100000);
open CACA, ">>xyxy";
open MSG, "./var/adm/messages";
while (<MSG>) {
  print CACA $_;
}
close CACA;
close MSG;
#system("cat ./var/adm/messages >> xyxy");
my $size = (stat("./var/adm/messages"))[7];
my $errcnt = 1;
$bigssh->{max_readsize} = 1024 * 1024 ;
while ($size < $bigssh->{max_readsize}) {
  open CACA, ">>xyxy";
  open MSG, "./var/adm/messages";
  while (<MSG>) {
    print CACA $_;
  }
  close CACA;
  close MSG;
  #system("cat ./var/adm/messages >> xyxy");
  $size = (stat("xyxy"))[7];
  $errcnt++;
}
open CACA, ">>xyxy";
open MSG, "./var/adm/messages";
while (<MSG>) {
  print CACA $_;
}
close CACA;
close MSG;
#system("cat ./var/adm/messages >> xyxy");
$errcnt++;
$size = (stat("xyxy"))[7];
open CACA, "xyxy";
open MSG, ">>./var/adm/messages2";
while (<CACA>) {
  print MSG $_;
}
close CACA;
close MSG;
#system("cat xyxy >> ./var/adm/messages2");
rename "./var/adm/messages2", "./var/adm/messages";
#system("mv ./var/adm/messages2 ./var/adm/messages");
unlink("xyxy");
diag(sprintf "i wrote the messages %d times", $errcnt);
diag(sprintf "size is %u\n", $size);
diag(sprintf "maxs is %u\n", $bigssh->{max_readsize});
sleep 1;
diag("now position at a low offset and scan through a big file");
$cl->run();
diag("now a big offset was saved");
diag($cl->has_result());
diag($cl->{exitmessage});
diag(sprintf "i expect %d errors", 2 * $errcnt);
ok($cl->expect_result(0, 0, 2 * $errcnt, 0, 2));
system("cat ./var/tmp/check_logfiles.._var_adm_messages.bigssh");

# now flood the log, rotate and find the two new criticals
$bigssh->trace("==== 3 ====");
$bigssh->loggercrap(undef, undef, 100);
$bigssh->rotate_compress(); # mess -> mess.0
$bigssh->loggercrap(undef, undef, 100);
$bigssh->rotate_compress(); # mess.0 -> mess.1.gz
$cl->reset();
$bigssh->loggercrap(undef, undef, 100);
$bigssh->logger(undef, undef, 2, "Failed password for invalid user3");
$bigssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));

