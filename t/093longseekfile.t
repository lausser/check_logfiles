#!/usr/bin/perl -w
# ~/check_logfiles/test/093longseekfile.t.t
# Pathnames have a max length of 256. If there is a long and complicated
# absolute path of a seekfile and/or a very long tag, then the seekfile
# might be longer than 256 characters. This leads to an error, when the
# plugin tries to write it.
use strict;
use Test::More tests => 4;
use Cwd;
use File::Basename;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";
if ($^O =~ /MSWin/) {
  system ('rd /S /Q .\var\hirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharn');
  system ('md var\hirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharn');
} else {
  system("rm -rf ./var/hirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharn");
  mkdir "./var/hirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharn";
}
my $logdir = sprintf "./var/hirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharnhirnhornharn";

mkdir $logdir;
my $cl = Nagios::CheckLogfiles::Test->new({
        protocolsdir => TESTDIR."/var/tmp",
        seekfilesdir => TESTDIR."/var/tmp",
        searches => [
            {
              tag => "goasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassschoasmassschoasmassschoasmassschoasmass",
              logfile => $logdir."/messages",
              criticalpatterns => "Failed password",
              warningpatterns => "Unknown user",
              rotation => "SOLARIS",
            }
        ]
});


my $ssh = $cl->get_search_by_tag("goasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassgoasmassschoasmassschoasmassschoasmassschoasmass");
$ssh->delete_logfile();
$ssh->delete_seekfile();
$ssh->trace("deleted logfile and seekfile");
# logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$ssh->logger(undef, undef, 2, "Failed password for invalid user1");
sleep 1;
$ssh->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));
# now find the two criticals
$ssh->trace("==== 2 ====");
$cl->reset();
$ssh->loggercrap(undef, undef, 100);
$ssh->logger(undef, undef, 2, "Failed password for invalid user2");
$ssh->loggercrap(undef, undef, 100);
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 2, 0, 2));
my $beforelen = length($ssh->{tag}) + length($logdir."/messages");
my $afterlen = length(basename($ssh->{seekfile}));
diag($beforelen);
diag($afterlen);
diag($ssh->{seekfile});
ok($beforelen > 250);
# 200 plus -hash
ok($afterlen < 206);

