#!/usr/bin/perl -w
#
# ~/check_logfiles/test/001simple.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 4;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";


my $cl = Nagios::CheckLogfiles::Test->new({
	seekfilesdir => TESTDIR."/var/tmp",
	searches => [
	    {
	      tag => "html",
	      logfile => TESTDIR."/var/adm/messages",
	      criticalpatterns => ["head.*body"],
	    }
	]    });
my $html = $cl->get_search_by_tag("html");
$html->delete_logfile();
$html->delete_seekfile();
$html->trace("deleted logfile and seekfile");

# 1 logfile will be created. there is no seekfile. position at the end of file
# and remember this as starting point for the next run.
$html->trace(sprintf "+----------------------- test %d ------------------", 1);
sleep 2;
$html->loggercrap(undef, undef, 100);
sleep 1;
$html->trace("initial run");
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 0, 0));

# 1 critical
$html->trace(sprintf "+----------------------- test %d ------------------", 2);
$cl->reset();
$html->logger(undef, undef, 1, "<head title=\"bled\">A&B</head><body title='bb'>");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));

# set the new preferredlevel option
$html->set_option('htmlencode', 1);
#
# 3 now find the two criticals 
# do not match the warningpatterns, prefer critical
$html->trace(sprintf "+----------------------- test %d ------------------", 3);
$cl->reset();
$html->logger(undef, undef, 1, "<head title=\"bled\">A&B</head><body title='bb'>");
sleep 1;
$cl->run();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 1, 0, 2));
ok($cl->{exitmessage} =~ /&#60;head title=&#34;bled&#34;&#62;A&#38;B&#60;\/head&#62;&#60;body title=&#39;bb&#39;&#62;/);
                          #&#60;head title=&#34;bled&#34;&#62;A&#38;B&#60;/head&#62;&#60;body title=&#39;bb&#39;&#62;'

printf "%s\n", Data::Dumper::Dumper($html->{matchlines});
