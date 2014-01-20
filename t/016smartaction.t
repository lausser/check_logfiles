#!/usr/bin/perl -w
#
# ~/check_logfiles/test/016smartaction.t
#
#  Test that all the Perl modules we require are available.
#

use strict;
use Test::More tests => 38;
use Cwd;
use lib "../plugins-scripts";
use Nagios::CheckLogfiles::Test;
use constant TESTDIR => ".";

my $configfile = <<EOCFG;
\$seekfilesdir = "./var/tmp";
\$scriptpath = "./bin";
\$options = "smartprescript,smartpostscript";
\$prescript = "prescript.sh"; 
#\$prescriptstdin = "huhuhu";
\$postscript = 'postscript.sh';
\$MACROS = {
  CL_HARN => "harn"
};
\@searches = (
    {
      tag => "smart",
      logfile => "./var/adm/messages",
      criticalpatterns => [
             '.*connection unexpectedly closed.*',
             '.*rsync error.*',
             '!.*FIN.*',
             'Thermometer',
         ],
         warningpatterns => [
             '.*total size is 0 .*',
         ],
         options => 'smartscript',
         script => "script.sh"
    });

EOCFG
open CCC, ">./etc/check_action.cfg";
print CCC $configfile;
close CCC;

my $cl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_action.cfg" });
my $action = $cl->get_search_by_tag("smart");
my $prescript = $cl->get_search_by_tag("prescript");
my $postscript = $cl->get_search_by_tag("postscript");
$cl->reset();

$action->delete_logfile();
$action->delete_seekfile();
$cl->delete_file("./bin/prescript.sh");
$cl->delete_file("./bin/postscript.sh");
$cl->delete_file("./bin/script.sh");
$cl->delete_file("./bin/prescript.bat");
$cl->delete_file("./bin/postscript.bat");
$cl->delete_file("./bin/script.bat");


diag("deleted logfile and seekfile");
$cl->trace("=========== 1 =============");
$action->trace("deleted logfile and seekfile");
$action->logger(undef, undef, 1, "Failed password for invalid user1...");
sleep 1;
diag("now run");
$cl->run();

$prescript->dump_protocol(); # 1W not found
#$action->dump_protocol(); # 1C Missing, 1W script not found
$postscript->dump_protocol(); # 1W not found
diag("=============");
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 3, 1, 0, 2));

$cl->trace("=========== 2 =============");
if ($^O =~ /MSWin/) {
  $cl->create_file("./bin/prescript.bat", 0755, "
\@echo off
echo i am the prescript
echo status \"%CHECK_LOGFILES_SERVICESTATEID%\"
echo output \"%CHECK_LOGFILES_SERVICEOUTPUT%\"
exit 0
");
  $cl->create_file("./bin/postscript.bat", 0755, "
\@echo off
echo i am the postscript
echo status \"%CHECK_LOGFILES_SERVICESTATEID%\"
echo output \"%CHECK_LOGFILES_SERVICEOUTPUT%\"
exit 0
");
  $cl->create_file("./bin/script.bat", 0755, "
\@echo off
echo i am the script
echo status \"%CHECK_LOGFILES_SERVICESTATEID%\"
echo output \"%CHECK_LOGFILES_SERVICEOUTPUT%\"
exit 0
");
  $prescript->{script} = "prescript.bat";
  $postscript->{script} = "postscript.bat";
  $action->{script} = "script.bat";
} else {
  $cl->create_file("./bin/prescript.sh", 0755, "
echo i am the prescript
echo status \"\$CHECK_LOGFILES_SERVICESTATEID\"
echo output \"\$CHECK_LOGFILES_SERVICEOUTPUT\"
exit 0
");
  $cl->create_file("./bin/postscript.sh", 0755, "
echo i am the postscript
echo status \"\$CHECK_LOGFILES_SERVICESTATEID\"
echo output \"\$CHECK_LOGFILES_SERVICEOUTPUT\"
exit 0
");
  $cl->create_file("./bin/script.sh", 0755, "
echo i am the script
echo status \"\$CHECK_LOGFILES_SERVICESTATEID\"
echo output \"\$CHECK_LOGFILES_SERVICEOUTPUT\"
exit 0
");
}

$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(4, 0, 4, 0, 2));

$cl->trace("=========== 3 =============");
# test 3. 
# 1 critical - postscript
# 4 criticals - pattern
# 1 critical - prescript
# 
if ($^O =~  /MSWin/) {
  $cl->create_file("./bin/postscript.bat", 0755, "
\@echo off
echo i am critical ha ha ha
exit 2
");
  $cl->create_file("./bin/prescript.bat", 0755, "
\@echo off
echo i am the prescript
echo status \"%CHECK_LOGFILES_SERVICESTATEID%\"
echo output \"%CHECK_LOGFILES_SERVICEOUTPUT%\"
exit 2
");
} else {
  $cl->create_file("./bin/postscript.sh", 0755, "
echo i am critical ha ha ha
exit 2
");
  $cl->create_file("./bin/prescript.sh", 0755, "
echo i am the prescript
echo status \"\$CHECK_LOGFILES_SERVICESTATEID\"
echo output \"\$CHECK_LOGFILES_SERVICEOUTPUT\"
exit 2
");
}
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$prescript->dump_protocol(); # 1C return
$action->dump_protocol(); # 4C rsync error, 4OK script
#$postscript->dump_protocol(); # 1C return
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(4, 0, 6, 0, 2));

$cl->trace("=========== 4 =============");
# test 4.
# 4 criticals - pattern
# 4 warnings - script
# 1 warning - prescript missing
# 1 unknown - postscript says unknown
$cl->delete_file("./bin/prescript.sh");
$cl->delete_file("./bin/postscript.sh");
$cl->delete_file("./bin/script.sh");
$cl->delete_file("./bin/prescript.bat");
$cl->delete_file("./bin/postscript.bat");
$cl->delete_file("./bin/script.bat");
if ($^O =~  /MSWin/) {
  $cl->create_file("./bin/postscript.bat", 0755, "
\@echo off
echo i am unknown ha ha ha
exit 3
");
  $cl->create_file("./bin/script.bat", 0755, "
\@echo off
echo i warn you
exit 1
");
} else {
  $cl->create_file("./bin/postscript.sh", 0755, "
echo i am unknown ha ha ha
exit 3
");
  $cl->create_file("./bin/script.sh", 0755, "
echo i warn you
exit 1
");
}
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$prescript->dump_protocol(); # 1W not found
#$action->dump_protocol();
#$postscript->dump_protocol(); # 1W not found
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 5, 4, 1, 2));



$cl->trace("=========== 5 =============");
# test 4.
# 4 criticals - pattern
# 4 warnings - script
# 1 warning - prescript missing
# 1 critical - postscript is now supersmart
#------------
# 1 critical
#
$cl->delete_file("./bin/prescript.sh");
$cl->delete_file("./bin/postscript.sh");
$cl->delete_file("./bin/script.sh");
$cl->delete_file("./bin/prescript.bat");
$cl->delete_file("./bin/postscript.bat");
$cl->delete_file("./bin/script.bat");
if ($^O =~  /MSWin/) {
  $cl->create_file("./bin/postscript.bat", 0755, "
\@echo off
if %CHECK_LOGFILES_SERVICESTATEID% gtr 0 goto nagioserr
  echo \"%CHECK_LOGFILES_SERVICEOUTPUT%\"
  exit %CHECK_LOGFILES_SERVICESTATEID%
:nagioserr
  echo this check failed with status %CHECK_LOGFILES_SERVICESTATE%
  exit 3
");
  $cl->create_file("./bin/script.bat", 0755, "
\@echo off
echo i warn you
exit 1
");
} else {
  $cl->create_file("./bin/postscript.sh", 0755, "
if [ \$CHECK_LOGFILES_SERVICESTATEID -gt 0 ]; then
  echo this check failed with status \$CHECK_LOGFILES_SERVICESTATE
  exit 3 # force the while script to end with unknown
else
  echo \"\$CHECK_LOGFILES_SERVICEOUTPUT\"
  exit \$CHECK_LOGFILES_SERVICESTATEID
fi
");
  $cl->create_file("./bin/script.sh", 0755, "
echo i warn you
exit 1
");
}
$postscript->{options}->{supersmartscript} = 1;
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$prescript->dump_protocol(); # 1W not found
#$action->dump_protocol();
#$postscript->dump_protocol(); # 1W not found
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 0, 1, 3));


$cl->trace("=========== 6 =============");
# test 4.
# 4 criticals - pattern
# 4 warnings - script
# 1 warning - prescript missing
# 1 critical - postscript is now supersmart
#------------
# 1 critical
#
$cl->delete_file("./bin/prescript.sh");
$cl->delete_file("./bin/postscript.sh");
$cl->delete_file("./bin/script.sh");
$cl->delete_file("./bin/prescript.bat");
$cl->delete_file("./bin/postscript.bat");
$cl->delete_file("./bin/script.bat");
if ($^O =~ /MSWin/) {
  $cl->create_file("./bin/postscript.bat", 0755, "
\@echo off
if %CHECK_LOGFILES_SERVICESTATEID% gtr 0 goto nagioserr
  echo \"%CHECK_LOGFILES_SERVICEOUTPUT%\"
  exit %CHECK_LOGFILES_SERVICESTATEID%
:nagioserr
  echo this check failed with status %CHECK_LOGFILES_SERVICESTATE%
  exit 3
");
  $cl->create_file("./bin/script.bat", 0755, "
\@echo off
echo i warn you
exit 1
");
} else {
  $cl->create_file("./bin/postscript.sh", 0755, "
if [ \$CHECK_LOGFILES_SERVICESTATEID -gt 0 ]; then
  echo this check failed with status \$CHECK_LOGFILES_SERVICESTATE
  exit 3 # force the while script to end with unknown
else
  echo \"\$CHECK_LOGFILES_SERVICEOUTPUT\"
  exit \$CHECK_LOGFILES_SERVICESTATEID
fi
");
  $cl->create_file("./bin/script.sh", 0755, "
echo i warn you
exit 1;
");
}
$postscript->{options}->{supersmartscript} = 1;
$postscript->{script} = sub {
  printf "hihihihihihihi";
  return 2;
};
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$prescript->dump_protocol(); # 1W not found
#$action->dump_protocol();
#$postscript->dump_protocol(); # 1W not found
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->{exitmessage} =~ /.*hihihihihihihi.*/);
ok($cl->expect_result(0, 0, 1, 0, 2));



# supersmart prescript aborts the whole run
$cl->trace("================== 7 ==============");
$cl->delete_file("./bin/prescript.sh");
$cl->delete_file("./bin/postscript.sh");
$cl->delete_file("./bin/script.sh");
$cl->delete_file("./bin/prescript.bat");
$cl->delete_file("./bin/postscript.bat");
$cl->delete_file("./bin/script.bat");
if ($^O =~ /MSWin/) {
  $cl->create_file("./bin/prescript.bat", 0755, "
\@echo off
echo no i will not run
exit 2
fi
");
} else {
  $cl->create_file("./bin/prescript.sh", 0755, "
echo no i will not run
exit 2
");
}
$prescript->{options}->{supersmartscript} = 1;
$postscript->{options}->{supersmartscript} = 1;
$postscript->{script} = sub {
  printf "hihihihihihihi";
  return 2;
};
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$prescript->dump_protocol(); # 1W not found
#$action->dump_protocol();
#$postscript->dump_protocol(); # 1W not found
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->{exitmessage} =~ /CRITICAL.*i will not run.*/);
ok($cl->expect_result(0, 0, 1, 0, 2));

############################ 7
diag("supersmart prescript aborts the whole run warning");
$cl->trace("================== 8 ==============");
$cl->delete_file("./bin/prescript.sh");
$cl->delete_file("./bin/postscript.sh");
$cl->delete_file("./bin/script.sh");
$cl->delete_file("./bin/prescript.bat");
$cl->delete_file("./bin/postscript.bat");
$cl->delete_file("./bin/script.bat");
if ($^O =~ /MSWin/) {
  $cl->create_file("./bin/prescript.bat", 0755, "
\@echo off
echo no i will not run
exit 1
fi
");
} else {
  $cl->create_file("./bin/prescript.sh", 0755, "
echo no i will not run
exit 1
");
}
$prescript->{options}->{supersmartscript} = 1;
$postscript->{options}->{supersmartscript} = 1;
$postscript->{script} = sub {
  printf "hihihihihihihi";
  return 2;
};
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$prescript->dump_protocol(); # 1W not found
#$action->dump_protocol();
#$postscript->dump_protocol(); # 1W not found
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->{exitmessage} =~ /WARNING.*i will not run.*/);
ok($cl->expect_result(0, 1, 0, 0, 1));

############################ 7
diag("supersmart prescript aborts the whole run critical");
$cl->trace("================== 9 ==============");
$cl->delete_file("./bin/prescript.sh");
$cl->delete_file("./bin/postscript.sh");
$cl->delete_file("./bin/script.sh");
$cl->delete_file("./bin/prescript.bat");
$cl->delete_file("./bin/postscript.bat");
$cl->delete_file("./bin/script.bat");
if ($^O =~ /MSWin/) {
  $cl->create_file("./bin/prescript.bat", 0755, "
\@echo off
echo no i will definitively not run
exit 2
fi
");
} else {
  $cl->create_file("./bin/prescript.sh", 0755, "
echo no i will definitively not run
exit 2
");
}
$prescript->{options}->{supersmartscript} = 1;
$postscript->{options}->{supersmartscript} = 1;
$postscript->{script} = sub {
  printf "hihihihihihihi";
  return 2;
};
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$prescript->dump_protocol(); # 1W not found
#$action->dump_protocol();
#$postscript->dump_protocol(); # 1W not found
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->{exitmessage} =~ /CRITICAL.*i will definitively not run.*/);
ok($cl->expect_result(0, 0, 1, 0, 2));


diag("reset the logfiles");
$cl->trace("reset log and seek");
$action->delete_logfile();
$action->delete_seekfile();
$action->loggercrap(undef, undef, 100);
$prescript->{options}->{supersmartscript} = 0; # no abort this time
$cl->reset();
sleep 1;
$cl->run();

$cl->trace("=========== 10 repeat the machtes =============");
diag("supersmart script repeats the match");
if ($^O =~ /MSWin/) {
  $cl->create_file("./bin/script.bat", 0755, "
\@echo off
rem repeat the match
echo \%\"\%%CHECK_LOGFILES_SERVICEOUTPUT%\%\"\%
exit %CHECK_LOGFILES_SERVICESTATEID%
");
  $action->{script} = "script.bat";
} else {
  $cl->create_file("./bin/script.sh", 0755, "
# repeat the match
echo \"\$CHECK_LOGFILES_SERVICEOUTPUT\"
exit \$CHECK_LOGFILES_SERVICESTATEID
");
}
$prescript->{options}->{smartscript} = 0;
$postscript->{options}->{smartscript} = 0;
$prescript->{options}->{supersmartscript} = 0;
$postscript->{options}->{supersmartscript} = 0;
$prescript->{script} = sub {
  printf "OK - leck mich am arsch\n";
  return 0;
};
$postscript->{script} = sub {
  printf "OK - du mich auch\n";
  return 0;
};
$action->{options}->{supersmartscript} = 1;
$action->{options}->{smartscript} = 1;
$action->{options}->{script} = 1;
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 4, 0, 2));
ok($cl->{exitmessage} =~ /CRITICAL - \(4 errors\) - .*localhost check_logfiles\[\d+\] there was an rsync error.*\.\.\./);

$cl->trace("=========== 11 repeat and modifies the maches =============");
diag("supersmart script repeats an mods the match");
if ($^O =~ /MSWin/) {
  $cl->create_file("./bin/script.bat", 0755, "
\@echo off
rem repeat the match
echo \%\"\%hihi %CHECK_LOGFILES_SERVICEOUTPUT%\%\"\%
exit %CHECK_LOGFILES_SERVICESTATEID%
");
  $action->{script} = "script.bat";
} else {
  $cl->create_file("./bin/script.sh", 0755, "
# repeat the match
echo \"hihi \$CHECK_LOGFILES_SERVICEOUTPUT\"
exit \$CHECK_LOGFILES_SERVICESTATEID
");
}
$prescript->{options}->{smartscript} = 0;
$postscript->{options}->{smartscript} = 0;
$prescript->{options}->{supersmartscript} = 0;
$postscript->{options}->{supersmartscript} = 0;
$prescript->{script} = sub {
  printf "OK - leck mich am arsch\n";
  return 0;
};
$postscript->{script} = sub {
  printf "OK - du mich auch\n";
  return 0;
};
$action->{options}->{supersmartscript} = 1;
$action->{options}->{smartscript} = 1;
$action->{options}->{script} = 1;
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 0, 4, 0, 2));
ok($cl->{exitmessage} =~ /CRITICAL - \(4 errors\) - .*hihi .* localhost check_logfiles\[\d+\] there was an rsync error.*\.\.\./);



$cl->trace("=========== 12 heals the maches =============");
diag("supersmart script says ok to the match");
if ($^O =~ /MSWin/) {
  $cl->create_file("./bin/script.bat", 0755, "
\@echo off
rem 
echo \"ben zi bena    bluot zi bluoda\"
exit 0
");
  $action->{script} = "script.bat";
} else {
  $cl->create_file("./bin/script.sh", 0755, "
# repeat the match
echo \"ben zi bena    bluot zi bluoda\"
exit 0
");
}
$prescript->{options}->{smartscript} = 0;
$postscript->{options}->{smartscript} = 0;
$prescript->{options}->{supersmartscript} = 0;
$postscript->{options}->{supersmartscript} = 0;
$prescript->{script} = sub {
  printf "OK - leck mich am arsch\n";
  return 0;
};
$postscript->{script} = sub {
  printf "OK - du mich auch\n";
  return 0;
};
$action->{options}->{supersmartscript} = 1;
$action->{options}->{smartscript} = 1;
$action->{options}->{script} = 1;
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
#$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$action->dump_protocol();
diag($cl->has_result());   # 4xCritical =>supersmart=> 4xOK, dto 1xMissing
diag($cl->{exitmessage});
diag("aa");
ok($cl->expect_result(5, 0, 0, 0, 0)); ############ ok 17
diag("bb");
ok($cl->{exitmessage} =~ /OK -/); # 19

$cl->trace("=========== 13 heals the matches with perl =============");
diag("supersmart script says ok to the match");
$prescript->{options}->{smartscript} = 0;
$postscript->{options}->{smartscript} = 0;
$prescript->{options}->{supersmartscript} = 0;
$postscript->{options}->{supersmartscript} = 0;
$prescript->{script} = sub {
  printf "OK - leck mich am arsch\n";
  return 0;
};
$postscript->{script} = sub {
  printf "OK - du mich auch\n";
  return 0;
};
$action->{script} = sub {
  printf "so lang dads zou bis oas huit\n";
  return 0;
};
$action->{options}->{supersmartscript} = 1;
$action->{options}->{smartscript} = 1;
$action->{options}->{script} = 1;
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
#$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$action->dump_protocol();
diag($cl->has_result()); # 4xCritica =>script=>4xOK, 1xMissing dto
diag($cl->{exitmessage});
ok($cl->expect_result(5, 0, 0, 0, 0)); # 20
ok($cl->{exitmessage} =~ /OK - /);

$cl->trace("=========== 13 mods the maches with perl =============");
diag("supersmart script mods the match");
$prescript->{options}->{smartscript} = 0;
$postscript->{options}->{smartscript} = 0;
$prescript->{options}->{supersmartscript} = 0;
$postscript->{options}->{supersmartscript} = 0;
$prescript->{script} = sub {
  printf "OK - leck mich am arsch\n";
  return 0;
};
$postscript->{script} = sub {
  printf "OK - du mich auch\n";
  return 0;
};
$action->{script} = sub {
  my $params = shift;
  printf "%s%s%s\n", $params->[0], $params->[1], $params->[2];
  return 1;
};
$action->{options}->{supersmartscript} = 1;
$action->{options}->{smartscript} = 1;
$action->{options}->{script} = 1;
$action->{scriptparams} = ["hirn", "horn", '$CL_HARN$'];
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
#$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
ok($cl->expect_result(0, 5, 0, 0, 1));
ok($cl->{exitmessage} =~ /WARNING - \(5 warnings\).*hirnhornharn.*/);

$cl->trace("=========== 13 heals some matches with perl =============");
diag("supersmart heals some matches");
$prescript->{options}->{smartscript} = 0;
$postscript->{options}->{smartscript} = 0;
$prescript->{options}->{supersmartscript} = 0;
$postscript->{options}->{supersmartscript} = 0;
$prescript->{script} = sub {
  printf "OK - leck mich am arsch\n";
  return 0;
};
$postscript->{script} = sub {
  printf "OK - du mich auch\n";
  return 0;
};
$action->{script} = sub {
      my $grad = 0;
      $ENV{CHECK_LOGFILES_SERVICEOUTPUT} =~ /: (\d+) Grad/;
      $grad = $1;
      if ($grad > 30) {
        if (($ENV{CHECK_LOGFILES_DATE_MM} >= 6) &&
            ($ENV{CHECK_LOGFILES_DATE_MM} <= 8)) {
          printf "OK - ist ja schliesslich Sommer\n";
          return 0;
        } elsif (($ENV{CHECK_LOGFILES_DATE_MM} >= 11) &&
            ($ENV{CHECK_LOGFILES_DATE_MM} <= 2)) {
          printf "CRITICAL - es brennt!\n";
          return 2;
        } else {
          printf "WARNING - bisschen warm hier drin\n";
          return 1;
        }
      } else {
        printf "OK - unter 30 Grad\n";
        return 0;
      }
};
$action->{options}->{supersmartscript} = 1;
$action->{options}->{smartscript} = 1;
$action->{options}->{script} = 1;
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Thermometer: 100 Grad");
$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
$action->dump_protocol();
diag($cl->has_result());
diag($cl->{exitmessage});
my $month = (localtime)[4] + 1;
if (($month >= 6) && ($month <= 8)) {
  ok($cl->expect_result(1, 0, 0, 0, 0));
  ok($cl->{exitmessage} =~ /OK - /);
} elsif (($month >= 11) && ($month <= 2)) {
  ok($cl->expect_result(0, 0, 1, 0, 2));
  ok($cl->{exitmessage} =~ /CRITICAL - es/);
} else {
  ok($cl->expect_result(0, 1, 0, 0, 1));
  ok($cl->{exitmessage} =~ /WARNING - bisschen/);
}

# another test. postscript can output its own message which overrides
# the default format
# OK - ois rodscher in kambodscher
# CRITICAL - ois is hi
$cl->trace("=========== supersmart postscript returns ok =============");
diag("supersmart postscript says ok to the match");
$prescript->{options}->{script} = 0;
$prescript->{options}->{smartscript} = 0;
$postscript->{options}->{smartscript} = 1;
$prescript->{options}->{supersmartscript} = 0;
$postscript->{options}->{supersmartscript} = 1;
$postscript->{script} = sub {
  # oberbayern prolls
  printf "ois rodscher in kambodscher\n";
  return 0;
};
$action->{script} = sub {
  printf "so lang dads zou bis oas huit\n";
  return 0;
};
$action->{options}->{supersmartscript} = 0;
$action->{options}->{smartscript} = 0;
$action->{options}->{script} = 0;
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
#$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$action->dump_protocol();
diag($cl->has_result()); # 4xCritica =>script=>4xOK, 1xMissing dto
diag($cl->{exitmessage}); # postscript resets
ok($cl->expect_result(1, 0, 0, 0, 0)); # 26
ok($cl->{exitmessage} =~ /ois rodscher/);

# postscript with its own crtical
$cl->trace("=========== supersmart postscript returns critical =============");
diag("supersmart postscript says critical to the match");
$prescript->{options}->{script} = 0;
$prescript->{options}->{smartscript} = 0;
$postscript->{options}->{smartscript} = 1;
$prescript->{options}->{supersmartscript} = 0;
$postscript->{options}->{supersmartscript} = 1;
$postscript->{script} = sub {
  printf "ois is hi\n";
  return 2;
};
$action->{script} = sub {
  printf "so lang dads zou bis oas huit\n";
  return 0;
};
$action->{options}->{supersmartscript} = 1;
$action->{options}->{smartscript} = 1;
$action->{options}->{script} = 1;
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
#$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$action->dump_protocol();
diag($cl->has_result()); # 4xCritica =>script=>4xOK, 1xMissing dto
diag($cl->{exitmessage}); # postscript resets
ok($cl->expect_result(0, 0, 1, 0, 2)); # 28
ok($cl->{exitmessage} =~ /ois is hi/);

# postscript which copies the generated output but raises the level
$cl->trace("=========== supersmart postscript returns critical =============");
diag("supersmart postscript copies results found so far");
$prescript->{options}->{script} = 0;
$prescript->{options}->{smartscript} = 0;
$postscript->{options}->{smartscript} = 1;
$prescript->{options}->{supersmartscript} = 0;
$postscript->{options}->{supersmartscript} = 1;
$postscript->{script} = sub {
  printf "%s", $ENV{CHECK_LOGFILES_SERVICEOUTPUT};
  return $ENV{CHECK_LOGFILES_SERVICESTATEID};
};
$action->{script} = sub {
  printf "so lang dads zou bis oas huit\n";
  return 0;
};
$action->{options}->{supersmartscript} = 1; 
$action->{options}->{smartscript} = 1;
$action->{options}->{script} = 0; ### do not clear the error lines
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
#$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$action->dump_protocol();
diag($cl->has_result()); # 4xCritica =>script=>4xOK, 1xMissing dto
diag($cl->{exitmessage}); # postscript resets
ok($cl->expect_result(0, 0, 1, 0, 2)); # 30
ok($cl->{exitmessage} =~ /CRITICAL - /);

# postscript with its own crtical
$cl->trace("=========== supersmart postscript returns critical =============");
diag("supersmart postscript says critical to the match");
$prescript->{options}->{script} = 0;
$prescript->{options}->{smartscript} = 0;
$postscript->{options}->{smartscript} = 1;
$prescript->{options}->{supersmartscript} = 0;
$postscript->{options}->{supersmartscript} = 1;
$postscript->{script} = sub {
  printf STDERR "huhi: %s\n", $ENV{CHECK_LOGFILES_SERVICEOUTPUT};
  printf STDERR "hihi: %s\n", $ENV{CHECK_LOGFILES_SERVICEPERFDATA};
  printf "ois is hi |%s\n", $ENV{CHECK_LOGFILES_SERVICEPERFDATA};
  return 2;
};
$action->{script} = sub {
  printf "so lang dads zou bis oas huit\n";
  return 0;
};
$action->{options}->{supersmartscript} = 1;
$action->{options}->{smartscript} = 1;
$action->{options}->{script} = 0;
$cl->reset();
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 1, "Ici le DEBUT ");
$action->loggercrap(undef, undef, 100);
$action->logger(undef, undef, 4, "there was an rsync error");
$action->logger(undef, undef, 40, "the total size is 0 hihi");
#$action->logger(undef, undef, 1, "Et le FIN de l'histoire");
sleep 1;
$cl->run();
#$action->dump_protocol();
diag($cl->has_result()); # 4xCritica =>script=>4xOK, 1xMissing dto
diag($cl->{exitmessage}); # postscript resets
ok($cl->expect_result(0, 0, 1, 0, 2)); # 32
ok($cl->{exitmessage} =~ /ois is hi/ && $cl->{perfdata} =~ /smart_criticals=5 .*/);


# an supersmart postscript wird der komplette serviceoutput geliefert
# dieser beinhaltet insbes. die performance data
# da der output des postscript als 1:1 gesamtoutput genommen wird, ist
# der script-autor verantwortlich, daﬂ performancedaten angeh‰ngt werden.



# check command line
my $perlpath = `which perl`;
chomp $perlpath;
$configfile = "";
if ($^O =~ /MSWin/) {
 if (-f 'C:\strawberry\perl\bin\perl.exe') {
  $perlpath = 'C:\strawberry\perl\bin\perl';
 } else {
  $perlpath = 'C:\Perl\bin\perl';
 }
$configfile = <<EOCFG;
\$seekfilesdir = "./var/tmp";
\$scriptpath = "./bin";
\$MACROS = {
  CL_NSCA_HOST_ADDRESS => 'nagios.dierichs.de',
  CL_NSCA_PORT => 5555,
};
\@searches = (
    {
      tag => "action",
      logfile => "./var/adm/messages",
      criticalpatterns => [ 
             '.*ERROR.*', ],
             options => 'supersmartscript',
             script => "send_nsca.bat",
             scriptparams => '-H \$CL_NSCA_HOST_ADDRESS\$ -p \$CL_NSCA_PORT\$ -to \$CL_NSCA_TO_SEC\$ -c \$CL_NSCA_CONFIG_FILE\$',
             scriptstdin => '\$CL_HOSTNAME\$\\t\$CL_SERVICEDESC\$\\t\$CL_SERVICESTATEID\$\\t\$CL_SERVICEOUTPUT\$\\n',
    });
EOCFG
  $cl->create_file("./bin/send_nsca.bat", 0755, "
\@echo off
if \"%1%2%3%4\" == \"-Hnagios.dierichs.de-p5555\" GOTO :good
echo bad
exit 2
:good
echo good
exit 0
");
} else {
$configfile = <<EOCFG;
\$seekfilesdir = "./var/tmp";
\$scriptpath = "./bin";
\$MACROS = {
  CL_NSCA_HOST_ADDRESS => 'nagios.dierichs.de',
  CL_NSCA_PORT => 5555,
};
\@searches = (
    {
      tag => "action",
      logfile => "./var/adm/messages",
      criticalpatterns => [ 
             '.*ERROR.*', ],
             options => 'supersmartscript',
             script => "send_nsca",
             scriptparams => '-H \$CL_NSCA_HOST_ADDRESS\$ -p \$CL_NSCA_PORT\$ -to \$CL_NSCA_TO_SEC\$ -c \$CL_NSCA_CONFIG_FILE\$',
             scriptstdin => '\$CL_HOSTNAME\$\\t\$CL_SERVICEDESC\$\\t\$CL_SERVICESTATEID\$\\t\$CL_SERVICEOUTPUT\$\\n',
    });
EOCFG
  $cl->create_file("./bin/send_nsca", 0755, "
echo i am the script with \"\$*\"
if [ \"\$1\" = \"-H\" ] && [ \"\$2\" = \"nagios.dierichs.de\" ] && [ \"\$3\" = \"-p\" ] && [ \"\$4\" = \"5555\" ]; then
echo good
exit 0;
else
echo bad
exit 2
fi
");
}
diag ("create check_action.cfg");
open CCC, ">./etc/2check_action.cfg";
print CCC $configfile;
close CCC;

my $xcl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/2check_action.cfg" });
$xcl->delete_file("./var/tmp/scriptcounter");
$action = $xcl->get_search_by_tag("action");
my $output = `$perlpath ../plugins-scripts/check_logfiles -f ./etc/2check_action.cfg`;
diag ("reset run: ".$output);
$action->loggercrap(undef, undef, 10);
$action->logger(undef, undef, 1, "building file list ... done");
$action->logger(undef, undef, 10, "a ERROR hoho");
$action->loggercrap(undef, undef, 10);
# this is the important part. if the script got the expected parameters
# it remedies the matches
$output = `$perlpath ../plugins-scripts/check_logfiles -f ./etc/2check_action.cfg`;
diag ("real run: ".$output);
ok($output =~ /OK/);

$configfile = <<EOCFG;
\$seekfilesdir = "./var/tmp";
\$scriptpath = "./bin";
\$options = "supersmartpostscript";
\@searches = (
    {
      tag => "smart",
      logfile => "./var/adm/messages",
      criticalpatterns => [
             '.*connection unexpectedly closed.*',
             '.*rsync error.*',
             'Thermometer',
         ],
         warningpatterns => [
             '.*total size is 0 .*',
         ],
    });
\$postscript = sub {
  print "0";
  return 0;
};

EOCFG
unlink "./etc/check_null.cfg";
open CCC, ">./etc/check_null.cfg";
print CCC $configfile;
close CCC;

diag("postscript returns 0");
my $ycl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_null.cfg" });
$action = $ycl->get_search_by_tag("smart");
$postscript = $ycl->get_search_by_tag("postscript");
$ycl->reset();
$action->delete_logfile();
$action->delete_seekfile();
$action->trace("deleted logfile and seekfile");
$ycl->run();
sleep 1;
$ycl->reset();
$action->logger(undef, undef, 1, "rsync error");
diag("now run");
$action->trace("now postscript returns the string 0");
$ycl->run();
diag("result should be \"0\"");
diag($ycl->has_result());
diag($ycl->{exitmessage});
ok($ycl->expect_result(1, 0, 0, 0, 0));
ok($ycl->{exitmessage} eq "0");

$configfile = <<EOCFG;
\$seekfilesdir = "./var/tmp";
\$scriptpath = "./bin";
\$options = "supersmartpostscript";
\@searches = (
    {
      tag => "smart",
      logfile => "./var/adm/messages2",
      criticalpatterns => [
             '.*rsync error.*',
         ],
    });
\$postscript = sub {
  # return undefined message
  return 0;
};

EOCFG
open CCC, ">./etc/check_kaas.cfg";
print CCC $configfile;
close CCC;

diag("postscript returns nothing");
$action = undef;
$postscript = undef;
my $zcl = Nagios::CheckLogfiles::Test->new({ cfgfile => "./etc/check_kaas.cfg" });
$action = $zcl->get_search_by_tag("smart");
$postscript = $zcl->get_search_by_tag("postscript");
$zcl->reset();

$action->delete_logfile();
$action->delete_seekfile();
$action->trace("deleted logfile and seekfile");
$zcl->run();
sleep 1;
$zcl->reset();
$action->logger(undef, undef, 1, "rsync error");
diag("now run");
$zcl->run();
diag($zcl->has_result());
diag($zcl->{exitmessage});
ok($zcl->expect_result(1, 0, 0, 0, 0));
ok($zcl->{exitmessage} eq "postscript");

