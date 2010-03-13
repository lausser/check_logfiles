## Process this file with automake to produce Makefile.in

# find . \( -type d -and -name .svn -and -prune \) -or -type f -exec fromdos -v {} \;

SUBDIRS = plugins-scripts t
EXTRA_DIST = winconfig.pl README.exe

dist-hook:
	rm -f t/var/tmp/*
	rm -f t/var/adm/*
	find $(distdir) -depth -name .svn -exec rm -rf {} \;
	find $(distdir) -type f -exec fromdos -v {} \;
	make

exe:
	 pp -M PerlIO -M Digest::MD5 -M Encode::Encoding -M Encode::Unicode -M Encode::Unicode::UTF7 -M Net::Domain -M Win32::Daemon -o check_logfiles.exe check_logfiles
