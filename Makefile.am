## Process this file with automake to produce Makefile.in

# find . \( -type d -and -name .svn -and -prune \) -or -type f -exec fromdos -v {} \;

SUBDIRS = plugins-scripts t
EXTRA_DIST = winconfig.pl README.windows-exe

dist-hook:
	rm -f t/var/tmp/*
	rm -f t/var/adm/*
	find $(distdir) -type f -exec dos2unix {} \;
	make

exe:
	 pp -M PerlIO -M Digest::MD5 -M Encode::Encoding -M Encode::Unicode -M Encode::Unicode::UTF7 -M Net::Domain -M Win32::Daemon -o check_logfiles.exe check_logfiles
