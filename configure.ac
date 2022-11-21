AC_REVISION ($Revision: 1.150 $)
AC_PREREQ(2.58)
AC_INIT(check_logfiles,4.1.1)
AM_MAINTAINER_MODE([disable])
AM_INIT_AUTOMAKE
AC_CANONICAL_HOST

RELEASE=1
AC_SUBST(RELEASE)

AC_PREFIX_DEFAULT(/usr/local/nagios)

dnl Figure out how to invoke "install" and what install options to use.
AC_PROG_INSTALL
AC_SUBST(INSTALL)

dnl AC_PROG_CC
dnl AC_PROG_CPP
dnl AC_PROG_GCC_TRADITIONAL
dnl AC_PROG_RANLIB

AC_PROG_MAKE_SET

WARRANTY="This plugin comes with ABSOLUTELY NO WARRANTY. You may redistribute\ncopies of the plugin under the terms of the GNU General Public License.\nFor more information about these matters, see the file named COPYING.\n"
AC_SUBST(WARRANTY)

SUPPORT="Send email to gerhard.lausser@consol.de if you have questions\nregarding use of this software.\nPlease include version information with all correspondence (when possible,\nuse output from the --version option of the plugin itself).\n"
AC_SUBST(SUPPORT)

AC_ARG_WITH(nagios_user,
  ACX_HELP_STRING([--with-nagios-user=USER],
    [set user name to run nagios]),
  with_nagios_user=$withval,
  with_nagios_user=nagios)
AC_ARG_WITH(nagios_group,
  ACX_HELP_STRING([--with-nagios-group=GROUP],
    [set group name to run nagios]),
  with_nagios_group=$withval,
  with_nagios_group=nagios)
AC_SUBST(with_nagios_user)
AC_SUBST(with_nagios_group)
INSTALL_OPTS="-o $with_nagios_user -g $with_nagios_group"
AC_SUBST(INSTALL_OPTS)

case "$host_os" in 
  *hp*)
    defaulttrustedpath=/bin:/sbin:/usr/bin:/usr/sbin:/usr/contrib/bin
    ;;
  *)
    defaulttrustedpath=/bin:/sbin:/usr/bin:/usr/sbin
    ;;
esac

AC_ARG_WITH(seekfiles_dir,
  ACX_HELP_STRING([--with-seekfiles-dir=PATH],
    [sets directory for the state files (default=/tmp)]),
  with_seekfiles_dir=$withval,
  with_seekfiles_dir=/var/tmp/check_logfiles)
AC_SUBST(SEEKFILES_DIR, $with_seekfiles_dir)
echo variable with_seekfiles_dir is $with_seekfiles_dir

AC_ARG_WITH(protocols_dir,
  ACX_HELP_STRING([--with-protocols-dir=PATH],
    [sets directory for the protocol files (default=/tmp)]),
  with_protocols_dir=$withval,
  with_protocols_dir=/tmp)
AC_SUBST(PROTOCOLS_DIR, $with_protocols_dir)

AC_ARG_WITH(trusted_path,
  ACX_HELP_STRING([--with-trusted-path=PATH],
    [sets trusted path for executables called by scripts (default=/bin:/sbin:/usr/bin:/usr/sbin)]),
  with_trusted_path=$withval,
  with_trusted_path=$defaulttrustedpath)
AC_SUBST(TRUSTED_PATH, $with_trusted_path)

EXTRAS=
dnl PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/etc:/usr/local/bin:/usr/local/sbin:$PATH

dnl Checks for programs.
AC_PATH_PROG(SH,sh)
AC_PATH_PROG(PERL,perl)
AC_PATH_PROG(GZIP,gzip)
AC_PATH_PROGS(AWK,gawk nawk /usr/xpg4/bin/awk awk)
AC_PATH_PROG(ECHO,echo)
AC_PATH_PROG(SED,sed)
AC_PATH_PROG(CAT,cat)

dnl allow them to override the path of perl
AC_ARG_WITH(perl,
  ACX_HELP_STRING([--with-perl=PATH],
    [sets path to perl executable]),
  with_perl=$withval,with_perl=$PERL)
AC_SUBST(PERL, $with_perl)

dnl allow them to override the path of gzip
AC_ARG_WITH(gzip,
  ACX_HELP_STRING([--with-gzip=PATH],
    [sets path to gzip executable]),
  with_gzip=$withval,with_gzip=$GZIP)
AC_SUBST(GZIP, $with_gzip)


AC_OUTPUT(Makefile plugins-scripts/Makefile plugins-scripts/subst t/Makefile)

ACX_FEATURE([with],[perl])
ACX_FEATURE([with],[gzip])
ACX_FEATURE([with],[seekfiles-dir])
ACX_FEATURE([with],[protocols-dir])
ACX_FEATURE([with],[trusted-path])
ACX_FEATURE([with],[nagios-user])
ACX_FEATURE([with],[nagios-group])
