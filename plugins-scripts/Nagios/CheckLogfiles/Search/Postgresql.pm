package Nagios::CheckLogfiles::Search::Postgresql;

=head1 NAME

Nagios::CheckLogfiles::Postgresql - Postgresql extension for check_logfiles.

=head1 METHODS

=over 4

=cut

use strict;
use Exporter;
use Params::Validate qw(validate :types);
use vars qw(@ISA);

=head2 B<getSearch()> Create a check_logfiles search hash for Postgresql

This method creates a check_logfiles search hash containing all necessary data for

check_logfiles to perform Postresql logfile checking. The search hash returned here

will take into account the log format prefix definition and will match exactly from the first

occurrence of given log format prefix definition just before the next one.

It is then checked for the position of "%e" within the format definition which represents

the SQL state. Any value other than "00000" will raise an error.

B<Return values>

=over 4

A search hash as required by check_logfiles searches.

=back

B<Attributes>

The following attributes are not given as HASH but sequentially, in the order described below.

=over 4

=item B<tag> - the search tag used for chack_logfiles searches

=item B<logfile> - the logfile to be checked

=item B<logLinePrefix> - the log line prefix definition

=back

=cut

sub getSearch() {
    my $self = shift;

    my ( $tag, $logfile, $postgresLoglinePrefix ) = @_;

    # use compiled log postgresql log prefix as multiline-start recognition pattern
    #
    my $multilinestartpattern = $self->_postgresqlFormatToPattern( logLinePrefix => $postgresLoglinePrefix );
    
    return ( {
            tag                   => "$tag",
            multiline             => 1,
            multilinestartpattern => $multilinestartpattern,
            logfile               => "$logfile",
            criticalpatterns      => [ ".*" ],
            options               => 'script,supersmartscript',
            scriptparams          => "$multilinestartpattern",
            script                => sub {
                
                my $multilinestartpattern = shift;
                my $matchedOutput    = $ENV{CHECK_LOGFILES_MATCHEDOUTPUT};
                chomp( $matchedOutput );

                # get the sql state
                # this is the first matching group
                # TODO fine tune matching groups to get sqlstate, message, date... etc
                # TODO implement named groups if available (Perl 5.10+)
                #
                my $sqlState = "00000";

                if ( $matchedOutput =~ /$multilinestartpattern/ ) {
                    $sqlState = $1;
                }

                # print plugin output
                #
                print( $matchedOutput );

                # any other sql state than "00000" will result in critical(2) plugin return value
                #
                if ( $sqlState ne "00000" ) {
                    return 2;
                }

                return 0;
            }
        } );
}

=head2 B<_postgresqlFormatToPattern()> Get a pattern for a postgresql log prefix format

This method transforms a given postgresql log prefix format string into a regex pattern

which can be used to identify log lines within a postgresql log file. The only matching

group will be placed around "%e" substitution, so that the SQL state can be matched with

the returned substituted pattern.

The following substitutions are used:

     format  | description                                         | substitution
    ---------+-----------------------------------------------------+--------------
       %a    | Application name                                    | \S+
       %u    | User name                                           | \S+
       %d    | Database name                                       | \S+
       %r    | Remote host name or IP address, and remote port     | \S+:\d+
       %h    | Remote host name or IP address                      | \S+
       %p    | Process ID                                          | \d+
       %t    | Time stamp without milliseconds                     | \d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2} \S+
       %m    | Time stamp with milliseconds                        | \d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \S+
       %i    | Command tag: type of session's current command      | \S+
       %e    | SQLSTATE error code                                 | (\S{5})
       %c    | Session ID: see below                               | \S\S\.\S\S
       %l    | Number of the log line for each session or process, | \d+ 
             | starting at 1                                       |
       %s    | Process start time stamp                            | \d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2} \S+
       %v    | Virtual transaction ID (backendID/localXID)         | \d+
       %x    | Transaction ID (0 if none is assigned)              | \d+
       %q    | Produces no output, but tells non-session processes | <empty string>, but everything after will be 
             | to stop at this point in the string;                | made an optional match -> (...)?
             | ignored by session processes                        | 
       %%    | Literal %                                           | %

Additionally all regex specific characters will be escaped.

B<Return values>

=over 4

The pattern which can be used to identify log lines

=back

B<Attributes>

=over 4

=item B<logLinePrefix> - the log line prefix definition to transform

=back

=cut

sub _postgresqlFormatToPattern {
    my $self = shift;

    my %attributes = validate( @_, { logLinePrefix => { type => SCALAR } } );

    my $pattern = $attributes{'logLinePrefix'};

    # escape regex specific characters
    #
    $pattern =~ s/([\?\-\+\.\(\)\[\]\{\}\*\^\$])/\\$1/g;

    # substitutions
    #
    $pattern =~ s/%[audhi]/\\S+/g;

    $pattern =~ s/%[plvx]/\\d+/g;

    $pattern =~ s/%r/\\S+:\\d+/g;

    $pattern =~ s/%[ts]/\\d{4}\\-\\d{2}\\-\\d{2} \\d{2}:\\d{2}:\\d{2} \\S+/g;

    $pattern =~ s/%m/\\d{4}\\-\\d{2}\\-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d+ \\S+/g;

    $pattern =~ s/%c/\\S\\S\\.\\S\\S/g;

    $pattern =~ s/%%/%/g;

    $pattern =~ s/%e/(\\S{5})/g;

    # handle "%q"
    # everything after this is an optional match
    #
    $pattern =~ s/%q(.+)$/($1)?/g;

    return $pattern;
}

=back

=cut

1;
