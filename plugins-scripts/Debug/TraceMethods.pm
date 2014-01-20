package Devel::TraceMethods;

use strict;

use vars '$VERSION';
$VERSION = '1.00';

sub import
{
	my $package = shift;

	while (@_)
	{
		my $traced = shift;
		my $logger = ref $_[0] eq 'CODE' && defined &{ $_[0] } ? shift : undef;
		_wrap_symbol( $traced, $logger );
	}
}

sub _wrap_symbol
{
	my ($traced, $logger) = @_;
	my $src;

	# get the calling package symbol table name
	{
		no strict 'refs';
		$src = \%{ $traced . '::' };
	}

	# loop through all symbols in calling package, looking for subs
	for my $symbol ( keys %$src )
	{
		# get all code references, make sure they're valid
		my $sub = *{ $src->{$symbol} }{CODE};
		next unless defined $sub and defined &$sub;

		# save all other slots of the typeglob
		my @slots;

		for my $slot (qw( SCALAR ARRAY HASH IO FORMAT ))
		{
			my $elem = *{ $src->{$symbol} }{$slot};
			next unless defined $elem;
			push @slots, $elem;
		}

		# clear out the source glob
		undef $src->{$symbol};

		# replace the sub in the source
		$src->{$symbol} = sub
		{
			my @args = @_;
			_log_call->( 
				name   => "${traced}::$symbol",
				logger => $logger,
				args   => [ @_ ]
			);
			return $sub->(@_);
		};

		# replace the other slot elements
		for my $elem (@slots)
		{
			$src->{$symbol} = $elem;
		}
	}
}

{
	my $logger = sub { require Carp; Carp::carp( join ', ', @_ ) };

	# set a callback sub for logging
	sub callback
	{
		# should allow this to be a class method :)
		shift if @_ > 1;

		my $coderef = shift;
		unless( ref($coderef) eq 'CODE' and defined(&$coderef) )
		{
			require Carp;
			Carp::croak( "$coderef is not a code reference!" );
		}

		$logger = $coderef;
	}

	# where logging actually happens
	sub _log_call
	{
		my %args    = @_;
		my $log_sub = $args{logger} || $logger;

		$log_sub->( $args{name}, @{ $args{args} });
	}
}

1;
