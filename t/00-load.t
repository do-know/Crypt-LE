#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Crypt::LE' ) || print "Bail out!\n";
}

diag( "Testing Crypt::LE $Crypt::LE::VERSION, Perl $], $^X" );
