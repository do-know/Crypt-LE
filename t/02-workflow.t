#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp ();
use Crypt::LE ':errors';
$|=1;
plan tests => 10;

my $le = Crypt::LE->new(autodir => 0);

can_ok($le, 'directory');
can_ok($le, 'register');
can_ok($le, 'accept_tos');
can_ok($le, 'request_challenge');
can_ok($le, 'accept_challenge');
can_ok($le, 'verify_challenge');
can_ok($le, 'request_certificate');
can_ok($le, 'request_issuer_certificate');
can_ok($le, 'revoke_certificate');

# We don't want to ship the same account key to everyone with this module and
# we don't really want to pollute Let's Encrypt staging server with multiple odd
# registrations, so just making sure that interaction works.

# Account for the fact that some test boxes return 'Network is unreachable'.
my $rv = ($le->directory() == OK or $le->error_details=~/\bunreachable\b/i) ? 1 : 0;
ok($rv == 1, 'loading resources directory - ' . $le->error_details);

diag( "Testing Crypt::LE $Crypt::LE::VERSION, Workflow methods, $^X" );
