#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;
use Crypt::LE ':errors';
$|=1;
plan tests => 8;

my $le = Crypt::LE->new(autodir => 0);

can_ok($le, 'ca_list');
can_ok($le, 'ca_supported');
can_ok($le, 'ca_supported_staging');

ok($le->ca_list() == 5, 'Checking the number of supported CAs');
ok(!$le->ca_supported('unknown'), 'Checking for unknown CA');
ok($le->ca_supported('zerossl.com'), 'Checking for the supported CA');
ok(!$le->ca_supported_staging('zerossl.com'), 'Checking for the supported CA with no staging environment');
ok($le->ca_supported_staging('google.com'), 'Checking for the supported CA with staging environment');

diag( "Testing Crypt::LE $Crypt::LE::VERSION, Utility methods, $^X" );
