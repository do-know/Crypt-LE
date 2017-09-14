#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;
use Crypt::LE ':errors';
$|=1;
plan tests => 15;

my $le = Crypt::LE->new(autodir => 0);

can_ok($le, 'directory');
can_ok($le, 'register');
can_ok($le, 'accept_tos');
can_ok($le, 'update_contacts');
can_ok($le, 'request_challenge');
can_ok($le, 'accept_challenge');
can_ok($le, 'verify_challenge');
can_ok($le, 'request_certificate');
can_ok($le, 'request_issuer_certificate');
can_ok($le, 'revoke_certificate');

SKIP: {

    # Skip the test if environment tells us to (check all variations Debian rules suggest)
    skip "Environment is configured with no network tests enabled, skipping CA resources testing", 1 if 
	($ENV{'NO_NETWORK_TESTING'} || $ENV{'NO_NETWORK'} || $ENV{'NOINTERNET'} || 
	 (defined $ENV{'CONNECTED_TO_NET'} && !$ENV{'CONNECTED_TO_NET'}) ||
         (defined $ENV{'HAVE_INTERNET'} && !$ENV{'HAVE_INTERNET'})
        );
    # We don't want to ship the same account key to everyone with this module and
    # we don't really want to pollute Let's Encrypt staging server with multiple odd
    # registrations, so just making sure that interaction works.

    # Account for the fact that some test boxes return 'Network is unreachable' and that staging API might be down.
    my $rv = ($le->directory() == OK or $le->error_details=~/\b(?:unreachable|<HTML>|known|timed?)\b/i) ? 1 : 0;
    ok($rv == 1, 'Loading resources directory ' . $le->error_details);

}

$le->set_domains('x.dom, y.dom, z.dom');
$le->{'domains'}->{'y.dom'} = 0;
$le->{'domains'}->{'z.dom'} = 1;
$le->{'failed_domains'} = [ [ qw<a.dom b.dom> ], undef ];

ok(@{$le->domains()} == 3, 'Checking the domains list');
ok(!defined $le->failed_domains(), 'Checking failed domains on the last verification call');
ok(@{$le->failed_domains(1)} == 2, 'Checking failed domains on any verification call');
ok(@{$le->verified_domains()} == 1, 'Checking verified domains');

diag( "Testing Crypt::LE $Crypt::LE::VERSION, Workflow methods, $^X" );
