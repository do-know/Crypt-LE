#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp ();
use Crypt::LE ':errors';
$|=1;
plan tests => 19;

my $le = Crypt::LE->new(autodir => 0);

can_ok($le, 'load_account_key');
can_ok($le, 'generate_account_key');
can_ok($le, 'account_key');
can_ok($le, 'load_csr');
can_ok($le, 'generate_csr');
can_ok($le, 'csr');
can_ok($le, 'csr_key');
can_ok($le, 'set_account_email');

my $fh = File::Temp->new(SUFFIX => '.le', UNLINK => 1, EXLOCK => 0);

ok($le->load_account_key($fh->filename) == READ_ERROR, 'loading non-existent key');

my $rv = $le->generate_account_key();
my $acceptable_rv = ($rv == OK or $rv == INVALID_DATA) ? 1 : 0;
ok($acceptable_rv == 1, 'generating account key');

# Make sure usable key is generated
if ($rv) {
	while ($le->generate_account_key()) {}
}
ok($le->account_key, 'getting account key');

print $fh $le->account_key;
$fh->flush;
ok($le->load_account_key($fh->filename) == OK, "reloading account key");

$fh = File::Temp->new(SUFFIX => '.le', UNLINK => 1, EXLOCK => 0);

ok($le->load_csr($fh->filename) == READ_ERROR, 'loading non-existent CSR');

SKIP: {

    eval { require Crypt::OpenSSL::PKCS10 };

    skip "Crypt::OpenSSL:PKCS10 is not installed, skipping CSR generation tests.", 6 if $@;

    ok($le->generate_csr() == INVALID_DATA, 'generating CSR without providing domain names');

    ok($le->generate_csr('odd.domain') == OK, 'generating CSR for one domain');

    ok($le->generate_csr('odd.domain,another.domain,yet.another.domain') == OK, 'generating CSR for multiple domains');

    ok($le->csr, 'retrieving generated CSR');

    ok($le->csr_key(), 'retrieving the key used for CSR');

    print $fh $le->csr;
    $fh->flush;
    ok($le->load_csr($fh->filename) == OK, 'reloading CSR');

}

diag( "Testing Crypt::LE $Crypt::LE::VERSION, Setup methods, $^X" );
