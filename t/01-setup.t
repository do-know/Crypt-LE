#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Temp ();
use Crypt::LE ':errors', ':keys';
$|=1;
plan tests => 59;

my $le = Crypt::LE->new(autodir => 0);
sub line { my $l = shift; $l=~s/[\r\n]//sg if $l; $l }
my $usable_csr = <<EOF;
-----BEGIN CERTIFICATE REQUEST-----
MIIC1TCCAb0CAQAwTzEcMBoGA1UEAxMTZXhhbXBsZS5ub25leGlzdGVudDEKMAgG
A1UEChMBLTEKMAgGA1UECxMBLTEKMAgGA1UECBMBLTELMAkGA1UEBhMCVVMwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDwTa2Kz/csjU/YztvvY/cDAWoa
WGzLTFQw2VVgPMCfn7aF8BoLJRP1XmEIruP0gPWD4zA02Tjs/p+uho0hRY91nnIK
9Oqx2PICjULwK0C8LMeKLzbTQd3o93uuEjKUsfoa/IelCCpRPB4sMb2BKAevhDKX
uPjA788ro/bNyU9CyUg8wRGwTauKVaJ4Ce5KXzyHReNa9OuMSWR/jWKWeqEoZaX/
UXHdW8/0OI815MeFpKmez4154r9vCyawSXl+951teht9HY1yKRTBaCqWHfnhy4Al
xUqN5Hiy9iUv6XnRUi9RUxYNMgoQfYXtTNi2QSIRjGrPYTlUi+IR7FEEGzdhAgMB
AAGgQTA/BgkqhkiG9w0BCQ4xMjAwMB4GA1UdEQQXMBWCE2V4YW1wbGUubm9uZXhp
c3RlbnQwDgYDVR0PAQH/BAQDAgWgMA0GCSqGSIb3DQEBCwUAA4IBAQAyKPIWXHrO
7D3J8b2uQDQERTLO3XLbc1igxjyQmuYCZX0jx6/qTLgQOOfjMxJ61AvhPOYS9aBy
4m+4udhF84QdpKgiQ7NOc+awDNBHxZesn84ujel+7PnIYAdNm2d+Qr2T5nt8mkYF
uRVbkldUTT0GL4nwZ+sCU09oU6ixZpmgUsQds0lZfXCv4mNmZt9+i82MV5IHSwoY
zXVkNsHweYs9HwAQAjbDAGRm73b+LGnPYw17GKm07r2VXwG8pgeApkeHr0tF24pc
R06FcYX9VACUdVRMnA+14IdMASxBNCnvkMWXIGcv95FgGbbKsWuJCsK1sLbu3tSI
QyQDVLXAeOwn
-----END CERTIFICATE REQUEST-----
EOF
my $invalid_csr = <<EOF;
-----BEGIN CERTIFICATE REQUEST-----
MIICxTCCAa0CAQAwRzEUMBIGA1UEAxMLMTI3LjAuMC4yNTUxCjAIBgNVBAoTAS0x
CjAIBgNVBAsTAS0xCjAIBgNVBAgTAS0xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8E2tis/3LI1P2M7b72P3AwFqGlhsy0xUMNlV
YDzAn5+2hfAaCyUT9V5hCK7j9ID1g+MwNNk47P6froaNIUWPdZ5yCvTqsdjyAo1C
8CtAvCzHii8200Hd6Pd7rhIylLH6GvyHpQgqUTweLDG9gSgHr4Qyl7j4wO/PK6P2
zclPQslIPMERsE2rilWieAnuSl88h0XjWvTrjElkf41ilnqhKGWl/1Fx3VvP9DiP
NeTHhaSpns+NeeK/bwsmsEl5fvedbXobfR2NcikUwWgqlh354cuAJcVKjeR4svYl
L+l50VIvUVMWDTIKEH2F7UzYtkEiEYxqz2E5VIviEexRBBs3YQIDAQABoDkwNwYJ
KoZIhvcNAQkOMSowKDAWBgNVHREEDzANggsxMjcuMC4wLjI1NTAOBgNVHQ8BAf8E
BAMCBaAwDQYJKoZIhvcNAQELBQADggEBALAXJluj0/eSgeh6fVefdiBdtKGqwoaf
EoVVqdk2X9+gOvLNNF/pBjKzZx/HCtQw7a1b4SVfh72x0voTdJ11w4+AErNEI040
HzTKHvCvc5eZoLygOagciCF1+TewJhHy3FdhkeD8mXn992bKuUwIbOmf7KfNaft9
PtY2ihVCoJGfiz7ikzhgvCjzAQgfxQNa+Wp/KV2N4/HoahkCTKyGrkHB+PLtqrzu
O8ho4q67zQLiOttwCQzc+SL9laMCGj3BjLK3EqUlROpTOkMd0IldRogDcQRvy5qC
6Tvdy33/JFev++ZEaLY/M2h3QYbc5fgkll5YDeiO8etS4u8OkRCgU74=
-----END CERTIFICATE REQUEST-----
EOF
my $usable_crt = <<EOF;
-----BEGIN CERTIFICATE-----
MIIDQjCCAiqgAwIBAgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwkxMjcu
MC4wLjEwHhcNMTcwNzAyMDgyMTMxWhcNMjcwNzAyMDgyMTMxWjAUMRIwEAYDVQQD
EwkxMjcuMC4wLjEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCE/+lh
oJdbkJmJbVRjIg05+xd29n7hz4SI19xio6e0kuvnxnLBS/rCeuLHeVa7n3gQPHhd
GmL5fJ5k4r8m7XVoTKwQgxPyO4Hl/C1STyUraBHc0364xLJWa2KmO/GVjpAN/k0r
9Ce0NdC8A0TJwhRrK8t3DDFsti5BwzYmIWHo7TKyZ7Og1onp7zOlR7LJEsKYyst/
sLD+HonbGvRcnEzD+Mw/OPK7R7jkQRxnEj/aqudLjPj8jZGoBkWkhCe+GqvKCMQ0
DerudsKvVP841vgB7qSBGLHHR4qUzXA2nUGGzjefE+AfV/bo3n8yq214rjdtLnh1
a3oRWgwczNdy+8aRAgMBAAGjgZ4wgZswDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMC
AvQwOwYDVR0lBDQwMgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYB
BQUHAwQGCCsGAQUFBwMIMBEGCWCGSAGG+EIBAQQEAwIA9zAPBgNVHREECDAGhwR/
AAABMB0GA1UdDgQWBBT+VuObL4pkhRyqiMte1EM0henL3TANBgkqhkiG9w0BAQsF
AAOCAQEAYUhEzIjcaVohCB9ciB0FdISxvtJjAL3Z3ST+kBbGDQFp9gs7wmHj1ERu
KZ1LDNOjyfWhX9UozogSyfdwEn6k/FZ3Mwy5c7ArsDX0U7EKHdJ1NYbU+P5GTex6
CJBZn8EZ+UxORyjuctrOcVnHPHTuzUHFwnhH62rQ0pokyrFZXi4L2JzZVCfb3Xox
YMG38g4jGU9eZ+2Jpxva7VgNNUVD9PbBNPW6J0h3at7bW98aTOnonQnhlmSDVA61
Qqmp0jDrGOtOIXuOdkYUsnLj5ESajat67g0PxxxDbbk4UTzCYjXuXjy+tFDYEVuV
lb+XMDEx0bcHpBoS1eYjGzNayJugag==
-----END CERTIFICATE-----
EOF

can_ok($le, 'load_account_key');
can_ok($le, 'generate_account_key');
can_ok($le, 'account_key');
can_ok($le, 'load_csr');
can_ok($le, 'generate_csr');
can_ok($le, 'csr');
can_ok($le, 'csr_key');
can_ok($le, 'set_account_email');
can_ok($le, 'set_domains');
can_ok($le, 'export_pfx');

my $fh = File::Temp->new(SUFFIX => '.le', UNLINK => 1, EXLOCK => 0);

ok($le->set_domains() == INVALID_DATA, 'Setting domain names with no value');
ok($le->set_domains('http://some.domain') == INVALID_DATA, 'Setting domain names with unsupported entity type (URI)');
ok($le->set_domains('10.0.0.100') == INVALID_DATA, 'Setting domain names with unsupported entity type (IP)');
ok($le->set_domains('a@b.c') == INVALID_DATA, 'Setting domain names with unsupported entity type (email)');
ok($le->set_domains('abc') == INVALID_DATA, 'Setting domain names with unsupported entity type (dotless name)');
ok($le->set_domains('*.domain.example') == INVALID_DATA, 'Setting domain names with unsupported entity type (wildcard)');
ok($le->set_domains('a.dom, b.dom') == OK, 'Setting domain names with a string');
ok($le->set_domains([ qw<a.dom b.dom x.dom> ]) == OK, 'Setting domain names with an array ref');
ok(@{$le->domains()} == 3, 'Checking the domain names set');

ok($le->load_account_key($fh->filename) == READ_ERROR, 'Loading non-existent key');

my $rv = $le->generate_account_key();
my $acceptable_rv = ($rv == OK or $rv == INVALID_DATA) ? 1 : 0;
ok($acceptable_rv == 1, 'Generating account key');

# Make sure usable key is generated
if ($rv) {
	while ($le->generate_account_key()) {}
}
ok($le->account_key, 'Getting account key');

print $fh $le->account_key;
$fh->flush;
ok($le->load_account_key($fh->filename) == OK, "Reloading account key");

# Try setting the key from a variable rather than file
my ($usable_key, $invalid_key) = ($le->account_key, '123456789');
ok($le->load_account_key(\$usable_key) == OK, 'Setting a valid key from scalar');
ok($le->load_account_key(\$invalid_key) == LOAD_ERROR, 'Setting an invalid key from scalar');
$fh->close;

$fh = File::Temp->new(SUFFIX => '.le', UNLINK => 1, EXLOCK => 0);

ok($le->load_csr($fh->filename) == READ_ERROR, 'Loading non-existent CSR');
my $broken_csr = '123456789';

# Try setting CSR from a variable rather than file
ok($le->load_csr(\$usable_csr) == OK, 'Setting a valid CSR from scalar');
ok($le->load_csr(\$invalid_csr) == INVALID_DATA, 'Setting an invalid CSR from scalar');
ok($le->load_csr(\$broken_csr) == LOAD_ERROR, 'Setting a broken CSR from scalar');

# Same for the CSR key
ok($le->load_csr_key(\$usable_key) == OK, 'Setting a valid CSR key from scalar');

# CSR tests
ok($le->generate_csr() == INVALID_DATA, 'Generating CSR without providing domain names');
ok($le->generate_csr('odd.domain') == OK, 'Generating CSR for one domain');
ok($le->generate_csr('odd.domain,another.domain,yet.another.domain') == OK, 'Generating CSR for multiple domains');
ok($le->csr, 'Retrieving generated CSR');
ok($le->csr_key(), 'Retrieving the key used for CSR');

print $fh $le->csr;
$fh->flush;
ok($le->load_csr($fh->filename) == OK, 'Reloading CSR without domains listed');
ok(join(',', @{$le->domains}) eq 'odd.domain,another.domain,yet.another.domain', 'Checking domain names order when those were NOT explicitly provided.');
ok($le->load_csr($fh->filename, 'odd.domain,another.domain,yet.another.domain') == OK, 'Reloading CSR with matching domains listed in the same order');
ok($le->load_csr($fh->filename, 'another.domain,yet.another.domain,odd.domain') == OK, 'Reloading CSR with matching domains listed in the different order');
ok(join(',', @{$le->domains}) eq 'another.domain,yet.another.domain,odd.domain', 'Checking domain names order when those were explicitly provided.');
ok($le->load_csr($fh->filename, 'another.domain,yet.another.domain') == DATA_MISMATCH, 'Reloading CSR with fewer domains listed');
ok($le->load_csr($fh->filename, 'odd.domain,another.odd.domain,another.domain,yet.another.domain') == DATA_MISMATCH, 'Reloading CSR with more domains listed');
ok(!defined $le->domains, 'Checking domain names reset on error.');
$fh->close;

# Try creating CSR with unsupported names, use already known usable key to speed up the process
ok($le->generate_csr('http://some.domain') == INVALID_DATA, 'Generating CSR for unsupported entity type (URI)');
ok($le->generate_csr('10.0.0.100') == INVALID_DATA, 'Generating CSR for unsupported entity type (IP)');
ok($le->generate_csr('a@b.c') == INVALID_DATA, 'Generating CSR for unsupported entity type (email)');
ok($le->generate_csr('abc') == INVALID_DATA, 'Generating CSR for unsupported entity type (dotless name)');
ok($le->generate_csr('*.domain.example') == INVALID_DATA, 'Generating CSR for unsupported entity type (wildcard)');

# Re-use previously generated key/CSR for RSA checks
ok($le->generate_csr('odd.domain', KEY_RSA) == OK, 'Generating RSA-based CSR (default)');
ok($le->generate_csr('odd.domain', KEY_RSA, 1024) == INVALID_DATA, 'Generating RSA-based CSR (short key)');
ok($le->generate_csr('odd.domain', KEY_RSA, 2048) == OK, 'Generating RSA-based CSR (regular key)');
ok($le->generate_csr('odd.domain', KEY_RSA, 3000) == INVALID_DATA, 'Generating RSA-based CSR (odd key)');

# Reset keys for ECC (curve check is runtime one)
$le->load_csr_key(\"");
$rv = $le->generate_csr('odd.domain', KEY_ECC);
ok(($rv == OK or $rv == UNSUPPORTED), 'Generating ECC-based CSR (default)');
$le->load_csr_key(\"");
$rv = $le->generate_csr('odd.domain', KEY_ECC, 'test');
ok(($rv == ERROR or $rv == UNSUPPORTED), 'Generating ECC-based CSR (odd curve)');

# Expiration checks against the invalid certificate and the one expiring in 2027.
is($le->check_expiration(\'aaa'), undef, 'Checking invalid certificate expiration');
ok(defined $le->check_expiration(\$usable_crt), 'Checking valid certificate expiration');

# Format conversion checks (account for arbitrary wrap length).
ok(line($le->der2pem($le->pem2der($usable_csr), 'CERTIFICATE REQUEST')) eq line($usable_csr), 'Checking unmodified CSR conversion');
ok(line($le->der2pem($le->pem2der("$usable_csr\r\n\r\n"), 'CERTIFICATE REQUEST')) eq line($usable_csr), 'Checking modified CSR conversion');

# Check export.
$rv = $le->export_pfx();
ok(($rv == UNSUPPORTED or $rv == INVALID_DATA), 'Exporting PFX with no password.');

diag( "Testing Crypt::LE $Crypt::LE::VERSION, Setup methods, $^X" );
