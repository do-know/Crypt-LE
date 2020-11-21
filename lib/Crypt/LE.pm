package Crypt::LE;

use 5.006;
use strict;
use warnings;

our $VERSION = '0.37';

=head1 NAME

Crypt::LE - Let's Encrypt API interfacing module and client.

=head1 VERSION

Version 0.37

=head1 SYNOPSIS

 use Crypt::LE;
    
 my $le = Crypt::LE->new();
 $le->load_account_key('account.pem');
 $le->load_csr('domain.csr');
 $le->register();
 $le->accept_tos();
 $le->request_challenge();
 $le->accept_challenge(\&process_challenge);
 $le->verify_challenge();
 $le->request_certificate();
 my $cert = $le->certificate();
 ...
 sub process_challenge {
    my $challenge = shift;
    print "Challenge for $challenge->{domain} requires:\n";
    print "A file '/.well-known/acme-challenge/$challenge->{token}' with the text: $challenge->{token}.$challenge->{fingerprint}\n";
    print "When done, press <Enter>";
    <STDIN>;
    return 1;
 };

=head1 DESCRIPTION

Crypt::LE provides the functionality necessary to use Let's Encrypt API and generate free SSL certificates for your domains. It can also
be used to generate RSA keys and Certificate Signing Requests or to revoke previously issued certificates. Crypt::LE is shipped with a 
self-sufficient client for obtaining SSL certificates - le.pl.

B<Provided client supports 'http' and 'dns' domain verification out of the box.>

Crypt::LE can be easily extended with custom plugins to handle Let's Encrypt challenges. See L<Crypt::LE::Challenge::Simple> module
for an example of a challenge-handling plugin.

Basic usage:

B<le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt --domains "www.domain.ext,domain.ext" --generate-missing>

That will generate an account key and a CSR (plus key) if they are missing. If any of those files exist, they will just be loaded, so it is safe to re-run
the client. Run le.pl without any parameters or with C<--help> to see more details and usage examples.

In addition to challenge-handling plugins, the client also supports completion-handling plugins, such as L<Crypt::LE::Complete::Simple>. You can easily 
handle challenges and trigger specific actions when your certificate gets issued by using those modules as templates, without modifying the client code.
You can also pass custom parameters to your modules from le.pl command line:

B<le.pl ... --handle-with Crypt::LE::Challenge::Simple --handle-params '{"key1": 1, "key2": "one"}'>
 
B<le.pl ... --complete-with Crypt::LE::Complete::Simple --complete-params '{"key1": 1, "key2": "one"}'>
 
The parameters don't have to be put directly in the command line, you could also give a name of a file containing valid JSON to read them from.

B<le.pl ... --complete-params complete.json>
 
Crypt::LE::Challenge:: and Crypt::LE::Complete:: namespaces are suggested for new plugins.

=head1 EXPORT

Crypt::LE does not export anything by default, but allows you to import the following constants:

=over

=item *
OK

=item *
READ_ERROR

=item *
LOAD_ERROR

=item *
INVALID_DATA

=item *
DATA_MISMATCH 

=item *
UNSUPPORTED

=item *
ALREADY_DONE

=item *
BAD_REQUEST

=item *
AUTH_ERROR

=item *
ERROR

=back

To import all of those, use C<':errors'> tag:

 use Crypt::LE ':errors';
 ...
 $le->load_account_key('account.pem') == OK or die "Could not load the account key: " . $le->error_details;
 
If you don't want to use error codes while checking whether the last called method has failed or not, you can use the
rule of thumb that on success it will return zero. You can also call error() or error_details() methods, which
will be set with some values on error.

=cut

use Crypt::OpenSSL::RSA;
use JSON::MaybeXS;
use HTTP::Tiny;
use IO::File;
use Digest::SHA 'sha256';
use MIME::Base64 qw<encode_base64url decode_base64url decode_base64 encode_base64>;
use Net::SSLeay qw<XN_FLAG_RFC2253 ASN1_STRFLGS_ESC_MSB MBSTRING_UTF8>;
use Scalar::Util 'blessed';
use Encode 'encode_utf8';
use Storable 'dclone';
use Convert::ASN1;
use Module::Load;
use Time::Piece;
use Time::Seconds;
use Data::Dumper;
use base 'Exporter';

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::OpenSSL_add_ssl_algorithms();
Net::SSLeay::OpenSSL_add_all_digests();
our $keysize = 4096;
our $keycurve = 'prime256v1';
our $headers = { 'Content-type' => 'application/jose+json' };

use constant {
    OK                     => 0,
    READ_ERROR             => 1,
    LOAD_ERROR             => 2,
    INVALID_DATA           => 3,
    DATA_MISMATCH          => 4,
    UNSUPPORTED            => 5,
    ERROR                  => 500,

    SUCCESS                => 200,
    CREATED                => 201,
    ACCEPTED               => 202,
    BAD_REQUEST            => 400,
    AUTH_ERROR             => 403,
    ALREADY_DONE           => 409,

    KEY_RSA                => 0,
    KEY_ECC                => 1,

    PEER_CRT               => 4,
    CRT_DEPTH              => 5,

    SAN                    => '2.5.29.17',
};

our @EXPORT_OK = (qw<OK READ_ERROR LOAD_ERROR INVALID_DATA DATA_MISMATCH UNSUPPORTED ERROR BAD_REQUEST AUTH_ERROR ALREADY_DONE KEY_RSA KEY_ECC>);
our %EXPORT_TAGS = ( 'errors' => [ @EXPORT_OK[0..9] ], 'keys' => [ @EXPORT_OK[10..11] ] );

my $pkcs12_available = 0;
my $j = JSON->new->canonical()->allow_nonref();
my $url_safe = qr/^[-_A-Za-z0-9]+$/; # RFC 4648 section 5.
my $flag_rfc22536_utf8 = (XN_FLAG_RFC2253) & (~ ASN1_STRFLGS_ESC_MSB);
if ($^O eq 'MSWin32') {
    eval { autoload 'Crypt::OpenSSL::PKCS12'; };
    $pkcs12_available = 1 unless $@;
}

# https://github.com/letsencrypt/boulder/blob/master/core/good_key.go
my @primes = map { Crypt::OpenSSL::Bignum->new_from_decimal($_) } (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
    109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
    173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
    293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359,
    367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431,
    433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491,
    499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571,
    577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
    643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709,
    719, 727, 733, 739, 743, 751
);

my $asn = Convert::ASN1->new();
$asn->prepare(q<
Extensions ::= SEQUENCE OF Extension
Extension ::= SEQUENCE {
    extnID          OBJECT IDENTIFIER,
    critical        BOOLEAN OPTIONAL,
    extnValue       OCTET STRING
}
SubjectAltName ::= GeneralNames
GeneralNames ::= SEQUENCE OF GeneralName
GeneralName ::= CHOICE {
    otherName                       [0]     ANY,
    rfc822Name                      [1]     IA5String,
    dNSName                         [2]     IA5String,
    x400Address                     [3]     ANY,
    directoryName                   [4]     ANY,
    ediPartyName                    [5]     ANY,
    uniformResourceIdentifier       [6]     IA5String,
    iPAddress                       [7]     OCTET STRING,
    registeredID                    [8]     OBJECT IDENTIFIER
}
>);

my $compat = {
    newAccount	=> 'new-reg',
    newOrder	=> 'new-cert',
    revokeCert	=> 'revoke-cert',
};

=head1 METHODS (API Setup)

The following methods are provided for the API setup. Please note that account key setup by default requests the resource directory from Let's Encrypt servers.
This can be changed by resetting the 'autodir' parameter of the constructor.

=head2 new()

Create a new instance of the class. Initialize the object with passed parameters. Normally you don't need to use any, but the following are supported:

=over 12

=item C<ua>

User-agent name to use while sending requests to Let's Encrypt servers. By default set to module name and version.

=item C<server>

Server URL to connect to. Only needed if the default live or staging server URLs have changed and this module has not yet been updated with the new
information or if you are using a custom server supporting ACME protocol. Note: the value is supposed to point to the root of the API (for example:
https://some.server/acme/) rather than the directory handler. This parameter might be deprecated in the future in favour of the 'dir' one below.

=item C<live>

Set to true to connect to a live Let's Encrypt server. By default it is not set, so staging server is used, where you can test the whole process of getting
SSL certificates.

=item C<debug>

Activates printing debug messages to the standard output when set. If set to 1, only standard messages are printed. If set to any greater value, then structures and
server responses are printed as well.

=item C<dir>

Full URL of a 'directory' handler on the server (the actual name of the handler can be different in certain configurations, where multiple handlers
are mapped). Only needed if you are using a custom server supporting ACME protocol. This parameter replaces the 'server' one.

=item C<autodir>

Enables automatic retrieval of the resource directory (required for normal API processing) from the servers. Enabled by default.

=item C<delay>

Specifies the time in seconds to wait before Let's Encrypt servers are checked for the challenge verification results again. By default set to 2 seconds.
Non-integer values are supported (so for example you can set it to 1.5 if you like).

=item C<version>

Enforces the API version to be used. If the response is not found to be compatible, an error will be returned. If not set, system will try to make an educated guess.

=item C<try>

Specifies the amount of retries to attempt while in 'pending' state and waiting for verification results response. By default set to 300, which combined 
with the delay of 2 seconds gives you 10 minutes of waiting.

=item C<logger>

Logger instance to use for debug messages. If not given, the messages will be printed to STDOUT.

=back

Returns: L<Crypt::LE> object.

=cut

sub new {
    my $class = shift;
    my %params = @_;
    my $self = {
        ua      => '',
        server  => '',
        dir     => '',
        live    => 0,
        debug   => 0,
        autodir => 1,
        delay   => 2,
        version => 0,
        try     => 300,
    };
    foreach my $key (keys %{$self}) {
        $self->{$key} = $params{$key} if (exists $params{$key} and !ref $params{$key});
    }
    # Init UA
    $self->{ua} = HTTP::Tiny->new( agent => $self->{ua} || __PACKAGE__ . " v$VERSION", verify_SSL => 1 );
    # Init server
    if ($self->{server}) {
        # Custom server - drop the protocol if given (defaults to https later). If that leaves nothing, the check below
        # will set the servers to LE standard ones.
        $self->{server}=~s~^\w+://~~;
    }
    if ($self->{dir}) {
        $self->{dir} = "https://$self->{dir}" unless $self->{dir}=~m~^https?://~i;
    }
    unless ($self->{server}) {
        if ($self->{version} > 1) {
            $self->{server} = $self->{live} ? 'acme-v02.api.letsencrypt.org' : 'acme-staging-v02.api.letsencrypt.org';
        } else {
            $self->{server} = $self->{live} ? 'acme-v01.api.letsencrypt.org' : 'acme-staging.api.letsencrypt.org';
        }
    }
    # Init logger
    $self->{logger} = $params{logger} if ($params{logger} and blessed $params{logger});
    bless $self, $class;
}

#====================================================================================================
# API Setup functions
#====================================================================================================

=head2 load_account_key($filename|$scalar_ref)

Loads the private account key from the file or scalar in PEM or DER formats.

Returns: OK | READ_ERROR | LOAD_ERROR | INVALID_DATA.

=cut

sub load_account_key {
    my ($self, $file) = @_;
    $self->_reset_key;
    my $key = $self->_file($file);
    return $self->_status(READ_ERROR, "Key reading error.") unless $key;
    eval {
        $key = Crypt::OpenSSL::RSA->new_private_key($self->_convert($key, 'RSA PRIVATE KEY'));
    };
    return $self->_status(LOAD_ERROR, "Key loading error.") if $@;
    return $self->_set_key($key, "Account key loaded.");
}

=head2 generate_account_key()

Generates a new private account key of the $keysize bits (4096 by default). The key is additionally validated for not being divisible by small primes.

Returns: OK | INVALID_DATA.

=cut

sub generate_account_key {
    my $self = shift;
    my ($pk, $err, $code) = _key();
    return $self->_status(INVALID_DATA, $err||"Could not generate account key") unless $pk;
    my $key = Crypt::OpenSSL::RSA->new_private_key(Net::SSLeay::PEM_get_string_PrivateKey($pk));
    _free(k => $pk);
    return $self->_set_key($key, "Account key generated.");
}

=head2 account_key()

Returns: A previously loaded or generated private key in PEM format or undef.

=cut

sub account_key {
    return shift->{pem};
}

=head2 load_csr($filename|$scalar_ref [, $domains])

Loads Certificate Signing Requests from the file or scalar. Domains list can be omitted or it can be given as a string of comma-separated names or as an array reference.
If omitted, then names will be loaded from the CSR. If it is given, then the list of names will be verified against those found on CSR.

Returns: OK | READ_ERROR | LOAD_ERROR | INVALID_DATA | DATA_MISMATCH.

=cut

sub load_csr {
    my $self = shift;
    my ($file, $domains) = @_;
    $self->_reset_csr;
    my $csr = $self->_file($file);
    return $self->_status(READ_ERROR, "CSR reading error.") unless $csr;
    my $bio = Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem());
    return $self->_status(LOAD_ERROR, "Could not allocate memory for the CSR") unless $bio;
    my ($in, $cn, $san, $i);
    unless (Net::SSLeay::BIO_write($bio, $csr) and $in = Net::SSLeay::PEM_read_bio_X509_REQ($bio)) {
        _free(b => $bio);
        return $self->_status(LOAD_ERROR, "Could not load the CSR");
    }
    $cn = Net::SSLeay::X509_REQ_get_subject_name($in);
    if ($cn) {
        $cn = Net::SSLeay::X509_NAME_print_ex($cn, $flag_rfc22536_utf8, 1);
        $cn = lc($1) if ($cn and $cn=~/^.*?\bCN=([^\s,]+).*$/);
    }
    my @list = @{$self->_get_list($domains)};
    $i = Net::SSLeay::X509_REQ_get_attr_by_NID($in, &Net::SSLeay::NID_ext_req, -1);
    if ($i > -1) {
        my $o = Net::SSLeay::P_X509_REQ_get_attr($in, $i);
        if ($o) {
            my $exts = $asn->find("Extensions");
            my $dec = $exts->decode(Net::SSLeay::P_ASN1_STRING_get($o));
            if ($dec) {
                foreach my $ext (@{$dec}) {
                     if ($ext->{extnID} and $ext->{extnID} eq SAN) {
                         $exts = $asn->find("SubjectAltName");
                         $san = $exts->decode($ext->{extnValue});
                         last;
                     }
                }
            }
        }
    }
    my @loaded_domains = ();
    my %seen = ();
    my $san_broken;
    if ($cn) {
        push @loaded_domains, $cn;
        $seen{$cn} = 1;
    }
    if ($san) {
        foreach my $ext (@{$san}) {
            if ($ext->{dNSName}) {
                $cn = lc($ext->{dNSName});
                push @loaded_domains, $cn unless $seen{$cn}++;
            } else {
                $san_broken++;
            }
        }
    }
    _free(b => $bio);
    if ($san_broken) {
        return $self->_status(INVALID_DATA, "CSR contains $san_broken non-DNS record(s) in SAN");
    }
    unless (@loaded_domains) {
        return $self->_status(INVALID_DATA, "No domains found on CSR.");
    } else {
        if (my $odd = $self->_verify_list(\@loaded_domains)) {
             return $self->_status(INVALID_DATA, "Unsupported domain names on CSR: " . join(", ", @{$odd}));
        }
        $self->_debug("Loaded domain names from CSR: " . join(', ', @loaded_domains));
    }
    if (@list) {
        return $self->_status(DATA_MISMATCH, "The list of provided domains does not match the one on the CSR.") unless (join(',', sort @loaded_domains) eq join(',', sort @list));
        @loaded_domains = @list; # Use the command line domain order if those were listed along with CSR.
    }
    $self->_set_csr($csr, undef, \@loaded_domains);
    return $self->_status(OK, "CSR loaded.");
}

=head2 generate_csr($domains, [$key_type], [$key_attr])

Generates a new Certificate Signing Request. Optionally accepts key type and key attribute parameters, where key type should
be either KEY_RSA or KEY_ECC (if supported on your system) and key attribute is either the key size (for RSA) or the curve (for ECC).
By default an RSA key of 4096 bits will be used.
Domains list is mandatory and can be given as a string of comma-separated names or as an array reference.

Returns: OK | ERROR | UNSUPPORTED | INVALID_DATA.

=cut

sub generate_csr {
    my $self = shift;
    my ($domains, $key_type, $key_attr) = @_;
    $self->_reset_csr;
    my @list = @{$self->_get_list($domains)};
    return $self->_status(INVALID_DATA, "No domains provided.") unless @list;
    if (my $odd = $self->_verify_list(\@list)) {
         return $self->_status(INVALID_DATA, "Unsupported domain names provided: " . join(", ", @{$odd}));
    }
    my ($key, $err, $code) = _key($self->csr_key(), $key_type, $key_attr);
    return $self->_status($code||ERROR, $err||"Key problem while creating CSR") unless $key;
    my ($csr, $csr_key) = _csr($key, \@list, { O => '-', L => '-', ST => '-', C => 'GB' });
    return $self->_status(ERROR, "Unexpected CSR error.") unless $csr;
    $self->_set_csr($csr, $csr_key, \@list);
    return $self->_status(OK, "CSR generated.");
}

=head2 csr()

Returns: A previously loaded or generated CSR in PEM format or undef.

=cut

sub csr {
    return shift->{csr};
}

=head2 load_csr_key($filename|$scalar_ref)

Loads the CSR key from the file or scalar (to be used for generating a new CSR).

Returns: OK | READ_ERROR.

=cut

sub load_csr_key {
    my $self = shift;
    my $file = shift;
    undef $self->{csr_key};
    my $key = $self->_file($file);
    return $self->_status(READ_ERROR, "CSR key reading error.") unless $key;
    $self->{csr_key} = $key;
    return $self->_status(OK, "CSR key loaded");
}

=head2 csr_key()

Returns: A CSR key (either loaded or generated with CSR) or undef.

=cut

sub csr_key {
    return shift->{csr_key};
}

=head2 set_account_email([$email])

Sets (or resets if no parameter is given) an email address that will be used for registration requests.

Returns: OK | INVALID_DATA.

=cut

sub set_account_email {
    my ($self, $email) = @_;
    unless ($email) {
        undef $self->{email};
        return $self->_status(OK, "Account email has been reset");
    }
    # Note: We don't validate email, just removing some extra bits which may be present.
    $email=~s/^\s*mail(?:to):\s*//i;
    $email=~s/^<([^>]+)>/$1/;
    $email=~s/^\s+$//;
    return $self->_status(INVALID_DATA, "Invalid email provided") unless $email;
    $self->{email} = $email;
    return $self->_status(OK, "Account email has been set to '$email'");
}

=head2 set_domains($domains)

Sets the list of domains to be used for verification process. This call is optional if you load or generate a CSR, in which case the list of the domains will be set at that point.

Returns: OK | INVALID_DATA.

=cut

sub set_domains {
    my ($self, $domains) = @_;
    my @list = @{$self->_get_list($domains)};
    return $self->_status(INVALID_DATA, "No domains provided.") unless @list;
    if (my $odd = $self->_verify_list(\@list)) {
         return $self->_status(INVALID_DATA, "Unsupported domain names provided: " . join(", ", @{$odd}));
    }
    $self->{loaded_domains} = \@list;
    my %loaded_domains = map {$_, undef} @list;
    $self->{domains} = \%loaded_domains;
    return $self->_status(OK, "Domains list is set");
}

=head2 set_version($version)

Sets the API version to be used. To pick the version automatically, use 0, other accepted values are currently 1 and 2.

Returns: OK | INVALID_DATA.

=cut

sub set_version {
    my ($self, $version) = @_;
    return $self->_status(INVALID_DATA, "Unsupported API version") unless (defined $version and $version=~/^\d+$/ and $version <= 2);
    $self->{version} = $version;
    return $self->_status(OK, "API version is set to $version.");
}

=head2 version()

Returns: The API version currently used (1 or 2). If 0 is returned, it means it is set to automatic detection and the directory has not yet been retrieved.

=cut

sub version {
    my $self = shift;
    return $self->{version};
}

#====================================================================================================
# API Setup helpers
#====================================================================================================

sub _reset_key {
    my $self = shift;
    undef $self->{$_} for qw<key_params key pem jwk fingerprint>;
}

sub _set_key {
    my $self = shift;
    my ($key, $msg) = @_;
    my $pem = $key->get_private_key_string;
    my ($n, $e) = $key->get_key_parameters;
    return $self->_status(INVALID_DATA, "Key modulus is divisible by a small prime and will be rejected.") if $self->_is_divisible($n);
    $key->use_pkcs1_padding;
    $key->use_sha256_hash;
    $self->{key_params} = { n => $n, e => $e };
    $self->{key} = $key;
    $self->{pem} = $pem;
    $self->{jwk} = $self->_jwk();
    $self->{fingerprint} = encode_base64url(sha256($j->encode($self->{jwk})));
    if ($self->{autodir}) {
        my $status = $self->directory;
        return $status unless ($status == OK);
    }
    return $self->_status(OK, $msg);
}

sub _is_divisible {
    my ($self, $n) = @_;
    my ($quotient, $remainder);
    my $ctx = Crypt::OpenSSL::Bignum::CTX->new();
    foreach my $prime (@primes) {
        ($quotient, $remainder) = $n->div($prime, $ctx);
        return 1 if $remainder->is_zero;
    }
    return 0;
}

sub _reset_csr {
    my $self = shift;
    undef $self->{$_} for qw<domains loaded_domains csr>;
}

sub _set_csr {
    my $self = shift;
    my ($csr, $pk, $domains) = @_;
    $self->{csr} = $csr;
    $self->{csr_key} = $pk;
    my %loaded_domains = map {$_, undef} @{$domains};
    $self->{loaded_domains} = $domains;
    $self->{domains} = \%loaded_domains;
}

sub _get_list {
    my ($self, $list) = @_;
    return [ map {lc $_} (ref $list eq 'ARRAY') ? @{$list} : $list ? split /\s*,\s*/, $list : () ];
}

sub _verify_list {
    my ($self, $list) = @_;
    my @odd = grep { /[\s\[\{\(\<\@\>\)\}\]\/\\:]/ or /^[\d\.]+$/ or !/\./ } @{$list};
    return @odd ? \@odd : undef;
}

#====================================================================================================
# API Workflow functions
#====================================================================================================

=head1 METHODS (API Workflow)

The following methods are provided for the API workflow processing. All but C<accept_challenge()> methods interact with Let's Encrypt servers.

=head2 directory([ $reload ])

Loads resource pointers from Let's Encrypt. This method needs to be called before the registration. It
will be called automatically upon account key loading/generation unless you have reset the 'autodir'
parameter when creating a new Crypt::LE instance. If any true value is provided as a parameter, reloads
the directory even if it has been already retrieved, but preserves the 'reg' value (for example to pull
another Nonce for the current session).

Returns: OK | INVALID_DATA | LOAD_ERROR.

=cut

sub directory {
    my ($self, $reload) = @_;
    if (!$self->{directory} or $reload) {
        my ($status, $content) = $self->{dir} ? $self->_request($self->{dir}) : $self->_request("https://$self->{server}/directory");
        if ($status == SUCCESS and $content and (ref $content eq 'HASH')) {
            if ($content->{newAccount}) {
                unless ($self->version) {
                    $self->set_version(2);
                } elsif ($self->version() != 2) {
                    return $self->_status(INVALID_DATA, "Resource directory is not compatible with the version set (required v1, got v2).");
                }
                $self->_compat($content);
            } elsif ($content->{'new-reg'}) {
                unless ($self->version) {
                    $self->set_version(1);
                } elsif ($self->version() != 1) {
                    return $self->_status(INVALID_DATA, "Resource directory is not compatible with the version set (required v2, got v1).");
                }
            } else {
                return $self->_status(INVALID_DATA, "Resource directory does not contain expected fields.");
            }
            $content->{reg} = $self->{directory}->{reg} if ($self->{directory} and $self->{directory}->{reg});
            $self->{directory} = $content;
            unless ($self->{nonce}) {
                if ($self->{directory}->{'newNonce'}) {
                    $self->_request($self->{directory}->{'newNonce'}, undef, { method => 'head' });
                    return $self->_status(LOAD_ERROR, "Could not retrieve the Nonce value.") unless $self->{nonce};
                } else {
                    return $self->_status(LOAD_ERROR, "Could not retrieve the Nonce value and there is no method to request it.")
                }
            }
            return $self->_status(OK, "Directory loaded successfully.");
        } else {
            return $self->_status(LOAD_ERROR, $content);
        }
    }
    return $self->_status(OK, "Directory has been already loaded.");
}

=head2 new_nonce()

Requests a new nonce by forcing the directory reload. Picks up the value from the returned headers if it
is present (API v1.0), otherwise uses newNonce method to get it (API v2.0) if one is provided.

Returns: Nonce value or undef (if neither the value is in the headers nor newNonce method is available).

=cut

sub new_nonce {
    my $self = shift;
    undef $self->{nonce};
    $self->directory(1);
    return $self->{nonce};
}

=head2 register()

Registers an account key with Let's Encrypt. If the key is already registered, it will be handled automatically.

Returns: OK | ERROR.

=cut

sub register {
    my $self = shift;
    my $req = { resource => 'new-reg' };
    $req->{contact} = [ "mailto:$self->{email}" ] if $self->{email};
    my ($status, $content) = $self->_request($self->{directory}->{'new-reg'}, $req);
    $self->{directory}->{reg} = $self->{location} if $self->{location};
    $self->{$_} = undef for (qw<registration_id contact_details>);
    if ($status == $self->_compat_response(ALREADY_DONE)) {
        $self->{new_registration} = 0;
        $self->_debug("Key is already registered, reg path: $self->{directory}->{reg}.");
        ($status, $content) = $self->_request($self->{directory}->{'reg'}, { resource => 'reg' });
        if ($status == $self->_compat_response(ACCEPTED)) {
            $self->{registration_info} = $content;
            if ($self->version() == 1 and $self->{links} and $self->{links}->{'terms-of-service'} and (!$content->{agreement} or ($self->{links}->{'terms-of-service'} ne $content->{agreement}))) {
                $self->_debug($content->{agreement} ? "You need to accept TOS" : "TOS has changed, you may need to accept it again.");
                $self->{tos_changed} = 1;
            } else {
                $self->{tos_changed} = 0;
            }
        } else {
            return $self->_status(ERROR, $content);
        }
    } elsif ($status == CREATED) {
        $self->{new_registration} = 1;
        $self->{registration_info} = $content;
        $self->{tos_changed} = 0;
        my $tos_message = '';
        if ($self->{links}->{'terms-of-service'}) {
            $self->{tos_changed} = 1;
            $tos_message = "You need to accept TOS at $self->{links}->{'terms-of-service'}";
        }
        $self->_debug("New key is now registered, reg path: $self->{directory}->{reg}. $tos_message");
    } else {
        return $self->_status(ERROR, $content);
    }
    if ($self->{registration_info} and ref $self->{registration_info} eq 'HASH') {
        $self->{registration_id} = $self->{registration_info}->{id};
        if ($self->{registration_info}->{contact} and (ref $self->{registration_info}->{contact} eq 'ARRAY') and @{$self->{registration_info}->{contact}}) {
            $self->{contact_details} = $self->{registration_info}->{contact};
        }
    }
    if (!$self->{registration_id} and $self->{directory}->{reg}=~/\/([^\/]+)$/) {
        $self->{registration_id} = $1;
    }
    $self->_debug("Account ID: $self->{registration_id}") if $self->{registration_id};
    return $self->_status(OK, "Registration success: TOS change status - $self->{tos_changed}, new registration flag - $self->{new_registration}.");
}

=head2 accept_tos()

Accepts Terms of Service set by Let's Encrypt.

Returns: OK | ERROR.

=cut

sub accept_tos {
    my $self = shift;
    return $self->_status(OK, "TOS has NOT been changed, no need to accept again.") unless $self->tos_changed;
    my ($status, $content) = $self->_request($self->{directory}->{'reg'}, { resource => 'reg', agreement => $self->{links}->{'terms-of-service'} });
    return ($status == $self->_compat_response(ACCEPTED)) ? $self->_status(OK, "Accepted TOS.") : $self->_status(ERROR, $content);
}

=head2 update_contacts($array_ref)

Updates contact details for your Let's Encrypt account. Accepts an array reference of contacts.
Non-prefixed contacts will be automatically prefixed with 'mailto:'.

Returns: OK | INVALID_DATA | ERROR.

=cut

sub update_contacts {
    my ($self, $contacts) = @_;
    return $self->_status(INVALID_DATA, "Invalid call parameters.") unless ($contacts and (ref $contacts eq 'ARRAY'));
    my @set = map { /^\w+:/ ? $_ : "mailto:$_" } @{$contacts};
    my ($status, $content) = $self->_request($self->{directory}->{'reg'}, { resource => 'reg', contact => \@set });
    return ($status == $self->_compat_response(ACCEPTED)) ? $self->_status(OK, "Email has been updated.") : $self->_status(ERROR, $content);
}

=head2 request_challenge()

Requests challenges for domains on your CSR. On error you can call failed_domains() method, which returns an array reference to domain names for which
the challenge was not requested successfully.

Returns: OK | ERROR.

=cut

sub request_challenge {
    my $self = shift;
    $self->_status(ERROR, "No domains are set.") unless $self->{domains};
    my ($domains_requested, %domains_failed);
    # For v2.0 API the 'new-authz' is optional. However, authz set is provided via newOrder request (also utilized by request_certificate call).
    # We are keeping the flow compatible with older clients, so if that call has not been specifically made (as it would in le.pl), we do
    # it at the point of requesting the challenge. Note that if certificate is already valid, we will skip most of the challenge-related
    # calls, but will not be returning the cert early to avoid interrupting the established flow.
    if ($self->version() > 1) {
        unless ($self->{authz}) {
            my ($status, $content) = $self->_request($self->{directory}->{'new-cert'}, { resource => 'new-cert' });
            if ($status == CREATED and $content->{'identifiers'} and $content->{'authorizations'}) {
                push @{$self->{authz}}, [ $_, '' ] for @{$content->{'authorizations'}};
                $self->{finalize} = $content->{'finalize'};
            } else {
                unless ($self->{directory}->{'new-authz'}) {
                    return $self->_status(ERROR, "Cannot request challenges - " . $self->_pull_error($content) . "($status).");
                }
                $self->_get_authz();
            }
        }
    } else {
        $self->_get_authz();
    }
    foreach my $authz (@{$self->{authz}}) {
        $self->_debug("Requesting challenge.");
        my ($status, $content) = $self->_request(@{$authz});
        $domains_requested++;
        if ($status == $self->_compat_response(CREATED)) {
            my $valid_challenge = 0;
            return $self->_status(ERROR, "Missing identifier in the authz response.") unless ($content->{identifier} and $content->{identifier}->{value});
            my $domain = $content->{identifier}->{value};
            $domain = "*.$domain" if $content->{wildcard};
            foreach my $challenge (@{$content->{challenges}}) {
                unless ($challenge and (ref $challenge eq 'HASH') and $challenge->{type} and
                       ($challenge->{url} or $challenge->{uri}) and
                       ($challenge->{status} or $content->{status})) {
                    $self->_debug("Challenge for domain $domain does not contain required fields.");
                    next;
                }
                my $type = (split '-', delete $challenge->{type})[0];
                unless ($challenge->{token} and $challenge->{token}=~$url_safe) {
                    $self->_debug("Challenge ($type) for domain $domain is missing a valid token.");
                    next;
                }
                $valid_challenge = 1 if ($challenge->{status} eq 'valid');
                $challenge->{uri} ||= $challenge->{url};
                $challenge->{status} ||= $content->{status};
                $self->{challenges}->{$domain}->{$type} = $challenge;
            }
            if ($self->{challenges} and exists $self->{challenges}->{$domain}) {
                $self->_debug("Received challenges for $domain.");
                $self->{domains}->{$domain} = $valid_challenge;
            } else {
                $self->_debug("Received no valid challenges for $domain.");
                $domains_failed{$domain} = $self->_pull_error($content)||'No valid challenges';
            }
        } else {
            # NB: In API v2.0 you don't know which domain you are receiving a challenge for - you can only rely
            # on the identifier in the response. Even though in v1.0 we could associate domain name with this error,
            # we treat this uniformly and return.
            my $err = $self->_pull_error($content);
            return $self->_status(ERROR, "Failed to receive the challenge. $err");
        }
    }
    if (%domains_failed) {
        my @failed = sort keys %domains_failed;
        $self->{failed_domains} = [ \@failed ];
        my $status = join "\n", map { "$_: $domains_failed{$_}" } @failed;
        my $info = @failed == $domains_requested ? "All domains failed" : "Some domains failed";
        return $self->_status(ERROR, "$info\n$status");
    } else {
        $self->{failed_domains} = [ undef ];
    }
    # Domains not requested with authz are considered to be already validated.
    for my $domain (@{$self->{loaded_domains}}) {
        unless (defined $self->{domains}->{$domain}) {
            $self->{domains}->{$domain} = 1;
            $self->_debug("Domain $domain does not require a challenge at this time.");
        }
    }
    return $self->_status(OK, $domains_requested ? "Requested challenges for $domains_requested domain(s)." : "There are no domains which were not yet requested for challenges.");
}

=head2 accept_challenge($callback [, $params] [, $type])

Sets up a callback, which will be called for each non-verified domain to satisfy the requested challenge. Each callback will receive two parameters -
a hash reference with the challenge data and a hash reference of parameters optionally passed to accept_challenge(). The challenge data has the following keys:

=over 14

=item C<domain>

The domain name being processed (lower-case)

=item C<host>

The domain name without the wildcard part (if that was present)

=item C<token>

The challenge token

=item C<fingerprint>
 
The account key fingerprint

=item C<file>

The file name for HTTP verification (essentially the same as token)

=item C<text>

The text for HTTP verification

=item C<record>

The value of the TXT record for DNS verification

=item C<logger>
 
Logger object.

=back

The type of the challenge accepted is optional and it is 'http' by default. The following values are currently available: 'http', 'tls', 'dns'. 
New values which might be added by Let's Encrypt will be supported automatically. While currently all domains being processed share the same type
of challenge, it might be changed in the future versions.

On error you can call failed_domains() method, which returns an array reference to domain names for which the challenge was not accepted successfully.

The callback should return a true value on success.

The callback could be either a code reference (for example to a subroutine in your program) or a blessed reference to a module handling
the challenge. In the latter case the module should have methods defined for handling appropriate challenge type, such as:

=over

=item

B<handle_challenge_http()>

=item

B<handle_challenge_tls()>

=item

B<handle_challenge_dns()>

=back

You can use L<Crypt::LE::Challenge::Simple> example module as a template.
 
Returns: OK | INVALID_DATA | ERROR.

=cut

sub accept_challenge {
    my $self = shift;
    my ($cb, $params, $type) = @_;
    return $self->_status(ERROR, "Domains and challenges need to be set before accepting.") unless ($self->{domains} and $self->{challenges});
    my $mod_callback = ($cb and blessed $cb) ? 1 : 0;
    $type||='http';
    my $handler = "handle_challenge_$type";
    return $self->_status(INVALID_DATA, "Valid callback has not been provided.") unless ($cb and ((ref $cb eq 'CODE') or ($mod_callback and $cb->can($handler))));
    return $self->_status(INVALID_DATA, "Passed parameters are not pointing to a hash.") if ($params and (ref $params ne 'HASH'));
    my ($domains_accepted, @domains_failed);
    $self->{active_challenges} = undef;
    foreach my $domain (@{$self->{loaded_domains}}) {
        unless (defined $self->{domains}->{$domain} and !$self->{domains}->{$domain}) {
            $self->_debug($self->{domains}->{$domain} ? "Domain $domain has been already validated, skipping." : "Challenge has not yet been requested for domain $domain, skipping.");
            next;
        }
        unless ($self->{challenges}->{$domain} and $self->{challenges}->{$domain}->{$type}) {
            $self->_debug("Could not find a challenge of type $type for domain $domain.");
            push @domains_failed, $domain;
            next;
        }
        my $rv;
        my $callback_data = {
                                domain => $domain,
                                token => $self->{challenges}->{$domain}->{$type}->{token},
                                fingerprint => $self->{fingerprint},
                                logger => $self->{logger},
                            };
        $self->_callback_extras($callback_data);
        eval {
            $rv = $mod_callback ? $cb->$handler($callback_data, $params) : &$cb($callback_data, $params); 
        };
        if ($@ or !$rv) {
            $self->_debug("Challenge callback for domain $domain " . ($@ ? "thrown an error: $@" : "did not return a true value"));
            push @domains_failed, $domain;
        } else {
            $self->{active_challenges}->{$domain} = $type;
            $domains_accepted++;
        }
    }
    if (@domains_failed) {
        push @{$self->{failed_domains}}, \@domains_failed;
        return $self->_status(ERROR, $domains_accepted ? "Challenges failed for domains: " . join(", ", @domains_failed) : "All challenges failed");
    } else {
        push @{$self->{failed_domains}}, undef;
    }
    return $self->_status(OK, $domains_accepted ? "Accepted challenges for $domains_accepted domain(s)." : "There are no domains for which challenges need to be accepted.");
}

=head2 verify_challenge([$callback] [, $params] [, $type])

Asks Let's Encrypt server to verify the results of the challenge. On error you can call failed_domains() method, which returns an array reference to domain names 
for which the challenge was not verified successfully.

Optionally you can set up a callback, which will be called for each domain with the results of verification. The callback will receive two parameters -
a hash reference with the results and a hash reference of parameters optionally passed to verify_challenge(). The results data has the following keys:

=over 14

=item C<domain>

The domain name processed (lower-case)

=item C<host>

The domain name without the wildcard part (if that was present)

=item C<token>

The challenge token

=item C<fingerprint>
 
The account key fingerprint

=item C<file>

The file name for HTTP verification (essentially the same as token)

=item C<text>

The text for HTTP verification

=item C<record>

The value of the TXT record for DNS verification

=item C<valid>
 
Set to 1 if the domain has been verified successfully or set to 0 otherwise.

=item C<error>
 
Error message returned for domain on verification failure.

=item C<logger>
 
Logger object.

=back

The type of the challenge accepted is optional and it is 'http' by default. The following values are currently available: 'http', 'tls', 'dns'.

The callback should return a true value on success.

The callback could be either a code reference (for example to a subroutine in your program) or a blessed reference to a module handling
the verification outcome. In the latter case the module should have methods defined for handling appropriate verification type, such as:

=over

=item

B<handle_verification_http()>

=item

B<handle_verification_tls()>

=item

B<handle_verification_dns()>

=back

You can use L<Crypt::LE::Challenge::Simple> example module as a template.

Returns: OK | INVALID_DATA | ERROR.

=cut

sub verify_challenge {
    my $self = shift;
    my ($cb, $params, $type) = @_;
    return $self->_status(ERROR, "Domains and challenges need to be set before verifying.") unless ($self->{domains} and $self->{challenges});
    return $self->_status(OK, "There are no active challenges to verify") unless $self->{active_challenges};
    my $mod_callback = ($cb and blessed $cb) ? 1 : 0;
    $type||='http';
    my $handler = "handle_verification_$type";
    if ($cb) {
        return $self->_status(INVALID_DATA, "Valid callback has not been provided.") unless ($cb and ((ref $cb eq 'CODE') or ($mod_callback and $cb->can($handler))));
        return $self->_status(INVALID_DATA, "Passed parameters are not pointing to a hash.") if ($params and (ref $params ne 'HASH'));
    }
    my ($domains_verified, @domains_failed);
    my $expected_status = $self->_compat_response(ACCEPTED);
    foreach my $domain (@{$self->{loaded_domains}}) {
        unless (defined $self->{domains}->{$domain} and !$self->{domains}->{$domain}) {
            $self->_debug($self->{domains}->{$domain} ? "Domain $domain has been already verified, skipping." : "Challenge has not yet been requested for domain $domain, skipping.");
            next;
        }
        unless ($self->{active_challenges}->{$domain}) {
            $self->_debug("Domain $domain is not set as having an active challenge (you may need to run 'accept_challenge'), skipping.");
            push @domains_failed, $domain;
            next;
        }
        my $type = delete $self->{active_challenges}->{$domain};
        my $token = $self->{challenges}->{$domain}->{$type}->{token};
        my ($status, $content) = $self->_request($self->{challenges}->{$domain}->{$type}->{uri}, { resource => 'challenge', keyAuthorization => "$token.$self->{fingerprint}" });
        my ($validated, $cb_reset) = (0, 0);
        if ($status == $expected_status) {
            $content->{uri} ||= $content->{url};
            if ($content->{uri}) {
                my @check = ($content->{uri});
                push @check, '' if ($self->version() > 1);
                my $try = 0;
                while ($status == $expected_status and $content and $content->{status} and $content->{status} eq 'pending') {
                    select(undef, undef, undef, $self->{delay});
                    ($status, $content) = $self->_request(@check);
                    last if ($self->{try} and (++$try == $self->{try}));
                }
                if ($status == $expected_status and $content and $content->{status}) {
                    if ($content->{status}=~/^(?:in)?valid$/) {
                        if ($content->{status} eq 'valid') {
                            $self->_debug("Domain $domain has been verified successfully.");
                            $validated = 1;
                        }
                    }
                }
            }
        }
        if ($cb) {
            my $rv;
            my $callback_data = { 
                                    domain => $domain,
                                    token => $self->{challenges}->{$domain}->{$type}->{token},
                                    fingerprint => $self->{fingerprint}, 
                                    valid => $validated, 
                                    error => $self->_pull_error($content),
                                    logger => $self->{logger},
                                };
            $self->_callback_extras($callback_data);
            eval {
                $rv = $mod_callback ? $cb->$handler($callback_data, $params) : &$cb($callback_data, $params); 
            };
            if ($@ or !$rv) {
                # NB: Error in callback will propagate, even if validation process returned OK.
                $self->_debug("Verification callback for domain $domain " . ($@ ? "thrown an error: $@" : "did not return a true value"));
                $cb_reset = 1 if $validated;
                $validated = 0;
            }
        }
        if ($validated) {
            $self->{domains}->{$domain} = 1;
            $domains_verified++;
        } else {
            $self->_debug("Domain $domain has failed verification (status code $status).", $content) unless $cb_reset;
            push @domains_failed, $domain;
        }
    }
    if (@domains_failed) {
        push @{$self->{failed_domains}}, \@domains_failed;
        return $self->_status(ERROR, $domains_verified ? "Verification failed for domains: " . join(", ", @domains_failed) : "All verifications failed");
    } else {
        push @{$self->{failed_domains}}, undef;
    }
    return $self->_status(OK, $domains_verified ? "Verified challenges for $domains_verified domain(s)." : "There are no domains pending challenge verification.");
}

=head2 request_certificate()

Requests the certificate for your CSR.

Returns: OK | AUTH_ERROR | ERROR.

=cut

sub request_certificate {
    my $self = shift;
    return $self->_status(ERROR, "CSR is missing, make sure it has been either loaded or generated.") unless $self->{csr};
    my $csr = encode_base64url($self->pem2der($self->{csr}));
    my ($status, $content);
    delete $self->{authz};
    delete $self->{alternatives};
    unless ($self->{finalize}) {
        ($status, $content) = $self->_request($self->{directory}->{'new-cert'}, { resource => 'new-cert', csr => $csr });
        return $self->_status($status == AUTH_ERROR ? AUTH_ERROR : ERROR, $content) unless ($status == CREATED);
        if (ref $content eq 'HASH' and $content->{'identifiers'} and $content->{'authorizations'}) {
            push @{$self->{authz}}, [ $_, '' ] for @{$content->{'authorizations'}};
            $self->{finalize} = $content->{'finalize'};
        }
    }
    if ($self->{finalize}) {
        # v2. Let's attempt to finalize the order immediately.
        my ($ready, $try) = (0, 0);
        ($status, $content) = $self->_request($self->{finalize}, { csr => $csr });
        while ($status == SUCCESS and $content and $content->{status} and $content->{status} eq 'processing') {
            select(undef, undef, undef, $self->{delay});
            ($status, $content) = $self->_request($self->{finalize}, { csr => $csr });
            last if ($self->{try} and (++$try == $self->{try}));
        }
        if ($status == SUCCESS and $content and $content->{status}) {
            if ($content->{status} eq 'valid') {
                if ($content->{certificate}) {
                    $self->_debug("The certificate is ready for download at $content->{certificate}.");
                    my @cert = ($content->{certificate});
                    push @cert, '' if ($self->version() > 1);
                    ($status, $content) = $self->_request(@cert);
                    return $self->_status(ERROR, "Certificate could not be downloaded from $content->{certificate}.") unless ($status == SUCCESS);
                    # In v2 certificate is returned along with the chain.
                    $ready = 1;
                    if ($content=~/(\n\-+END CERTIFICATE\-+)[\s\r\n]+(.+)/s) {
                        $self->_debug("Certificate is separated from the chain.");
                        $self->{issuer} = $self->_convert($2, 'CERTIFICATE');
                        $content = $` . $1;
                    }
                    # Save the links to alternative certificates.
                    $self->{alternatives} = $self->{links}->{alternate} || [];
                } else {
                    return $self->_status(ERROR, "The certificate is ready, but there was no download link provided.");
                }
            } elsif ($content->{status} eq 'invalid') {
                return $self->_status(ERROR, "Certificate cannot be issued.");
            } elsif ($content->{status} eq 'pending') {
                return $self->_status(AUTH_ERROR, "Order already exists but not yet completed.");
            } else {
                return $self->_status(ERROR, "Unknown order status: $content->{status}.");
            }
        } else {
            return $self->_status(AUTH_ERROR, "Could not finalize an order.");
        }
        return $self->_status(AUTH_ERROR, "Could not finalize an order.") unless $ready;
    }
    $self->{certificate} = $self->_convert($content, 'CERTIFICATE');
    $self->{certificate_url} = $self->{location};
    $self->{issuer_url} = ($self->{links} and $self->{links}->{up}) ? $self->{links}->{up} : undef;
    return $self->_status(OK, "Domain certificate has been received." . ($self->{issuer_url} ? " Issuer's certificate can be found at: $self->{issuer_url}" : ""));
}

=head2 request_alternatives()

Requests alternative certificates if any are available.

Returns: OK | ERROR.

=cut

sub request_alternatives {
    my $self = shift;
    return $self->_status(ERROR, "The default certificate must be requested before the alternatives.") unless $self->{alternatives};
    my ($status, $content);
    delete $self->{alternative_certificates};
    foreach my $link (@{$self->{alternatives}}) {
        $self->_debug("Alternative certificate is available at $link.");
        my @cert = ($link);
        push @cert, '' if ($self->version() > 1);
        ($status, $content) = $self->_request(@cert);
        return $self->_status(ERROR, "Certificate could not be downloaded from $link.") unless ($status == SUCCESS);
        # In v2 certificate is returned along with the chain.
        if ($content=~/(\n\-+END CERTIFICATE\-+)[\s\r\n]+(.+)/s) {
            $self->_debug("Certificate is separated from the chain.");
            push @{$self->{alternative_certificates}}, [ $self->_convert($` . $1, 'CERTIFICATE'), $self->_convert($2, 'CERTIFICATE') ];
        } else {
            push @{$self->{alternative_certificates}}, [ $self->_convert($content, 'CERTIFICATE') ];
        }
    }
    return $self->_status(OK, "Alternative certificates have been received.");
}

=head2 request_issuer_certificate()

Requests the issuer's certificate.

Returns: OK | ERROR.

=cut

sub request_issuer_certificate {
    my $self = shift;
    return $self->_status(OK, "Issuer's certificate has been already received.") if $self->issuer();
    return $self->_status(ERROR, "The URL of issuer certificate is not set.") unless $self->{issuer_url};
    my ($status, $content) = $self->_request($self->{issuer_url});
    if ($status == SUCCESS) {
        $self->{issuer} = $self->_convert($content, 'CERTIFICATE');
        return $self->_status(OK, "Issuer's certificate has been received.");
    }
    return $self->_status(ERROR, $content);
}

=head2 revoke_certificate($certificate_file|$scalar_ref)

Revokes a certificate.

Returns: OK | READ_ERROR | ALREADY_DONE | ERROR.

=cut

sub revoke_certificate {
    my $self = shift;
    my $file = shift;
    my $crt = $self->_file($file);
    return $self->_status(READ_ERROR, "Certificate reading error.") unless $crt;
    my ($status, $content) = $self->_request($self->{directory}->{'revoke-cert'},
                             { resource => 'revoke-cert', certificate => encode_base64url($self->pem2der($crt)) },
                             { jwk => 0 });
    if ($status == SUCCESS) {
        return $self->_status(OK, "Certificate has been revoked.");
    } elsif ($status == ALREADY_DONE) {
        return $self->_status(ALREADY_DONE, "Certificate has been already revoked.");
    }
    return $self->_status(ERROR, $content);
}

#====================================================================================================
# API Workflow helpers
#====================================================================================================

=head1 METHODS (Other)

The following methods are the common getters you can use to get more details about the outcome of the workflow run and return some retrieved data, such as
registration info and certificates for your domains.

=head2 tos()

Returns: The link to a Terms of Service document or undef.

=cut

sub tos {
    my $self = shift;
    return ($self->{links} and $self->{links}->{'terms-of-service'}) ? $self->{links}->{'terms-of-service'} : undef;
}

=head2 tos_changed()

Returns: True if Terms of Service have been changed (or you haven't yet accepted them). Otherwise returns false.

=cut

sub tos_changed {
    return shift->{tos_changed};
}

=head2 new_registration()

Returns: True if new key has been registered. Otherwise returns false.

=cut

sub new_registration {
    return shift->{new_registration};
}

=head2 registration_info()

Returns: Registration information structure returned by Let's Encrypt for your key or undef.

=cut

sub registration_info {
    return shift->{registration_info};
}

=head2 registration_id()

Returns: Registration ID returned by Let's Encrypt for your key or undef.

=cut

sub registration_id {
    return shift->{registration_id};
}

=head2 contact_details()

Returns: Contact details returned by Let's Encrypt for your key or undef.

=cut

sub contact_details {
    return shift->{contact_details};
}

=head2 certificate()

Returns: The last received certificate or undef.

=cut

sub certificate {
    return shift->{certificate};
}

=head2 alternative_certificate()

Returns: Specific alternative certificate as an arrayref (domain, issuer) or undef.

=cut

sub alternative_certificate {
    my ($self, $idx) = @_;
    if ($self->{alternative_certificates} and defined $idx and $idx < @{$self->{alternative_certificates}}) {
        return $self->{alternative_certificates}->[$idx];
    }
    return undef;
}

=head2 alternative_certificates()

Returns: All available alternative certificates (as an arrayref of arrayrefs) or undef.

=cut

sub alternative_certificates {
    my ($self) = @_;
    if ($self->{alternative_certificates}) {
        # Prevent them from being accidentally changed (using the core module to avoid adding more dependencies).
        return dclone $self->{alternative_certificates};
    }
    return undef;
}

=head2 certificate_url()

Returns: The URL of the last received certificate or undef.

=cut

sub certificate_url {
    return shift->{certificate_url};
}

=head2 issuer()

Returns: The issuer's certificate or undef.

=cut

sub issuer {
    return shift->{issuer};
}

=head2 issuer_url()

Returns: The URL of the issuer's certificate or undef.

=cut

sub issuer_url {
    return shift->{issuer_url};
}

=head2 domains()

Returns: An array reference to the loaded domain names or undef.

=cut

sub domains {
    return shift->{loaded_domains};
}

=head2 failed_domains([$all])

Returns: An array reference to the domain names for which processing has failed or undef. If any true value is passed as a parameter, then the list 
will contain domain names which failed on any of the request/accept/verify steps. Otherwise the list will contain the names of the domains failed on 
the most recently called request/accept/verify step.

=cut

sub failed_domains {
    my ($self, $all) = @_;
    return undef unless ($self->{failed_domains} and @{$self->{failed_domains}});
    return $self->{failed_domains}->[-1] unless $all;   
    my %totals;
    foreach my $proc (@{$self->{failed_domains}}) {
        if ($proc) {
            $totals{$_} = undef for @{$proc};
        }
    }
    my @rv = sort keys %totals;
    return @rv ? \@rv : undef;
}

=head2 verified_domains()

Returns: An array reference to the successfully verified domain names.

=cut

sub verified_domains {
    my $self = shift;
    return undef unless ($self->{domains} and %{$self->{domains}});
    my @list = grep { $self->{domains}->{$_} } keys %{$self->{domains}};
    return @list ? \@list : undef;
}

=head2 check_expiration($certificate_file|$scalar_ref|$url, [ \%params ])

Checks the expiration of the certificate. Accepts an URL, a full path to the certificate file or a
scalar reference to a certificate in memory. Optionally a hash ref of parameters can be provided with the
timeout key set to the amount of seconds to wait for the https checks (by default set to 10 seconds).

Returns: Days left until certificate expiration or undef on error. Note - zero and negative values can be
returned for the already expired certificates. On error the status is set accordingly to one of the following:
INVALID_DATA, LOAD_ERROR or ERROR, and the 'error_details' call can be used to get more information about the problem.

=cut

sub check_expiration {
    my ($self, $res, $params) = @_;
    my ($load_error, $exp);
    my $timeout = $params->{timeout} if ($params and (ref $params eq 'HASH'));
    if (!$res or ($timeout and ($timeout!~/^\d+/ or $timeout < 1))) {
        $self->_status(INVALID_DATA, "Invalid parameters");
        return undef;
    } elsif (ref $res or $res!~m~^\w+://~i) {
        my $bio;
        if (ref $res) {
            $bio = Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem());
            $load_error = 1 unless ($bio and Net::SSLeay::BIO_write($bio, $$res));
        } else {
           $bio = Net::SSLeay::BIO_new_file($res, 'r');
           $load_error = 1 unless $bio;
        }
        unless ($load_error) {
            my $cert = Net::SSLeay::PEM_read_bio_X509($bio);
            Net::SSLeay::BIO_free($bio);
            unless ($cert) {
                $self->_status(LOAD_ERROR, "Could not parse the certificate");
                return undef;
            }
            _verify_crt(\$exp)->(0, 0, 0, 0, $cert, 0);
        } else {
            $self->_status(LOAD_ERROR, "Could not load the certificate");
            return undef;
        }
    } else {
        $res=~s/^[^:]+/https/;
        my $probe = HTTP::Tiny->new(
            agent => "Mozilla/5.0 (compatible; Crypt::LE v$VERSION agent; https://Do-Know.com/)",
            verify_SSL => 1,
            timeout => $timeout || 10,
            SSL_options => { SSL_verify_callback => _verify_crt(\$exp) },
            );
        my $response = $probe->head($res);
        $self->_status(ERROR, "Connection error: $response->{status} " . ($response->{reason}||'')) unless $response->{success};
    }
    return $exp;
}

=head2 pem2der($pem)

Returns: DER form of the provided PEM content

=cut

sub pem2der {
    my ($self, $pem) = @_;
    return unless $pem;
    $pem = $1 if $pem=~/(?:^|\s+)-+BEGIN[^-]*-+\s+(.*?)\s+-+END/s;
    $pem=~s/\s+//;
    return decode_base64($pem);
}

=head2 der2pem($der, $type)

Returns: PEM form of the provided DER content of the given type (for example 'CERTIFICATE REQUEST') or undef.

=cut

sub der2pem {
    my ($self, $der, $type) = @_;
    return ($der and $type) ? "-----BEGIN $type-----$/" . encode_base64($der) . "-----END $type-----" : undef;
}

=head2 export_pfx($file, $pass, $cert, $key, [ $ca ], [ $tag ])

Exports given certificate, CA chain and a private key into a PFX/P12 format with a given password.
Optionally you can specify a text to go into pfx instead of the default "Crypt::LE exported".

Returns: OK | UNSUPPORTED | INVALID_DATA | ERROR.

=cut

sub export_pfx {
    my ($self, $file, $pass, $cert, $key, $ca, $tag) = @_;
    my $unsupported = "PFX export is not supported (requires specific build of PKCS12 library for Windows).";
    return $self->_status(UNSUPPORTED, $unsupported) unless $pkcs12_available;
    return $self->_status(INVALID_DATA, "Password is required") unless $pass;
    my $pkcs12 = Crypt::OpenSSL::PKCS12->new();
    eval {
        $pkcs12->create($cert, $key, $pass, $file, $ca, $tag || "Crypt::LE exported");
    };
    return $self->_status(UNSUPPORTED, $unsupported) if ($@ and $@=~/Usage/);
    return $self->_status(ERROR, $@) if $@;
    return $self->_status(OK, "PFX exported to $file.");
}

=head2 error()

Returns: Last error (can be a code or a structure) or undef.

=cut

sub error {
    return shift->{error};
}

=head2 error_details()

Returns: Last error details if available or a generic 'error' string otherwise. Empty string if the last called method returned OK.

=cut

sub error_details {
    my $self = shift;
    if ($self->{error}) {
        my $err = $self->_pull_error($self->{error});
        return $err ? $err : (ref $self->{error}) ? 'error' : $self->{error};
    }
    return '';
}

#====================================================================================================
# Internal Crypto helpers
#====================================================================================================

sub _key {
    my ($key, $type, $attr) = @_;
    my $pk;
    $type||=KEY_RSA;
    return (undef, "Unsupported key type", INVALID_DATA) unless ($type=~/^\d+$/ and $type <= KEY_ECC);
    if ($type == KEY_RSA) {
        $attr||=$keysize;
        return (undef, "Unsupported key size", INVALID_DATA) if ($attr < 2048 or $attr%1024);
    } elsif ($type == KEY_ECC) {
        $attr = $keycurve unless ($attr and $attr ne 'default');
        return (undef, "Unsupported key type - upgrade Net::SSLeay to version 1.75 or better", UNSUPPORTED) unless defined &Net::SSLeay::EC_KEY_generate_key;
    }
    if ($key) {
        my $bio = Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem());
        return (undef, "Could not allocate memory for the key") unless $bio;
        return _free(b => $bio, error => "Could not load the key data") unless Net::SSLeay::BIO_write($bio, $key);
        $pk = Net::SSLeay::PEM_read_bio_PrivateKey($bio);
        _free(b => $bio);
        return (undef, "Could not read the private key") unless $pk;
    } else {
        $pk = Net::SSLeay::EVP_PKEY_new();
        return (undef, "Could not allocate memory for the key") unless $pk;
        my $gen;
        eval {
            $gen = ($type == KEY_RSA) ? Net::SSLeay::RSA_generate_key($attr, &Net::SSLeay::RSA_F4) : Net::SSLeay::EC_KEY_generate_key($attr);
        };
        $@=~s/ at \S+ line \d+.$// if $@;
        return _free(k => $pk, error => "Could not generate the private key '$attr'" . ($@ ? " - $@" : "")) unless $gen;
        ($type == KEY_RSA) ? Net::SSLeay::EVP_PKEY_assign_RSA($pk, $gen) : Net::SSLeay::EVP_PKEY_assign_EC_KEY($pk, $gen);
    }
    return ($pk);
}

sub _csr {
    my ($pk, $domains, $attrib) = @_;
    my $ref = ref $domains;
    return unless ($domains and (!$ref or $ref eq 'ARRAY'));
    return if ($attrib and (ref $attrib ne 'HASH'));
    my $req = Net::SSLeay::X509_REQ_new();
    return _free(k => $pk) unless $req;
    return _free(k => $pk, r => $req) unless (Net::SSLeay::X509_REQ_set_pubkey($req, $pk));
    my @names = $ref ? @{$domains} : split(/\s*,\s*/, $domains);
    $attrib->{CN} = $names[0] unless ($attrib and ($attrib->{CN} or $attrib->{commonName}));
    my $list = join ',', map { 'DNS:' . encode_utf8($_) } @names;
    return _free(k => $pk, r => $req) unless Net::SSLeay::P_X509_REQ_add_extensions($req, &Net::SSLeay::NID_subject_alt_name => $list);
    my $n = Net::SSLeay::X509_NAME_new();
    return _free(k => $pk, r => $req) unless $n;
    foreach my $key (keys %{$attrib}) {
         # Can use long or short names
         return _free(k => $pk, r => $req) unless Net::SSLeay::X509_NAME_add_entry_by_txt($n, $key, MBSTRING_UTF8, encode_utf8($attrib->{$key}));
    }
    return _free(k => $pk, r => $req) unless Net::SSLeay::X509_REQ_set_subject_name($req, $n);
    # Handle old openssl and set the version explicitly unless it is set already to greater than v1 (0 value).
    # NB: get_version will return 0 regardless of whether version is set to v1 or not set at all.
    unless (Net::SSLeay::X509_REQ_get_version($req)) {
        return _free(k => $pk, r => $req) unless Net::SSLeay::X509_REQ_set_version($req, 0);
    }
    my $md = Net::SSLeay::EVP_get_digestbyname('sha256');
    return _free(k => $pk, r => $req) unless ($md and Net::SSLeay::X509_REQ_sign($req, $pk, $md));
    my @rv = (Net::SSLeay::PEM_get_string_X509_REQ($req), Net::SSLeay::PEM_get_string_PrivateKey($pk));
    _free(k => $pk, r => $req);
    return @rv;
}

sub _free {
    my %data = @_;
    Net::SSLeay::X509_REQ_free($data{r}) if $data{r};
    Net::SSLeay::BIO_free($data{b}) if $data{b};
    Net::SSLeay::EVP_PKEY_free($data{k}) if $data{k};
    return wantarray ? (undef, $data{'error'}) : undef;
}

sub _to_hex {
    my $val = shift;
    $val = $val->to_hex;
    $val =~s/^0x//;
    $val = "0$val" if length($val) % 2;
    return $val;
}

#====================================================================================================
# Internal Service helpers
#====================================================================================================

sub _request {
    my $self = shift;
    my ($url, $payload, $opts) = @_;
    unless ($url) {
        my $rv = 'Resource directory does not contain expected fields.';
        return wantarray ? (INVALID_DATA, $rv) : $rv;
    }
    $self->_debug("Connecting to $url");
    $payload = $self->_translate($payload);
    my $resp;
    $opts ||= {};
    my $method = lc($opts->{method} || 'get');
    if (defined $payload or $method eq 'post') {
        $resp = defined $payload ? $self->{ua}->post($url, { headers => $headers, content => $self->_jws($payload, $url, $opts) }) :
                           $self->{ua}->post($url, { headers => $headers });
    } else {
        $resp = $self->{ua}->$method($url);
    }
    my $slurp = ($resp->{headers}->{'content-type'} and $resp->{headers}->{'content-type'}=~/^application\/(?:problem\+)?json/) ? 0 : 1;
    $self->_debug($slurp ? $resp->{headers} : $resp);
    $self->{nonce} = $resp->{headers}->{'replay-nonce'} if $resp->{headers}->{'replay-nonce'};
    my ($status, $rv) = ($resp->{status}, $resp->{content});
    unless ($slurp) {
        eval {
            $rv = $j->decode($rv);
        };
        if ($@) {
            ($status, $rv) = (ERROR, $@);
        }
    }
    $self->{links} = $resp->{headers}->{link} ? $self->_links($resp->{headers}->{link}) : undef;
    $self->{location} = $resp->{headers}->{location} ? $resp->{headers}->{location} : undef;
    return wantarray ? ($status, $rv) : $rv;
}

sub _jwk {
    my $self = shift;
    return unless $self->{key_params};
    return {
        kty => "RSA",
        n   => encode_base64url(pack("H*", _to_hex($self->{key_params}->{n}))),
        e   => encode_base64url(pack("H*", _to_hex($self->{key_params}->{e}))),
    };
}

sub _jws {
    my $self = shift;
    my ($obj, $url, $opts) = @_;
    return unless (defined $obj);
    my $json = ref $obj ? encode_base64url($j->encode($obj)) : "";
    my $protected = { alg => "RS256", jwk => $self->{jwk}, nonce => $self->{nonce} };
    $opts ||= {};
    if ($url and $self->version() > 1) {
        if ($self->{directory}->{reg} and !$opts->{jwk}) {
            $protected->{kid} = $self->{directory}->{reg};
            delete $protected->{jwk};
        }
        $protected->{url} = $url;
    }
    my $header = encode_base64url($j->encode($protected));
    my $sig = encode_base64url($self->{key}->sign("$header.$json"));
    my $jws = $j->encode({ protected => $header, payload => $json, signature => $sig });
    return $jws;
}

sub _links {
    my $self = shift;
    my ($links) = @_;
    return unless $links;
    my $rv;
    foreach my $link ((ref $links eq 'ARRAY') ? @{$links} : ($links)) {
        next unless ($link and $link=~/^<([^>]+)>;rel="([^"]+)"$/i);
        if ($2 eq 'alternate') {
            # We might have more than one alternate link.
            push @{$rv->{$2}}, $1;
        } else {
            $rv->{$2} = $1;
        }
    }
    return $rv;
}

sub _compat {
    my ($self, $content) = @_;
    return unless $content;
    foreach (keys %{$content}) {
        if (my $name = $compat->{$_}) {
            $content->{$name} = delete $content->{$_};
        }
    }
}

sub _compat_response {
    my ($self, $code) = @_;
    return ($self->version() == 2) ? SUCCESS : $code;
}

sub _translate {
    my ($self, $req) = @_;
    return $req if (!$req or $self->version() == 1 or !$req->{'resource'});
    return $req unless my $res = delete $req->{'resource'};
    if ($res eq 'new-reg' or $res eq 'reg') {
        delete $req->{'agreement'};
        $req->{'termsOfServiceAgreed'} = \1;
    } elsif ($res eq 'new-cert') {
        delete $req->{'csr'};
        push @{$req->{'identifiers'}}, { type => 'dns', value => $_ } for @{$self->{loaded_domains}};
    }
    return $req;
}

sub _callback_extras {
    my ($self, $data) = @_;
    return unless ($data and $data->{domain});
    $data->{domain}=~/^(\*\.)?(.+)$/;
    $data->{host} = $2;
    $data->{file} = $data->{token};
    $data->{text} = "$data->{token}.$data->{fingerprint}";
    $data->{record} = encode_base64url(sha256($data->{text}));
}

sub _debug {
    my $self = shift;
    return unless $self->{debug};
    foreach (@_) {
        if (!ref $_) {
            $self->{logger} ? $self->{logger}->debug($_) : print "$_\n";
        } elsif ($self->{debug} > 1) {
            $self->{logger} ? $self->{logger}->debug(Dumper($_)) : print Dumper($_);
        }
    }
}

sub _status {
    my $self = shift;
    my ($code, $data) = @_;
    if ($code == OK) {
        undef $self->{error};
    } else {
        if (ref $data eq 'HASH' and $data->{error}) {
            $self->{error} = $data->{error};
        } else {
            $self->{error} = $data||$code;
        }
    }
    $self->_debug($data) if $data;
    return $code;
}

sub _pull_error {
    my $self = shift;
    my ($err) = @_;
    if ($err and ref $err eq 'HASH') {
        return $err->{error}->{detail} if ($err->{error} and $err->{error}->{detail});
        return $err->{detail} if $err->{detail};
    }
    return '';
}

sub _get_authz {
    my $self = shift;
    return unless $self->{loaded_domains};
    $self->{authz} = [];
    foreach my $domain (@{$self->{loaded_domains}}) {
        push @{$self->{authz}}, [ $self->{directory}->{'new-authz'}, { resource => 'new-authz', identifier => { type => 'dns', value => $domain } } ];
    }
}

sub _file {
    my $self = shift;
    my ($file) = @_;
    return unless $file;
    unless (ref $file) {
        my ($fh, $content) = (new IO::File "<$file");
        if (defined $fh) {
            local $/;
            $fh->binmode;
            $content = <$fh>;
            $fh->close;
        }
        return $content;
    }
    return (ref $file eq 'SCALAR') ? $$file : undef;
}

sub _verify_crt {
    my $exp = shift;
    return sub {
        unless (defined $_[CRT_DEPTH] and $_[CRT_DEPTH]) {
            my ($t, $s);
            eval {
                $t = Net::SSLeay::X509_get_notAfter($_[PEER_CRT]);
                $t = Time::Piece->strptime(Net::SSLeay::P_ASN1_TIME_get_isotime($t), "%Y-%m-%dT%H:%M:%SZ");
            };
            unless ($@) {
                $s = $t - localtime;
                $s = int($s->days);
                $$exp = $s unless ($$exp and $s > $$exp);
            }
        }
    };
}

sub _convert {
    my $self = shift;
    my ($content, $type) = @_;
    return (!$content or $content=~/^\-+BEGIN/) ? $content : $self->der2pem($content, $type);
}

1;

=head1 AUTHOR

Alexander Yezhov, C<< <leader at cpan.org> >>
Domain Knowledge Ltd.
L<https://do-know.com/>

=head1 BUGS

Considering that this module has been written in a rather quick manner after I decided to give a go to Let's Encrypt certificates
and found that CPAN seems to be lacking some easy ways to leverage LE API from Perl, expect some (hopefully minor) bugs. 
The initial goal was to make this work, make it easy to use and possibly remove the need to use openssl command line.

Please report any bugs or feature requests to C<bug-crypt-le at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Crypt-LE>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Crypt::LE


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Crypt-LE>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Crypt-LE>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Crypt-LE>

=item * Search CPAN

L<http://search.cpan.org/dist/Crypt-LE/>

=item * Project homepage

L<https://Do-Know.com/>



=back

=head1 LICENSE AND COPYRIGHT

Copyright 2016-2020 Alexander Yezhov.

This program is free software; you can redistribute it and/or modify it
under the terms of the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

