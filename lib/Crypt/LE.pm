package Crypt::LE;

use 5.006;
use strict;
use warnings;

our $VERSION = '0.20';

=head1 NAME

Crypt::LE - Let's Encrypt API interfacing module.

=head1 VERSION

Version 0.20

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
use Crypt::Format;
use JSON::MaybeXS;
use HTTP::Tiny;
use IO::File;
use Digest::SHA 'sha256';
use MIME::Base64 qw<encode_base64url decode_base64url>;
use Net::SSLeay qw<XN_FLAG_RFC2253 ASN1_STRFLGS_ESC_MSB MBSTRING_UTF8>;
use Scalar::Util 'blessed';
use Encode 'encode_utf8';
use Convert::ASN1;
use Data::Dumper;
use base 'Exporter';

Net::SSLeay::randomize();
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::OpenSSL_add_ssl_algorithms();
Net::SSLeay::OpenSSL_add_all_digests();
our $keysize = 4096;
our $keycurve = 'prime256v1';

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

    SAN                    => '2.5.29.17',
};

our @EXPORT_OK = (qw<OK READ_ERROR LOAD_ERROR INVALID_DATA DATA_MISMATCH UNSUPPORTED ERROR BAD_REQUEST AUTH_ERROR ALREADY_DONE KEY_RSA KEY_ECC>);
our %EXPORT_TAGS = ( 'errors' => [ @EXPORT_OK[0..9] ], 'keys' => [ @EXPORT_OK[10..11] ] );

my $header = 'replay-nonce';
my $j = JSON->new->canonical()->allow_nonref();
my $url_safe = qr/^[-_A-Za-z0-9]+$/; # RFC 4648 section 5.
my $flag_rfc22536_utf8 = (XN_FLAG_RFC2253) & (~ ASN1_STRFLGS_ESC_MSB);

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

=head1 METHODS (API Setup)

The following methods are provided for the API setup. Please note that account key setup by default requests the resource directory from Let's Encrypt servers.
This can be changed by resetting the 'autodir' parameter of the constructor.

=head2 new()

Create a new instance of the class. Initialize the object with passed parameters. Normally you don't need to use any, but the following are supported:

=over 12

=item C<ua>

User-agent name to use while sending requests to Let's Encrypt servers. By default set to module name and version.

=item C<server>

Server URL address to connect to (http or https prefix is required). Only needed if the default live or staging server URLs have changed and this module
has not yet been updated with the new information. You can then explicitly set the URL you need.

=item C<live>

Set to true to connect to a live Let's Encrypt server. By default it is not set, so staging server is used, where you can test the whole process of getting
SSL certificates.

=item C<debug>

Activates printing debug messages to the standard output when set. If set to 1, only standard messages are printed. If set to any greater value, then structures and
server responses are printed as well.

=item C<autodir>

Enables automatic retrieval of the resource directory (required for normal API processing) from Let's Encrypt servers. Enabled by default.

=item C<delay>

Specifies the time in seconds to wait before Let's Encrypt servers are checked for the challenge verification results again. By default set to 2 seconds.
Non-integer values are supported (so for example you can set it to 1.5 if you like).

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
        live    => 0,
        debug   => 0,
        autodir => 1,
        delay   => 2,
    };
    foreach my $key (keys %{$self}) {
        $self->{$key} = $params{$key} if (exists $params{$key} and !ref $params{$key});
    }
    # Init UA
    $self->{ua} = HTTP::Tiny->new( agent => $self->{ua} || __PACKAGE__ . " v$VERSION", verify_SSL => 1 );
    # Init server
    $self->{server} ||= $self->{live} ? 'acme-v01.api.letsencrypt.org' : 'acme-staging.api.letsencrypt.org';
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
        $cn=~s/^.*?\bCN=([^\s,]+).*$/$1/ if $cn;
    }
    my ($san_broken, %alt);
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
    $alt{lc $cn} = undef if $cn;
    if ($san) {
        foreach my $ext (@{$san}) {
            if ($ext->{dNSName}) {
                $alt{lc $ext->{dNSName}} = undef;
            } else {
                $san_broken++;
            }
        }
    }
    _free(b => $bio);
    if ($san_broken) {
        return $self->_status(INVALID_DATA, "CSR contains $san_broken non-DNS record(s) in SAN");
    }
    unless (%alt) {
        return $self->_status(INVALID_DATA, "No domains found on CSR.");
    } else {
        my @list = sort keys %alt;
        if (my $odd = $self->_verify_list(\@list)) {
             return $self->_status(INVALID_DATA, "Unsupported domain names on CSR: " . join(", ", @{$odd}));
        }
        $self->_debug("Loaded domain names from CSR: " . join(', ', @list));
    }
    if (my %loaded_domains = map {$_, undef} @list) {
        unless (join(',', sort keys %loaded_domains) eq join(',', sort keys %alt)) {
            return $self->_status(DATA_MISMATCH, "The list of provided domains does not match the one on the CSR.");
        }
    }
    $self->_set_csr($csr, undef, \%alt);
    return $self->_status(OK, "CSR loaded.");
}

=head2 generate_csr($domains, [$key_type], [$key_attr])

Generates a new Certificate Signing Request. Optionally accepts key type and key attribute parameters, where key type should
be either KEY_RSA or KEY_ECC (if supported on your system) and key attribute is either the key size (for RSA) or the curve (for ECC).
By default an RSA key of 4096 bits will be used.
Domains list is mandatory and can be given as a string of comma-separated names or as an array reference.

Returns: OK | ERROR | INVALID_DATA.

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
    my %loaded_domains = map {$_, undef} @list;
    $self->_set_csr($csr, $csr_key, \%loaded_domains);
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
    my %loaded_domains = map {$_, undef} @list;
    $self->{domains} = \%loaded_domains;
    return $self->_status(OK, "Domains list is set");
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
    undef $self->{$_} for qw<domains csr>;
}

sub _set_csr {
    my $self = shift;
    my ($csr, $pk, $domains) = @_;
    $self->{csr} = $csr;
    $self->{csr_key} = $pk;
    $self->{domains} = $domains;
}

sub _get_list {
    my ($self, $list) = @_;
    return [ map {lc $_} (ref $list eq 'ARRAY') ? @{$list} : $list ? split /\s*,\s*/, $list : () ];
}

sub _verify_list {
    my ($self, $list) = @_;
    my @odd = grep { /[\[\{\(\<\*\@\>\)\}\]\/\\:]/ or /^[\d\.]+$/ or !/\./ } @{$list};
    return @odd ? \@odd : undef;
}

#====================================================================================================
# API Workflow functions
#====================================================================================================

=head1 METHODS (API Workflow)

The following methods are provided for the API workflow processing. All but C<accept_challenge()> methods interact with Let's Encrypt servers.

=head2 directory()

Loads resource pointers from Let's Encrypt. This method needs to be called before the registration. It
will be called automatically upon account key loading/generation unless you have reset the 'autodir'
parameter when creating a new Crypt::LE instance.

Returns: OK | LOAD_ERROR.

=cut

sub directory {
    my $self = shift;
    unless ($self->{directory}) {
        my ($status, $content) = $self->_request("https://$self->{server}/directory");
        if ($status == SUCCESS) {
            $self->{directory} = $content;
            return $self->_status(OK, "Directory loaded successfully.");
        } else {
            return $self->_status(LOAD_ERROR, $content);
        }
    }
    return $self->_status(OK, "Directory has been already loaded.");
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
    $self->{registration_id} = undef;
    if ($status == ALREADY_DONE) {
        $self->{new_registration} = 0;
        $self->_debug("Key is already registered, reg path: $self->{directory}->{reg}.");
        ($status, $content) = $self->_request($self->{directory}->{'reg'}, { resource => 'reg' });
        if ($status == ACCEPTED) {
            $self->{registration_info} = $content;
            if ($self->{links} and $self->{links}->{'terms-of-service'} and (!$content->{agreement} or ($self->{links}->{'terms-of-service'} ne $content->{agreement}))) {
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
        $self->{tos_changed} = 1 if $self->{links}->{'terms-of-service'};
        $self->_debug("New key is now registered, reg path: $self->{directory}->{reg}. You need to accept TOS at $self->{links}->{'terms-of-service'}");
    } else {
        return $self->_status(ERROR, $content);
    }
    $self->{registration_id} = $self->{registration_info}->{id} if ($self->{registration_info} and ref $self->{registration_info} eq 'HASH');
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
    my ($status, $content) = $self->_request($self->{directory}->{'reg'}, { resource => 'reg', agreement => $self->{links}->{'terms-of-service'}, key => $self->{jwk} });
    return ($status == ACCEPTED) ? $self->_status(OK, "Accepted TOS.") : $self->_status(ERROR, $content);
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
    foreach my $domain (sort keys %{$self->{domains}}) {
        if (defined $self->{domains}->{$domain}) {
            $self->_debug("Domain $domain " . ($self->{domains}->{$domain} ? "has been already validated, skipping." : "challenge has been already requested, skipping."));
            next;
        }
        $self->_debug("Requesting challenge for domain $domain.");
        my ($status, $content) = $self->_request($self->{directory}->{'new-authz'}, { resource => 'new-authz', identifier => { type => 'dns', value => $domain } });
        $domains_requested++;
        if ($status == CREATED) {
            foreach my $challenge (@{$content->{challenges}}) {
                unless ($challenge and (ref $challenge eq 'HASH') and $challenge->{type} and $challenge->{uri} and $challenge->{status}) {
                    $self->_debug("Challenge for domain $domain does not contain required fields.");
                    next;
                }
                my $type = (split '-', delete $challenge->{type})[0];
                unless ($challenge->{token} and $challenge->{token}=~$url_safe) {
                    $self->_debug("Challenge ($type) for domain $domain is missing a valid token.");
                    next;
                }
                $self->{challenges}->{$domain}->{$type} = $challenge;
            }
            if ($self->{challenges} and exists $self->{challenges}->{$domain}) {
                $self->_debug("Received challenges for $domain.");
                $self->{domains}->{$domain} = 0;
            } else {
                $self->_debug("Received no valid challenges for $domain.");
                $domains_failed{$domain} = $self->_pull_error($content)||'No valid challenges';
            }
        } else {
            my $err = $self->_pull_error($content);
            $self->_debug("Failed to receive challenges for $domain. $err");
            $domains_failed{$domain} = $err||'Failed to receive challenges';
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
    return $self->_status(OK, $domains_requested ? "Requested challenges for $domains_requested domain(s)." : "There are no domains which were not yet requested for challenges.");
}

=head2 accept_challenge($callback [, $params] [, $type])

Sets up a callback, which will be called for each non-verified domain to satisfy the requested challenge. Each callback will receive two parameters -
a hash reference with the challenge data and a hash reference of parameters optionally passed to accept_challenge(). The challenge data has the following keys:

=over 14

=item C<domain>

The domain name being processed (lower-case)

=item C<token>

The challenge token

=item C<fingerprint>
 
The account key fingerprint

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
    foreach my $domain (sort keys %{$self->{domains}}) {
        unless (defined $self->{domains}->{$domain} and !$self->{domains}->{$domain}) {
            $self->_debug($self->{domains}->{$domain} ? "Domain $domain has been already validated, skipping." : "Challenge has not yet been requested for domain $domain, skipping.");
            next;
        }
        unless ($self->{challenges}->{$domain} and $self->{challenges}->{$domain}->{$type}) {
            $self->_debug("Could not find a challenge of type $type for domain $domain.");
            push @domains_failed, $domain;
        }
        my $rv;
        my $callback_data = { domain => $domain, token => $self->{challenges}->{$domain}->{$type}->{token}, fingerprint => $self->{fingerprint}, logger => $self->{logger} };
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

=item C<token>

The challenge token

=item C<fingerprint>
 
The account key fingerprint

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
    foreach my $domain (sort keys %{$self->{domains}}) {
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
        if ($status == ACCEPTED) {
            if ($content->{uri}) {
                my $check = $content->{uri};
                while ($status == ACCEPTED and $content and $content->{status} and $content->{status} eq 'pending') {
                    select(undef, undef, undef, $self->{delay});
                    ($status, $content) = $self->_request($check);
                }
                if ($status == ACCEPTED and $content and $content->{status}) {
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
    my $csr = encode_base64url(Crypt::Format::pem2der($self->{csr}));
    my ($status, $content) = $self->_request($self->{directory}->{'new-cert'}, { resource => 'new-cert', csr => $csr });
    if ($status == CREATED) {
        $self->{certificate} = $self->_convert($content, 'CERTIFICATE');
        $self->{certificate_url} = $self->{location};
        $self->{issuer_url} = ($self->{links} and $self->{links}->{up}) ? $self->{links}->{up} : undef;
        return $self->_status(OK, "Domain certificate has been received." . ($self->{issuer_url} ? " Issuer's certificate can be found at: $self->{issuer_url}" : ""));
    }
    return $self->_status($status == AUTH_ERROR ? AUTH_ERROR : ERROR, $content);
}

=head2 request_issuer_certificate()

Requests the issuer's certificate.

Returns: OK | ERROR.

=cut

sub request_issuer_certificate {
    my $self = shift;
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
    my ($status, $content) = $self->_request($self->{directory}->{'revoke-cert'}, { resource => 'revoke-cert', certificate => encode_base64url(Crypt::Format::pem2der($crt)) });
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

=head2 certificate()

Returns: The last received certificate or undef.

=cut

sub certificate {
    return shift->{certificate};
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

Returns: An array reference to the domain names loaded from CSR or undef.

=cut

sub domains {
    my $self = shift;
    return $self->{domains} ? [ sort keys %{$self->{domains}} ] : undef;
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
    my ($url, $payload) = @_;
    my $resp = $payload ? $self->{ua}->post($url, { content => $self->_jws($payload) }) : $self->{ua}->get($url);
    my $slurp = ($resp->{headers}->{'content-type'} and $resp->{headers}->{'content-type'}=~/^application\/(?:problem\+)?json/) ? 0 : 1;
    $self->_debug($slurp ? $resp->{headers} : $resp);
    $self->{nonce} = $resp->{headers}->{$header};
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
    my ($obj) = @_;
    return unless ($obj and ref $obj);
    my $json = encode_base64url($j->encode($obj));
    my $header = encode_base64url('{"nonce":"' . $self->{nonce} . '"}');
    my $sig = encode_base64url($self->{key}->sign("$header.$json"));
    my $jws = $j->encode({ header => { alg => "RS256", jwk => $self->{jwk} }, protected => $header, payload => $json, signature => $sig });
    return $jws;
}

sub _links {
    my $self = shift;
    my ($links) = @_;
    return unless $links;
    my $rv;
    foreach my $link ((ref $links eq 'ARRAY') ? @{$links} : ($links)) {
        next unless ($link and $link=~/^<([^>]+)>;rel="([^"]+)"$/i);
        $rv->{$2} = $1;
    }
    return $rv;
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

sub _convert {
    my $self = shift;
    my ($content, $type) = @_;
    return (!$content or $content=~/^\-+BEGIN/) ? $content : Crypt::Format::der2pem($content, $type);
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

L<https://ZeroSSL.com/>

=item * Company homepage

L<https://Do-Know.com/>



=back

=head1 LICENSE AND COPYRIGHT

Copyright 2016 Alexander Yezhov.

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

