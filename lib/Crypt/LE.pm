package Crypt::LE;

use 5.006;
use strict;
use warnings;

our $VERSION = '0.12';

=head1 NAME

Crypt::LE - Let's Encrypt API interfacing module.

=head1 VERSION

Version 0.12

=head1 SYNOPSIS

 use Crypt::LE;
 use File::Slurp;
    
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
 write_file('domain.cert', $cert) if $cert;
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
use Crypt::PKCS10;
use Crypt::Format;
use JSON::MaybeXS;
use HTTP::Tiny;
use IO::File;
use Digest::SHA 'sha256';
use MIME::Base64 'encode_base64url';
use Scalar::Util 'blessed';
use Data::Dumper;
use base 'Exporter';

our $keysize = 4096;
my $pkcs10_available = 0;

# At the moment, to make LE client self-sufficient (so there's no need to generate keys or CSR with openssl),
# Crypt::OpenSSL::PKCS10 is offered as 'required' rather than 'recommended'. Depending on feedback it might
# be moved to 'recommended' later, but the code will perform fine even without it. You will get a warning if
# you try to generate a CSR and that module is not available.

eval "use Crypt::OpenSSL::PKCS10;";
unless ($@) {
    $pkcs10_available = 1;
}
Crypt::PKCS10->setAPIversion(1);
Crypt::OpenSSL::RSA->import_random_seed();

use constant OK                     => 0;
use constant READ_ERROR             => 1;
use constant LOAD_ERROR             => 2;
use constant INVALID_DATA           => 3;
use constant DATA_MISMATCH          => 4;
use constant ERROR                  => 500;

use constant SUCCESS                => 200;
use constant CREATED                => 201;
use constant ACCEPTED               => 202;
use constant AUTH_ERROR             => 403;
use constant ALREADY_DONE           => 409;

use constant NID_subject_alt_name   => 85;

our @EXPORT_OK = (qw<OK READ_ERROR LOAD_ERROR INVALID_DATA DATA_MISMATCH ERROR AUTH_ERROR ALREADY_DONE>);
our %EXPORT_TAGS = ( errors => [ @EXPORT_OK ] );

my $header = 'replay-nonce';
my $j = JSON->new->canonical()->allow_nonref();

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

=head2 load_account_key($filename)

Loads the private account key from the file in PEM or DER formats.

Returns: OK | READ_ERROR | LOAD_ERROR | INVALID_DATA.

=cut

sub load_account_key {
    my $self = shift;
    my $file = shift;
    $self->_reset_key;
    my $key = $self->_file($file);
    return $self->_status(READ_ERROR, "Key reading error.") unless $key;
    eval {
        $key = Crypt::OpenSSL::RSA->new_private_key($self->_convert($key, 'RSA PRIVATE KEY'));
    };
    return $self->_status(LOAD_ERROR, "Key loading error.") if $@;
    return $self->_status(INVALID_DATA, "Key modulus is divisible by a small prime and will be rejected.") if $self->_is_divisible($key);
    return $self->_set_key($key, "Account key loaded.");
}

=head2 generate_account_key()

Generates a new private account key of the $keysize bits (4096 by default). The key is additionally validated for not being divisible by small primes.

Returns: OK | INVALID_DATA.

=cut

sub generate_account_key {
    my $self = shift;
    my $key = Crypt::OpenSSL::RSA->new_private_key(Crypt::OpenSSL::RSA->generate_key($keysize)->get_private_key_string);
    return $self->_status(INVALID_DATA, "Key modulus is divisible by a small prime and will be rejected.") if $self->_is_divisible($key);
    return $self->_set_key($key, "Account key generated.");
}

=head2 account_key()

Returns: A previously loaded or generated private key in PEM format or undef.

=cut

sub account_key {
    my $self = shift;
    return $self->{key} ? $self->{key}->get_private_key_string : undef;
}

=head2 load_csr($filename [, $domains])

Loads Certificate Signing Requests from file. Domains list can be omitted or it can be given as a string of comma-separated names or as an array reference.
If omitted, then names will be loaded from the CSR. If it is given, then the list of names will be verified against those found on CSR.

Returns: OK | READ_ERROR | LOAD_ERROR | INVALID_DATA | DATA_MISMATCH.

=cut

sub load_csr {
    my $self = shift;
    my ($file, $domains) = @_;
    $self->_reset_csr;
    my $csr = $self->_file($file);
    return $self->_status(READ_ERROR, "CSR reading error.") unless $csr;
    $csr = $self->_convert($csr, 'CERTIFICATE REQUEST');
    my $decoded;
    eval {
        $decoded = Crypt::PKCS10->new($csr);
    };
    return $self->_status(LOAD_ERROR, "CSR loading error." . ($@ ? " $@" : "")) unless $decoded;
    my @list = (ref $domains eq 'ARRAY') ? @{$domains} : $domains ? split /\s*,\s*/, $domains : ();
    my $cn = $decoded->commonName;
    my %alt = map {lc $_, undef} $decoded->subjectAltName('dNSName');
    $alt{lc $cn} = undef if $cn;
    unless (%alt) {
        return $self->_status(INVALID_DATA, "No domains found on CSR.");
    } else {
        $self->_debug("Loaded domain names from CSR: " . join(', ', sort keys %alt));
    }
    if (my %loaded_domains = map {lc $_, undef} @list) {
        unless (join(',', sort keys %loaded_domains) eq join(',', sort keys %alt)) {
            return $self->_status(DATA_MISMATCH, "The list of provided domains does not match the one on the CSR.");
        }
    }
    $self->_set_csr($csr, undef, \%alt);
    return $self->_status(OK, "CSR loaded.");
}

=head2 generate_csr($domains)

Generates a new Certificate Signing Requests based on a new RSA key of $keysize bits (4096 by default). 
Domains list is mandatory and can be given as a string of comma-separated names or as an array reference.

Returns: OK | ERROR | INVALID_DATA.

=cut

sub generate_csr {
    my $self = shift;
    my $domains = shift;
    return $self->_status(ERROR, "To generate CSR you need Crypt::OpenSSL::PKCS10 module installed.") unless $pkcs10_available;
    # NB: Crypt::OpenSSL::PKCS10 has its quirks, such as issues with DESTROY in PKCS10.xs and segfaults on an attempt 
    # to read non-existent CSR from file. It should work for this particular task though.
    $self->_reset_csr;
    my @list = map {lc $_} (ref $domains eq 'ARRAY') ? @{$domains} : $domains ? split /\s*,\s*/, $domains : ();
    return $self->_status(INVALID_DATA, "No domains provided.") unless @list;
    my $rsa = Crypt::OpenSSL::RSA->generate_key($keysize);
    my $csr = Crypt::OpenSSL::PKCS10->new_from_rsa($rsa);
    $csr->set_subject("/CN=$list[0]");
    if (@list > 1) {
        $csr->add_ext(NID_subject_alt_name, join(",", map {"DNS:$_"} @list));
        $csr->add_ext_final();
    }
    $csr->sign;
    my %loaded_domains = map {$_, undef} @list;
    $self->_set_csr($csr->get_pem_req, $rsa->get_private_key_string, \%loaded_domains);
    return $self->_status(OK, "CSR generated.");
}

=head2 csr()

Returns: A previously loaded or generated CSR in PEM format or undef.

=cut

sub csr {
    return shift->{csr};
}

=head2 csr_key()

Returns: A private key of a previously generated CSR in PEM format or undef.

=cut

sub csr_key {
    return shift->{csr_key};
}

=head2 set_account_email([$email])

Sets (or resets if no parameter is given) an email address that will be used for registration requests.

Returns: OK | INVALID_DATA.

=cut

sub set_account_email {
    my $self = shift;
    my $email = shift;
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

#====================================================================================================
# API Setup helpers
#====================================================================================================

sub _reset_key {
    my $self = shift;
    undef $self->{$_} for qw<key jwk fingerprint>;
}

sub _set_key {
    my $self = shift;
    my ($key, $msg) = @_;
    return $self->_status(INVALID_DATA, "Key modulus is divisible by a small prime and will be rejected.") if (!$key or $self->_is_divisible($key));
    $key->use_pkcs1_padding;
    $key->use_sha256_hash;
    $self->{key} = $key;
    $self->{jwk} = $self->_jwk($key);
    $self->{fingerprint} = encode_base64url(sha256($j->encode($self->{jwk})));
    if ($self->{autodir}) {
        my $status = $self->directory;
        return $status unless ($status == OK);
    }
    return $self->_status(OK, $msg);
}

sub _is_divisible {
    my $self = shift;
    my $key = shift;
    my $n = ($key->get_key_parameters)[0];
    my $ctx = Crypt::OpenSSL::Bignum::CTX->new();
    my ($quotient, $remainder);
    foreach my $prime (@primes) {
        ($quotient, $remainder) = $n->div($prime, $ctx);
        return 1 if $remainder->is_zero;
    }
    return 0;
}

sub _reset_csr {
    my $self = shift;
    undef $self->{$_} for qw<domains csr csr_key>;
}

sub _set_csr {
    my $self = shift;
    my ($csr, $pk, $domains) = @_;
    $self->{csr} = $csr;
    $self->{csr_key} = $pk;
    $self->{domains} = $domains;
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
    my ($domains_requested, @domains_failed);
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
                next unless ($challenge and (ref $challenge eq 'HASH') and $challenge->{type} and $challenge->{uri} and $challenge->{status});
                my $type = delete $challenge->{type};
                $type = (split '-', $type)[0];
                $self->{challenges}->{$domain}->{$type} = $challenge;
            }
            $self->_debug("Received challenges for $domain.");
            $self->{domains}->{$domain} = 0;
        } else {
            $self->_debug("Failed to receive challenges for $domain.");
            push @domains_failed, $domain;
        }
    }
    if (@domains_failed) {
        $self->{failed_domains} = \@domains_failed;
        return $self->_status(ERROR, @domains_failed == $domains_requested ? "All domains failed" : "Some domains failed: " . join(", ", @domains_failed));
    } else {
        undef $self->{failed_domains};
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
        $self->{failed_domains} = \@domains_failed;
        return $self->_status(ERROR, $domains_accepted ? "Challenges failed for domains: " . join(", ", @domains_failed) : "All challenges failed");
    } else {
        undef $self->{failed_domains};
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
                            $self->{domains}->{$domain} = 1;
                            $validated = 1;
                        }
                    }
                }
            }
        }
        if ($cb) {
            my $rv;
            my $error = (ref $content eq 'HASH' and $content->{error} and $content->{error}->{detail}) ? $content->{error}->{detail} : '';
            my $callback_data = { 
                                    domain => $domain, 
                                    token => $self->{challenges}->{$domain}->{$type}->{token},
                                    fingerprint => $self->{fingerprint}, 
                                    valid => $validated, 
                                    error => $error,
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
            $domains_verified++;
        } else {
            $self->_debug("Domain $domain has failed verification (status code $status).", $content) unless $cb_reset;
            push @domains_failed, $domain;
        }
    }
    if (@domains_failed) {
        $self->{failed_domains} = \@domains_failed;
        return $self->_status(ERROR, $domains_verified ? "Verification failed for domains: " . join(", ", @domains_failed) : "All verifications failed");
    } else {
        undef $self->{failed_domains};
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

=head2 revoke_certificate($certificate_file)

Revokes a certificate.

Returns: OK | READ_ERROR | ALREADY_DONE | ERROR.

=cut

sub revoke_certificate {
    my $self = shift;
    my $file = shift;
    my $crt = $self->_file($file);
    return $self->_status(READ_ERROR, "Could not read the certificate from '$file'.") unless $crt;
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

=head2 failed_domains()

Returns: An array reference to the domain names for which challenge processing has failed (on any of request/accept/verify steps) or undef.

=cut

sub failed_domains {
    return shift->{failed_domains};
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
        if ((ref $self->{error} eq 'HASH') and $self->{error}->{detail}) {
            return $self->{error}->{detail};
        } elsif (ref $self->{error}) {
            return 'error';
        } else {
            return $self->{error};
        }
    }
    return '';
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
    my $key = shift;
    return unless $key;
    my ($n, $e) = $key->get_key_parameters;
    for ($n, $e) {
      $_ = $_->to_hex;
      $_ = "0$_" if length($_) % 2;
    }
    return {
        kty => "RSA",
        n   => encode_base64url(pack("H*", $n)),
        e   => encode_base64url(pack("H*", $e)),
    };
}

sub _jws {
    my $self = shift;
    my ($obj) = @_;
    return undef unless ($obj and ref $obj);
    my $json = encode_base64url($j->encode($obj));
    my $header = encode_base64url('{"nonce":"' . $self->{nonce} . '"}');
    my $sig = encode_base64url($self->{key}->sign("$header.$json"));
    my $jws = $j->encode({ header => { alg => "RS256", jwk => $self->{jwk} }, protected => $header, payload => $json, signature => $sig });
    return $jws;
}

sub _links {
    my $self = shift;
    my ($links) = @_;
    return undef unless $links;
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

sub _file {
    my $self = shift;
    my ($file) = @_;
    return unless $file;
    my ($fh, $content) = (new IO::File "<$file");
    if (defined $fh) {
        local $/;
        $fh->binmode;
        $content = <$fh>;
        $fh->close;
    }
    return $content;
}

sub _convert {
    my $self = shift;
    my ($content, $type) = @_;
    return (!$content or $content=~/^\-+BEGIN/) ? $content : Crypt::Format::der2pem($content, $type);
}

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

1;
