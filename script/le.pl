#!/usr/bin/env perl
use strict;
use warnings;
use Getopt::Long;
use IO::File;
use JSON::MaybeXS;
use HTTP::Tiny;
use Net::SSLeay;
use Time::Piece;
use Time::Seconds;
use Log::Log4perl;
use Module::Load;
use Encode 'decode';
use Digest::SHA 'sha256';
use MIME::Base64 'encode_base64url';
use Crypt::LE ':errors', ':keys';
use utf8;

my $VERSION = '0.23';

use constant PEER_CRT  => 4;
use constant CRT_DEPTH => 5;

exit main();

sub main {
    Log::Log4perl->easy_init({ utf8  => 1 });
    my $opt = { logger => Log::Log4perl->get_logger(), e => encode_args() };
    binmode(STDOUT, ":encoding(UTF-8)");
    if (my $rv = work($opt)) {
        $opt->{logger}->error($rv->{'msg'}) if $rv->{'msg'};
        return defined $rv->{'code'} ? $rv->{'code'} : 255;
    }
    return 0;
}

sub work {
    my $opt = shift;
    my $rv = parse_options($opt);
    return $rv if $rv;

    my $le = Crypt::LE->new(autodir => 0, debug => $opt->{'debug'}, live => $opt->{'live'}, logger => $opt->{'logger'});

    if (-r $opt->{'key'}) {
        $opt->{'logger'}->info("Loading an account key from $opt->{'key'}");
        $le->load_account_key($opt->{'key'}) == OK or return _error("Could not load an account key: " . $le->error_details);
    } else {
        $opt->{'logger'}->info("Generating a new account key");
        $le->generate_account_key == OK or return _error("Could not generate an account key: " . $le->error_details);
        $opt->{'logger'}->info("Saving generated account key into $opt->{'key'}");
        return _error("Failed to save an account key file") if _write($opt->{'key'}, $le->account_key);
    }

    if ($opt->{'revoke'}) {
        return _error("Name of the certificate file should be specified.") unless $opt->{'crt'};
        my $crt = _read($opt->{'crt'});
        return _error("Could not read the certificate file.") unless $crt;
        # Take the first certificate in file, disregard the issuer's one.
        $crt=~s/^(.*?-+\s*END CERTIFICATE\s*-+).*/$1/s;
        my $rv = $le->revoke_certificate(\$crt);
        if ($rv == OK) {
            $opt->{'logger'}->info("Certificate has been revoked.");
        } elsif ($rv == ALREADY_DONE) {
            $opt->{'logger'}->info("Certificate has been ALREADY revoked.");
        } else {
            return _error("Problem with revoking certificate: " . $le->error_details);
        }
        return;
    }

    if ($opt->{'domains'} and !$opt->{'e'}) {
        my @domains = grep { $_ } split /\s*\,\s*/, $opt->{'domains'};
        $opt->{'domains'} = join ",", map { _puny($_) } @domains;
    }
    if (-r $opt->{'csr'}) {
        $opt->{'logger'}->info("Loading a CSR from $opt->{'csr'}");
        $le->load_csr($opt->{'csr'}, $opt->{'domains'}) == OK or return _error("Could not load a CSR: " . $le->error_details);
        return _error("For multi-webroot path usage, the amount of paths given should match the amount of domain names listed.") if _path_mismatch($le, $opt);
    } else {
        return _error("For multi-webroot path usage, the amount of paths given should match the amount of domain names listed.") if _path_mismatch($le, $opt);
        $opt->{'logger'}->info("Generating a new CSR for domains $opt->{'domains'}");
        if (-e $opt->{'csr-key'}) {
             # Allow using pre-existing key when generating CSR
             return _error("Could not load existing CSR key from $opt->{'csr-key'} - " . $le->error_details) if $le->load_csr_key($opt->{'csr-key'});
             $opt->{'logger'}->info("New CSR will be based on '$opt->{'csr-key'}' key");
        } else {
             $opt->{'logger'}->info("New CSR will be based on a generated key");
        }
        my ($type, $attr) = $opt->{'curve'} ? (KEY_ECC, $opt->{'curve'}) : (KEY_RSA, $opt->{'legacy'} ? 2048 : 4096);
        $le->generate_csr($opt->{'domains'}, $type, $attr) == OK or return _error("Could not generate a CSR: " . $le->error_details);
        $opt->{'logger'}->info("Saving a new CSR into $opt->{'csr'}");
        return "Failed to save a CSR" if _write($opt->{'csr'}, $le->csr);
        unless (-e $opt->{'csr-key'}) {
            $opt->{'logger'}->info("Saving a new CSR key into $opt->{'csr-key'}");
            return _error("Failed to save a CSR key") if _write($opt->{'csr-key'}, $le->csr_key);
        }
    }

    return if $opt->{'generate-only'};

    if ($opt->{'renew'}) {
        if ($opt->{'crt'} and -r $opt->{'crt'}) {
            $opt->{'logger'}->info("Checking certificate for expiration (local file).");
            verify_crt_file($opt);
            $opt->{'logger'}->warn("Problem checking existing certificate file.") unless (defined $opt->{'expires'});
        }
        unless (defined $opt->{'expires'}) {
            $opt->{'logger'}->info("Checking certificate for expiration (website connection).");
            my $probe = HTTP::Tiny->new( agent => "Mozilla/5.0 (compatible; ZeroSSL Crypt::LE v$VERSION renewal agent; https://ZeroSSL.com/)", verify_SSL => 1, timeout => 10, SSL_options => { SSL_verify_callback => verify_crt($opt) } );
            foreach my $domain (@{$le->domains}) {
                $opt->{'logger'}->info("Checking $domain");
                $probe->head("https://$domain/");
                last if (defined $opt->{'expires'});
            }
        }
        return _error("Could not get the certificate expiration value, cannot renew.") unless (defined $opt->{'expires'});
        if ($opt->{'expires'} > $opt->{'renew'}) {
            $opt->{'logger'}->info("Too early for renewal, certificate expires in $opt->{'expires'} days.");
            return;
        }
        $opt->{'logger'}->info("Expiration threshold set at $opt->{'renew'} days, the certificate " . ($opt->{'expires'} < 0 ? "has already expired" : "expires in $opt->{'expires'} days") . " - will be renewing.");
    }
    
    if ($opt->{'email'}) {
        return _error($le->error_details) if $le->set_account_email($opt->{'email'});
    }
    return _error("Could not load the resource directory: " . $le->error_details) if $le->directory;
    $opt->{'logger'}->info("Registering the account key");
    return _error($le->error_details) if $le->register;
    my $current_account_id = $le->registration_id||'unknown';
    $opt->{'logger'}->info($le->new_registration ? "The key has been successfully registered. ID: $current_account_id" : "The key is already registered. ID: $current_account_id");
    $opt->{'logger'}->info("Make sure to check TOS at " . $le->tos) if ($le->tos_changed and $le->tos);
    $le->accept_tos();
    # We might not need to re-verify, verification holds for a while.
    my $new_crt_status = $le->request_certificate();
    unless ($new_crt_status) {
        $opt->{'logger'}->info("Received domain certificate, no validation required at this time.");
    } else {
        # If it's not an auth problem, but blacklisted domains for example - stop.
        return _error("Error requesting certificate: " . $le->error_details) if $new_crt_status != AUTH_ERROR;
        # Add multi-webroot option to parameters passed if it is set.
        $opt->{'handle-params'}->{'multiroot'} = $opt->{'multiroot'} if $opt->{'multiroot'};
        # Handle DNS internally along with HTTP
        my ($challenge_handler, $verification_handler) = ($opt->{'handler'}, $opt->{'handler'});
        if (!$opt->{'handler'}) {
            if ($opt->{'handle-as'}) {
                return _error("Only 'http' and 'dns' can be handled internally, use external modules for other verification types.") unless $opt->{'handle-as'}=~/^(http|dns)$/i;
                if (lc($1) eq 'dns') {
                    ($challenge_handler, $verification_handler) = (\&process_challenge_dns, \&process_verification_dns);
                }
            }
        }
        return _error($le->error_details) if $le->request_challenge();
        return _error($le->error_details) if $le->accept_challenge($challenge_handler || \&process_challenge, $opt->{'handle-params'}, $opt->{'handle-as'});
        return _error($le->error_details) if $le->verify_challenge($verification_handler || \&process_verification, $opt->{'handle-params'}, $opt->{'handle-as'});
    }
    unless ($le->certificate) {
        $opt->{'logger'}->info("Requesting domain certificate.");
        return _error($le->error_details) if $le->request_certificate();
    }
    $opt->{'logger'}->info("Requesting issuer's certificate.");
    if ($le->request_issuer_certificate()) {
        $opt->{'logger'}->error("Could not download an issuer's certificate, try to download manually from " . $le->issuer_url);
        $opt->{'logger'}->warn("Will be saving the domain certificate alone, not the full chain.");
        return _error("Failed to save the domain certificate file") if _write($opt->{'crt'}, $le->certificate);
    } else {
        unless ($opt->{'legacy'}) {
            $opt->{'logger'}->info("Saving the full certificate chain to $opt->{'crt'}.");
            return _error("Failed to save the domain certificate file") if _write($opt->{'crt'}, $le->certificate . "\n" . $le->issuer . "\n");
        } else {
            $opt->{'logger'}->info("Saving the domain certificate to $opt->{'crt'}.");
            return _error("Failed to save the domain certificate file") if _write($opt->{'crt'}, $le->certificate);
            $opt->{'crt'}=~s/\.[^\.]+$//;
            $opt->{'crt'}.='.ca';
            $opt->{'logger'}->info("Saving the issuer's certificate to $opt->{'crt'}.");
            $opt->{'logger'}->error("Failed to save the issuer's certificate, try to download manually from " . $le->issuer_url) if _write($opt->{'crt'}, $le->issuer);
        }
    }
    if ($opt->{'complete-handler'}) {
        # Add multi-webroot option to parameters passed if it is set.
        $opt->{'complete-params'}->{'multiroot'} = $opt->{'multiroot'} if $opt->{'multiroot'};
        my $data = {
            # Note, certificate here is just a domain certificate, issuer is passed separately - so handler could merge those or use them separately as well.
            certificate => $le->certificate, certificate_file => $opt->{'crt'}, key_file => $opt->{'csr-key'}, issuer => $le->issuer, 
            domains => $le->domains, logger => $opt->{'logger'},
        };
        my $rv;
        eval {
            $rv = $opt->{'complete-handler'}->complete($data, $opt->{'complete-params'});
        };
        if ($@ or !$rv) {
            return _error("Completion handler " . ($@ ? "thrown an error: $@" : "did not return a true value"));
        }
    }

    $opt->{'logger'}->info("===> NOTE: You have been using the test server for this certificate. To issue a valid trusted certificate add --live option.") unless $opt->{'live'};
    $opt->{'logger'}->info("The job is done, enjoy your certificate! For feedback and bug reports contact us at [ https://ZeroSSL.com | https://Do-Know.com ]\n");
    return { code => $opt->{'issue-code'}||0 };
}

sub parse_options {
    my $opt = shift;
    my $args = @ARGV;

    GetOptions ($opt, 'key=s', 'csr=s', 'csr-key=s', 'domains=s', 'path=s', 'crt=s', 'email=s', 'curve=s', 'renew=i',
        'issue-code=i', 'handle-with=s', 'handle-as=s', 'handle-params=s', 'complete-with=s', 'complete-params=s', 'log-config=s',
        'generate-missing', 'generate-only', 'revoke', 'legacy', 'unlink', 'live', 'debug', 'help') || return _error("Use --help to see the usage examples.");

    usage_and_exit($opt) unless ($args and !$opt->{'help'});
    my $rv = reconfigure_log($opt);
    return $rv if $rv;

    $opt->{'logger'}->info("[ ZeroSSL Crypt::LE client v$VERSION started. ]");
    $opt->{'logger'}->warn("Could not encode arguments, support for internationalized domain names may not be available.") if $opt->{'e'};

    return _error("Incorrect parameters - need account key file name specified.") unless $opt->{'key'};
    if (-e $opt->{'key'}) {
        return _error("Account key file is not readable.") unless (-r $opt->{'key'});
    } else {
        return _error("Account key file is missing and the option to generate missing files is not used.") unless $opt->{'generate-missing'};
    }

    unless ($opt->{'crt'} or $opt->{'generate-only'}) {
        return _error("Please specify a file name for the certificate.");
    }

    if ($opt->{'revoke'}) {
        return _error("Need a certificate file for revoke to work.") unless (-r $opt->{'crt'});
        return _error("Need an account key - revoke assumes you had a registered account when got the certificate.") unless (-r $opt->{'key'});
    } else {
        return _error("Incorrect parameters - need CSR file name specified.") unless $opt->{'csr'};
        if (-e $opt->{'csr'}) {
            return _error("CSR file is not readable.") unless (-r $opt->{'csr'});
        } else {
            return _error("CSR file is missing and the option to generate missing files is not used.") unless $opt->{'generate-missing'};
            return _error("CSR file is missing and CSR-key file name is not specified.") unless $opt->{'csr-key'};
            return _error("Domain list should be provided to generate a CSR.") unless ($opt->{'domains'} and $opt->{'domains'}!~/^[\s\,]*$/);
        }

        if ($opt->{'path'}) {
            my @non_writable = ();
            foreach my $path (grep { $_ } split /\s*,\s*/, $opt->{'path'}) {
                push @non_writable, $path unless (-d $path and -w _);
            }
            return _error("Path to save challenge files into should be a writable directory for: " . join(', ', @non_writable)) if @non_writable;
        } elsif ($opt->{'unlink'}) {
            return _error("Unlink option will have no effect without --path.");
        }

        $opt->{'handle-as'} = $opt->{'handle-as'} ? lc($opt->{'handle-as'}) : 'http';

        if ($opt->{'handle-with'}) {
            eval {
                load $opt->{'handle-with'};
                $opt->{'handler'} = $opt->{'handle-with'}->new();
            };
            return _error("Cannot use the module to handle challenges with.") if $@;
            my $method = 'handle_challenge_' . $opt->{'handle-as'};
            return _error("Module to handle challenges does not seem to support the challenge type of $opt->{'handle-as'}.") unless $opt->{'handler'}->can($method);
            my $rv = _load_params($opt, 'handle-params');
            return $rv if $rv;
        } else {
            $opt->{'handle-params'} = { path => $opt->{'path'}, unlink => $opt->{'unlink'} };
        }

        if ($opt->{'complete-with'}) {
            eval {
                load $opt->{'complete-with'};
                $opt->{'complete-handler'} = $opt->{'complete-with'}->new();
            };
            return _error("Cannot use the module to complete processing with.") if $@;
            return _error("Module to complete processing with does not seem to support the required 'complete' method.") unless $opt->{'complete-handler'}->can('complete');
            my $rv = _load_params($opt, 'complete-params');
            return $rv if $rv;
        } else {
            $opt->{'complete-params'} = { path => $opt->{'path'}, unlink => $opt->{'unlink'} };
        }
    }
    return;
}

sub encode_args {
    eval {
        my $from;
        if ($^O eq 'MSWin32') {
            load 'Win32';
            if (defined &Win32::GetACP) {
                $from = "cp" . Win32::GetACP();
            } else {
                load 'Win32::API';
                Win32::API->Import('kernel32', 'int GetACP()');
                $from = "cp" . GetACP() if (defined &GetACP);
            }
            $from ||= 'cp1252';
        } else {
            load 'I18N::Langinfo';
            $from = I18N::Langinfo::langinfo(&I18N::Langinfo::CODESET) || 'UTF-8';
        }
        @ARGV = map { decode $from, $_ } @ARGV;
        autoload 'URI::_punycode';
    };
    return $@;
}

sub reconfigure_log {
    my $opt = shift;
    if ($opt->{'log-config'}) {
        eval {
            Log::Log4perl::init($opt->{'log-config'});
        };
        if ($@ or !%{Log::Log4perl::appenders()}) {
            Log::Log4perl->easy_init({ utf8  => 1 });
            return _error("Could not init logging with '$opt->{'log-config'}' file");
        }
        $opt->{logger} = Log::Log4perl->get_logger();
    }
    return;
}

sub _puny {
    my $domain = shift;
    my @rv = ();
    for (split /\./, $domain) {
        my $enc = encode_punycode($_);
        push @rv, ($_ eq $enc) ? $_ : 'xn--' . $enc;
    }
    return join '.', @rv;
}

sub _path_mismatch {
    my ($le, $opt) = @_;
    if ($opt->{'path'} and my $domains = $le->domains) {
        my @paths = grep {$_} split /\s*,\s*/, $opt->{'path'};
        if (@paths > 1) {
            return 1 unless @{$domains} == @paths;
            for (my $i = 0; $i <= $#paths; $i++) {
                $opt->{'multiroot'}->{$domains->[$i]} = $paths[$i];
            }
        }
    }
    return 0;
}

sub _load_params {
    my ($opt, $type) = @_;
    return unless ($opt and $opt->{$type});
    if ($opt->{$type}!~/[\{\[\}\]]/) {
        $opt->{$type} = _read($opt->{$type});
        return _error("Could not read the file with '$type'.") unless $opt->{$type};
    }
    my $j = JSON->new->canonical()->allow_nonref();
    eval {
        $opt->{$type} = $j->decode($opt->{$type});
    };
    return ($@ or (ref $opt->{$type} ne 'HASH')) ? 
        _error("Could not decode '$type'. Please make sure you are providing a valid JSON document and {} are in place." . ($opt->{'debug'} ? $@ : '')) : 0;
}

sub _read {
    my $file = shift;
    return unless (-e $file and -r _);
    my $fh = IO::File->new();
    $fh->open($file, '<:encoding(UTF-8)') or return;
    local $/;
    my $src = <$fh>;
    $fh->close;
    return $src;
}

sub _write {
    my ($file, $content) = @_;
    return 1 unless ($file and $content);
    my $fh = IO::File->new($file, 'w');
    return 1 unless defined $fh;
    $fh->binmode;
    print $fh $content;
    $fh->close;
    return 0;
}

sub _error {
    my ($msg, $code) = @_;
    return { msg => $msg, code => $code||255 };
}

sub verify_crt {
    my $opt = shift;
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
                $opt->{'expires'} = $s unless ($opt->{'expires'} and $s > $opt->{'expires'});
            }
        }
    };
}

sub verify_crt_file {
    my $opt = shift;
    my $bio = Net::SSLeay::BIO_new_file($opt->{'crt'}, 'r') or return $!;
    my $cert = Net::SSLeay::PEM_read_bio_X509($bio);
    Net::SSLeay::BIO_free($bio);
    return $cert ? verify_crt($opt)->(0, 0, 0, 0, $cert, 0) : "Could not parse the certificate";
}

sub process_challenge {
    my ($challenge, $params) = @_;
    my $text = "$challenge->{token}.$challenge->{fingerprint}";
    if ($params->{'path'}) {
        my $path = $params->{'multiroot'} ? $params->{'multiroot'}->{$challenge->{domain}} : $params->{'path'};
        unless ($path) {
            $challenge->{'logger'}->error("Could not find the path for domain '$challenge->{domain}' to save the challenge file into.");
            return 0;
        }
        my $file = "$path/$challenge->{token}";
        if (-e $file) {
           $challenge->{'logger'}->error("File already exists - this should not be the case, please move it or remove it.");
           return 0;
        }
        if (_write($file, $text)) {
           $challenge->{'logger'}->error("Failed to save a challenge file '$file' for domain '$challenge->{domain}'");
           return 0;
        } else {
           $challenge->{'logger'}->info("Successfully saved a challenge file '$file' for domain '$challenge->{domain}'");
           return 1;
        }
    }
    print <<EOF;
Challenge for $challenge->{domain} requires:
A file '$challenge->{token}' in '/.well-known/acme-challenge/' with the text: $text
When done, press <Enter>
EOF
    <STDIN>;
    return 1;
};

sub process_verification {
    my ($results, $params) = @_;
    if ($results->{valid}) {
        $results->{'logger'}->info("Domain verification results for '$results->{domain}': success.");
    } else {
        $results->{'logger'}->error("Domain verification results for '$results->{domain}': error. " . $results->{'error'});
    }
    my $path = $params->{'multiroot'} ? $params->{'multiroot'}->{$results->{domain}} : $params->{'path'};
    my $file = $path ? "$path/$results->{token}" : $results->{token};
    if ($params->{'unlink'}) {
        unless ($path) {
            $results->{'logger'}->error("Could not find the path for domain '$results->{domain}' - you may need to find and remove file named '$results->{token}' manually.");
        } else {
            if (-e $file) {
                if (unlink $file) {
                    $results->{'logger'}->info("Challenge file '$file' has been deleted.");
                } else {
                    $results->{'logger'}->error("Could not delete the challenge file '$file', you may need to do it manually.");
                }
            } else {
                $results->{'logger'}->error("Could not find the challenge file '$file' to delete, it might have been already removed.");
            }
        }
    } else {
        $results->{'logger'}->info("You can now delete the '$file' file.");
    }
    1;
}

sub process_challenge_dns {
    my ($challenge, $params) = @_;
    my $value = encode_base64url(sha256("$challenge->{token}.$challenge->{fingerprint}"));
    print <<EOF;
Challenge for '$challenge->{domain}' requires the following DNS record to be created:
Host: _acme-challenge.$challenge->{domain}, type: TXT, value: $value
Wait for DNS to update by checking it with the command: nslookup -q=TXT _acme-challenge.$challenge->{domain}
When you see a text record returned, press <Enter>
EOF
    <STDIN>;
    return 1;
}

sub process_verification_dns {
    my ($results, $params) = @_;
    $results->{logger}->info("Processing the 'dns' verification for '$results->{domain}'");
    if ($results->{valid}) {
        $results->{'logger'}->info("Domain verification results for '$results->{domain}': success.");
    } else {
        $results->{'logger'}->error("Domain verification results for '$results->{domain}': error. " . $results->{'error'});
    }
    $results->{'logger'}->info("You can now delete '_acme-challenge.$results->{domain}' DNS record");
    1;
}

sub usage_and_exit {
    my $opt = shift;
    print "\n ZeroSSL Crypt::LE client v$VERSION\n\n";
    if ($opt->{'help'}) {
        print << 'EOF';
 ===============
 USAGE EXAMPLES: 
 ===============

a) To register (if needed) and issue a certificate:

 le.pl --key account.key --email "my@email.address" --csr domain.csr
       --csr-key domain.key --crt domain.crt --generate-missing
       --domains "www.domain.ext,domain.ext"

Please note that email is only used for the initial registration and
cannot be changed later. Even though it is optional, you may want to
have your email registered to receive certificate expiration notifications
and be able to recover your account in the future if needed.

b) To have challenge files automatically placed into your web directory
   before the verification and then removed after the verification:

 le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt
       --domains "www.domain.ext,domain.ext" --generate-missing --unlink
       --path /some/path/.well-known/acme-challenge

If www.domain.ext and domain.ext use different "webroots", you can specify
those in --path parameter, as a comma-separated list as follows:

 le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt
       --domains "www.domain.ext,domain.ext" --generate-missing --unlink
       --path /a/.well-known/acme-challenge,/b/.well-known/acme-challenge

Please note that with multiple webroots specified, the amount of those should
match the amount of domains listed. They will be used in the same order as
the domains given and all of those folders should be writable.

c) To use external modules to handle challenges and process completion
   while getting a certificate:

 le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt
       --domains "www.domain.ext,domain.ext" --generate-missing
       --handle-with Crypt::LE::Challenge::Simple
       --complete-with Crypt::LE::Complete::Simple

   - See Crypt::LE::Challenge::Simple for an example of a challenge module.
   - See Crypt::LE::Complete::Simple for an example of a completion module.

d) To pass parameters to external modules as JSON either directly or by
   specifying a file name:

 le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt
       --domains "www.domain.ext,domain.ext" --generate-missing
       --handle-with Crypt::LE::Challenge::Simple
       --complete-with Crypt::LE::Complete::Simple
       --handle-params '{"key1": 1, "key2": 2, "key3": "something"}'
       --complete-params complete.json
         
e) To use basic DNS verification:

 le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt
       --domains "www.domain.ext,domain.ext" --generate-missing --handle-as dns

f) To just generate the keys and CSR:

 le.pl --key account.key --csr domain.csr --csr-key domain.key
       --domains "www.domain.ext,domain.ext" --generate-missing
       --generate-only

g) To revoke a certificate:

 le.pl --key account.key --crt domain.crt --revoke

 ===============
 RENEWAL PROCESS
 ===============

To RENEW your existing certificate: use the same command line as you used
for issuing the certificate, with one additional parameter:
   
 --renew XX, where XX is the number of days left until certificate expiration.

If le.pl detects that it is XX or fewer days left until certificate expiration,
then (and only then) the renewal process will be run, so the script can be
safely put into crontab to run on a daily basis if needed. The amount of days
left is checked by either of two methods:

 1) If the certificate (which name is used with --crt parameter) is available
    locally, then it will be loaded and checked.

 2) If the certificate is not available locally (for example if you moved it
    to another server), then an attempt to connect to the domains listed in
    --domains or CSR will be made until the first successful response is
    received. The peer certificate will be then checked for expiration.

 NOTE: By default a staging server is used, which does not provide trusted
 certificates. This is to avoid exceeding a rate limits on Let's Encrypt
 live server. To generate an actual certificate, always add --live option.
       
 ==================================
 LOGGING CONFIGURATION FILE EXAMPLE
 ==================================
 
 log4perl.rootLogger=DEBUG, File, Screen
 log4perl.appender.File = Log::Log4perl::Appender::File
 log4perl.appender.File.filename = le.log
 log4perl.appender.File.mode = append
 log4perl.appender.File.layout = PatternLayout
 log4perl.appender.File.layout.ConversionPattern = %d [%p] %m%n
 log4perl.appender.File.utf8 = 1
 log4perl.appender.Screen = Log::Log4perl::Appender::Screen
 log4perl.appender.Screen.layout = PatternLayout
 log4perl.appender.Screen.layout.ConversionPattern = %d [%p] %m%n
 log4perl.appender.Screen.utf8 = 1
        
EOF
    }
    print <<'EOF';
 =====================
 AVAILABLE PARAMETERS:
 =====================

-key <file>                  : Account key file.
-csr <file>                  : CSR file.
-csr-key <file>              : Key for CSR (optional if CSR exists).
-crt <file>                  : Name for the domain certificate file.
-domains <list>              : Domains list (optional if CSR exists).
-renew <XX>                  : Renew if XX or fewer days are left.
-curve <name|default>        : ECC curve name (optional).
-path <absolute path>        : Path to .well-known/acme-challenge/ (optional).
-handle-with <module>        : Module to handle challenges with (optional).
-handle-as <http|dns|tls>    : Type of challenge, by default 'http' (optional).
-handle-params <json|file>   : JSON for the challenge module (optional).
-complete-with <module>      : Module to handle completion with (optional).
-complete-params <json|file> : JSON for the completion module (optional).
-issue-code XXX              : Exit code to use on issuance/renewal (optional).
-email <some@mail.address>   : Email for expiration notifications (optional).
-log-config <file>           : Configuration file for logging.
-generate-missing            : Generate missing files (key, csr and csr-key).
-generate-only               : Exit after generating the missing files.
-unlink                      : Remove challenge files automatically.
-revoke                      : Revoke a certificate.
-legacy                      : Legacy mode (shorter keys, separate CA file).
-live                        : Use the live server instead of the test one.
-debug                       : Print out debug messages.
-help                        : Detailed help.

EOF
    exit(1);
}
