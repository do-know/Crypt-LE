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
use Crypt::LE ':errors';

my $VERSION = '0.14';

use constant PEER_CRT  => 4;
use constant CRT_DEPTH => 5;

exit main();

sub main {
    Log::Log4perl->easy_init();
    my $opt = { logger => Log::Log4perl->get_logger() };
    binmode(STDOUT, ":encoding(UTF-8)");
    if (my $rv = work($opt)) {
        $opt->{logger}->error($rv);
        return 255;
    }
    return 0;
}

sub work {
    my $opt = shift;
    my $rv = parse_options($opt);
    return $rv if $rv;

    my $le = Crypt::LE->new(debug => $opt->{'debug'}, live => $opt->{'live'}, logger => $opt->{'logger'});

    if (-r $opt->{'key'}) {
        $opt->{'logger'}->info("Loading an account key from $opt->{'key'}");
        $le->load_account_key($opt->{'key'}) == OK or return "Could not load an account key: " . $le->error_details;
    } else {
        $opt->{'logger'}->info("Generating a new account key");
        $le->generate_account_key == OK or return "Could not generate an account key: " . $le->error_details;
        $opt->{'logger'}->info("Saving generated account key into $opt->{'key'}");
        return "Failed to save an account key file" if _write($opt->{'key'}, $le->account_key);
    }

    if ($opt->{'revoke'}) {
        my $rv = $le->revoke_certificate($opt->{'crt'});
        if ($rv == OK) {
            $opt->{'logger'}->info("Certificate has been revoked.");
        } elsif ($rv == ALREADY_DONE) {
            $opt->{'logger'}->info("Certificate has been ALREADY revoked.");
        } else {
            return "Problem with revoking certificate: " . $le->error_details;
        }
        return;
    }

    if (-r $opt->{'csr'}) {
        $opt->{'logger'}->info("Loading a CSR from $opt->{'csr'}");
        $le->load_csr($opt->{'csr'}, $opt->{'domains'}) == OK or return "Could not load a CSR: " . $le->error_details;
    } else {
        $opt->{'logger'}->info("Generating a new CSR for domains $opt->{'domains'}");
        $le->generate_csr($opt->{'domains'}) == OK or return "Could not generate a CSR: " . $le->error_details;
        $opt->{'logger'}->info("Saving a new CSR into $opt->{'csr'}");
        return "Failed to save a CSR" if _write($opt->{'csr'}, $le->csr);
        $opt->{'logger'}->info("Saving a new CSR key into $opt->{'csr-key'}");
        return "Failed to save a CSR key" if _write($opt->{'csr-key'}, $le->csr_key);
    }

    return if $opt->{'generate-only'};

    if ($opt->{'renew'}) {
        my $rv = 1;
        if ($opt->{'crt'} and -r $opt->{'crt'}) {
            $opt->{'logger'}->info("Checking certificate for expiration (local file).");
            $rv = verify_crt_file($opt);
            $opt->{'logger'}->warn("Problem checking existing certificate file: $rv") if $rv;
        }
        if ($rv) {
            $opt->{'logger'}->info("Checking certificate for expiration (website connection).");
            my $probe = HTTP::Tiny->new( agent => "Mozilla/5.0 (compatible; ZeroSSL Crypt::LE v$VERSION renewal agent; https://ZeroSSL.com/)", verify_SSL => 1, timeout => 10, SSL_options => { SSL_verify_callback => verify_crt($opt) } );
            foreach my $domain (@{$le->domains}) {
                $opt->{'logger'}->info("Checking $domain");
                $probe->head("https://$domain/");
                if (defined $opt->{'expires'}) {
                    $rv = 0;
                    last;
                }
            }
        }
        return "Could not get the certificate expiration value, cannot renew." if $rv;
        if ($opt->{'expires'} > $opt->{'renew'}) {
            $opt->{'logger'}->info("Too early for renewal, certificate expires in $opt->{'expires'} days.");
            return;
        }
        $opt->{'logger'}->info("Expiration threshold set at $opt->{'renew'} days, the certificate " . ($opt->{'expires'} < 0 ? "has already expired" : "expires in $opt->{'expires'} days") . " - will be renewing.");
    }
    
    if ($opt->{'email'}) {
        return $le->error_details if $le->set_account_email($opt->{'email'});
    }
    
    return $le->error_details if $le->register;
    $opt->{'logger'}->info("Make sure to check TOS at " . $le->tos) if ($le->tos_changed and $le->tos);
    $le->accept_tos();
    # We might not need to re-verify, verification holds for quite a few months.
    unless ($le->request_certificate()) {
        $opt->{'logger'}->info("Received domain certificate, no validation required at this time.");
    } else {
        return $le->error_details if $le->request_challenge();
        return $le->error_details if $le->accept_challenge($opt->{'handler'} || \&process_challenge, $opt->{'handle-params'}, $opt->{'handle-as'});
        return $le->error_details if $le->verify_challenge($opt->{'handler'} || \&process_verification, $opt->{'handle-params'}, $opt->{'handle-as'});
    }
    unless ($le->certificate) {
        $opt->{'logger'}->info("Requesting domain certificate.");
        return $le->error_details if $le->request_certificate();
    }
    $opt->{'logger'}->info("Requesting issuer's certificate.");
    if ($le->request_issuer_certificate()) {
        $opt->{'logger'}->error("Could not download an issuer's certificate, try to download manually from " . $le->issuer_url);
        $opt->{'logger'}->warn("Will be saving the domain certificate alone, not the full chain.");
        return "Failed to save the domain certificate file" if _write($opt->{'crt'}, $le->certificate);
    } else {
        $opt->{'logger'}->info("Saving the full certificate chain.");
        return "Failed to save the domain certificate file" if _write($opt->{'crt'}, $le->certificate . "\n" . $le->issuer);
    }
    if ($opt->{'complete-handler'}) {
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
            return "Completion handler " . ($@ ? "thrown an error: $@" : "did not return a true value");
        }
    }

    $opt->{'logger'}->info("The job is done, enjoy your certificate! For feedback and bug reports contact us at [ https://ZeroSSL.com | https://Do-Know.com ]\n");
    return;
}

sub parse_options {
    my $opt = shift;
    my $args = @ARGV;
    
    GetOptions ($opt, 'key=s', 'csr=s', 'csr-key=s', 'domains=s', 'path=s', 'crt=s', 'email=s', 'renew=i',
            'handle-with=s', 'handle-as=s', 'handle-params=s', 'complete-with=s', 'complete-params=s', 'log-config=s',
            'generate-missing', 'generate-only', 'revoke', 'unlink', 'live', 'debug', 'help') || return "Use --help to see the usage examples.\n";
            
    usage_and_exit() unless ($args and !$opt->{'help'});
    my $rv = reconfigure_log($opt);
    return $rv if $rv;

    $opt->{'logger'}->info("[ ZeroSSL Crypt::LE client v$VERSION started. ]");

    unless ($opt->{'key'} and (-r $opt->{'key'} or $opt->{'generate-missing'})) {
        return "Incorrect parameters - need an account key loaded or generated.";
    }

    unless ($opt->{'crt'} or $opt->{'generate-only'}) {
        return "Please specify a file name for the certificate.";
    }

    if ($opt->{'revoke'}) {
        return "Need a certificate file for revoke to work." unless (-r $opt->{'crt'});
        return "Need an account key - revoke assumes you had a registered account when got the certificate." unless (-r $opt->{'key'});
    } else {
        unless ($opt->{'csr'} and (-r $opt->{'csr'} or ($opt->{'csr-key'} and $opt->{'generate-missing'})))  {
            return "Incorrect parameters - need CSR loaded or generated.";
        }

        if (!$opt->{'generate-missing'} and ! -r $opt->{'csr'} and (!$opt->{'domains'} or $opt->{'domains'}=~/^\s*$/)) {
            return "Domain list should be provided to generate a CSR.";
        }

        if ($opt->{'path'}) {
            return "Path to save challenge files into should be a writable directory" unless (-d $opt->{'path'} and -w _);
        } elsif ($opt->{'unlink'}) {
            return "Unlink option will have no effect without --path.";
        }

        $opt->{'handle-as'} = $opt->{'handle-as'} ? lc($opt->{'handle-as'}) : 'http';

        if ($opt->{'handle-with'}) {
            eval {
                load $opt->{'handle-with'};
                $opt->{'handler'} = $opt->{'handle-with'}->new();
            };
            return "Cannot use the module to handle challenges with." if $@;
            my $method = 'handle_challenge_' . $opt->{'handle-as'};
            return "Module to handle challenges does not seem to support the challenge type of $opt->{'handle-as'}." unless $opt->{'handler'}->can($method);
            my $rv = _load_params($opt, 'handle-params');
            return $rv if $rv;
        } else {
            $opt->{'handle-params'} = { path => $opt->{'path'}, unlink => $opt->{'unlink'}, logger => $opt->{'logger'} };
        }

        if ($opt->{'complete-with'}) {
            eval {
                load $opt->{'complete-with'};
                $opt->{'complete-handler'} = $opt->{'complete-with'}->new();
            };
            return "Cannot use the module to complete processing with." if $@;
            return "Module to complete processing with does not seem to support the required 'complete' method." unless $opt->{'complete-handler'}->can('complete');
            my $rv = _load_params($opt, 'complete-params');
            return $rv if $rv;
        } else {
            $opt->{'complete-params'} = { path => $opt->{'path'}, unlink => $opt->{'unlink'}, logger => $opt->{'logger'} };
        }
    }
    return;
}

sub usage_and_exit {
    local $/;
    print <DATA>;
    exit(1);
}

sub reconfigure_log {
    my $opt = shift;
    if ($opt->{'log-config'}) {
        eval {
            Log::Log4perl::init($opt->{'log-config'});
        };
        if ($@ or !%{Log::Log4perl::appenders()}) {
            Log::Log4perl->easy_init();
            return "Could not init logging with '$opt->{'log-config'}' file";
        }
        $opt->{logger} = Log::Log4perl->get_logger();
    }
    return;
}

sub _load_params {
    my ($opt, $type) = @_;
    return unless ($opt and $opt->{$type});
    if ($opt->{$type}!~/[\{\[\}\]]/) {
        $opt->{$type} = _read($opt->{$type});
        return "Could not read the file with '$type'." unless $opt->{$type};
    }
    my $j = JSON->new->canonical()->allow_nonref();
    eval {
        $opt->{$type} = $j->decode($opt->{$type});
    };
    return ($@ or (ref $opt->{$type} ne 'HASH')) ? 
        "Could not decode '$type'. Please make sure you are providing a valid JSON document and {} are in place." . ($opt->{'debug'} ? $@ : '') : 0;
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

sub verify_crt {
    my $opt = shift;
    return sub {
        my @crt = @_;
        unless ($crt[CRT_DEPTH]) {
            my ($t, $s);
            eval {
                $t = Net::SSLeay::X509_get_notAfter($crt[PEER_CRT]);
                $t = Time::Piece->strptime(Net::SSLeay::P_ASN1_TIME_get_isotime($t), "%Y-%m-%dT%H:%M:%SZ");
            };
            return $@ if $@;
            $s = $t - localtime;
            $opt->{'expires'} = int($s->days);
            return 0;
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
        my $file = "$params->{'path'}/$challenge->{token}";
	if (_write($file, $text)) {
	   $params->{'logger'}->error("Failed to save a challenge file '$file' for domain '$challenge->{domain}'");
           return 0;
	} else {
           $params->{'logger'}->info("Successfully saved a challenge file '$file' for domain '$challenge->{domain}'");
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
        $params->{'logger'}->info("Domain verification results for '$results->{domain}': success.");
    } else {
        $params->{'logger'}->error("Domain verification results for '$results->{domain}': error. " . $results->{'error'});
    }
    my $file = $params->{'path'} ? "$params->{'path'}/$results->{token}" : $results->{token};
    if ($params->{'unlink'}) {
        if (unlink $file) {
            $params->{'logger'}->info("Challenge file '$file' has been deleted.");
        } else {
            $params->{'logger'}->error("Could not delete the challenge file '$file', you may need to do it manually.");
        }
    } else {
        $params->{'logger'}->info("You can now delete the '$file' file.");
    }
    1;
}

__END__

 ZeroSSL Crypt::LE client v0.14

 ===============
 USAGE EXAMPLES: 
 ===============

a) To register (if needed) and issue a certificate:

   le.pl --key account.key --email "my@email.address" --csr domain.csr --csr-key domain.key --crt domain.crt --domains "www.domain.ext,domain.ext" \\
         --generate-missing

   Please note that email is only used for the initial registration and cannot be changed later. Even though it is optional,
   you may want to have your email registered to receive certificate expiration notifications and be able to recover your
   account in the future if needed.

b) To have challenge files automatically placed into your web directory before the verification and then removed after the verification:

   le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt --domains "www.domain.ext,domain.ext" --generate-missing \\
         --path /some/path/.well-known/acme-challenge --unlink

c) To use external modules to handle challenges and process completion while getting a certificate:

   le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt --domains "www.domain.ext,domain.ext" --generate-missing \\
         --handle-with Crypt::LE::Challenge::Simple --complete-with Crypt::LE::Complete::Simple

   - See provided Crypt::LE::Challenge::Simple for an example of a challenge-handling module.
   - See provided Crypt::LE::Complete::Simple for an example of a completion-handling module.

d) To pass parameters to external modules as JSON either directly or by specifying a file name:

   le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt --domains "www.domain.ext,domain.ext" --generate-missing \\
         --handle-with Crypt::LE::Challenge::Simple --complete-with Crypt::LE::Complete::Simple \\
         --handle-params '{"key1": 1, "key2": 2, "key3": "something"}' --complete-params complete.json
         
e) To use basic DNS verification:

   le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt --domains "www.domain.ext,domain.ext" --generate-missing \\
         --handle-as dns --handle-with Crypt::LE::Challenge::Simple

f) To just generate the keys and CSR:

   le.pl  --key account.key --csr domain.csr --csr-key domain.key --domains "www.domain.ext,domain.ext" --generate-missing --generate-only

g) To revoke a certificate:

   le.pl --key account.key --crt domain.crt --revoke

 ===============
 RENEWAL PROCESS
 ===============

To RENEW your existing certificate: use the same command line as you used for issuing the certificate, with one additional parameter
   
   --renew XX, where XX is the number of days left until certificate expiration.

If le.pl detects that it is XX or fewer days left until certificate expiration, then (and only then) the renewal process will be run,
so the script can be safely put into crontab to run on a daily basis if needed. The amount of days left is checked by either of two
methods:

 1) If the certificate (which name is used with --crt parameter) is available locally, then it will be loaded and checked.

 2) If the certificate is not available locally (for example if you moved it to another server), then an attempt to
    connect to the domains listed in --domains or CSR will be made until the first successful response is received. The
    peer certificate will be then checked for expiration.

 NOTE: by default a staging server is used, which does not provide trusted certificates. This is to avoid hitting a 
       rate limits on Let's Encrypt live server. To generate an actual certificate, always add --live option.
       
 ==================================
 LOGGING CONFIGURATION FILE EXAMPLE
 ==================================
 
 log4perl.rootLogger=DEBUG, File, Screen
 log4perl.appender.File = Log::Log4perl::Appender::File
 log4perl.appender.File.filename = le.log
 log4perl.appender.File.mode = append
 log4perl.appender.File.layout = PatternLayout
 log4perl.appender.File.layout.ConversionPattern = %d [%p] %m%n
 log4perl.appender.Screen = Log::Log4perl::Appender::Screen
 log4perl.appender.Screen.layout = PatternLayout
 log4perl.appender.Screen.layout.ConversionPattern = %d [%p] %m%n
        
 =====================
 AVAILABLE PARAMETERS:
 =====================

 key <file>                       - Your account key file.
 csr <file>                       - Your CSR file.
 csr-key <file>                   - Key for your CSR (only mandatory if CSR is missing and to be generated).
 domains <list>                   - Domains as comma-separated list (only mandatory if CSR is missing).
 path <absolute path>             - Path to local .well-known/acme-challenge/ to drop required challenge files into (optional).
 handle-with <Some::Module>       - Module name to handle challenges with (optional).
 handle-as <http|dns|tls|...>     - Type of challenge to request, by default 'http' (optional).
 handle-params <{json}|file>      - JSON (or name of the file containing it) with parameters to be passed to the challenge-handling module (optional).
 complete-with <Another::Module>  - Module name to handle process completion with (optional).
 complete-params <{json}|file>    - JSON (or name of the file containing it) with parameters to be passed to the completion-handling module (optional).
 email <some@mail.address>        - Mail address for the account registration and certificate expiration notifications (optional).
 log-config <file>                - Configuration file for logging (perldoc Log::Log4perl to see configuration examples).
 generate-missing                 - Generate missing files (key, csr and csr-key).
 generate-only                    - Generate a new key and/or CSR if they are missing and then exit.
 unlink                           - Remove challenge files which were automatically created if --path option was used.
 renew <XX>                       - Renew the certificate if XX or fewer days are left until its expiration.
 crt <file>                       - Name for the domain certificate file.
 revoke                           - Revoke a certificate.
 live                             - Connect to a live server instead of staging.
 debug                            - Print out debug messages.
 help                             - This screen.

