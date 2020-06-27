#!/usr/bin/env perl
use strict;
use warnings;
use Getopt::Long;
use IO::File;
use JSON::MaybeXS;
use Log::Log4perl;
use Log::Log4perl::Level;
use Module::Load;
use Encode 'decode';
use Digest::SHA 'sha256';
use MIME::Base64 'encode_base64url';
use Crypt::LE ':errors', ':keys';
use utf8;

my $VERSION = '0.36';

exit main();

sub main {
    Log::Log4perl->easy_init({ utf8  => 1 });
    my $opt = { logger => Log::Log4perl->get_logger(), e => encode_args(), error => parse_config() };
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
    # Set the default protocol version to 2 unless it is set explicitly or custom server/directory is set (in which case auto-sense is used).
    $opt->{'api'} = 2 unless (defined $opt->{'api'} or $opt->{'server'} or $opt->{'directory'});
    my $le = Crypt::LE->new(
	autodir => 0,
	dir => $opt->{'directory'},
	server => $opt->{'server'},
	live => $opt->{'live'},
	version => $opt->{'api'}||0,
	debug => $opt->{'debug'},
	logger => $opt->{'logger'},
    );

    if (-r $opt->{'key'}) {
        $opt->{'logger'}->info("Loading an account key from $opt->{'key'}");
        $le->load_account_key($opt->{'key'}) == OK or return $opt->{'error'}->("Could not load an account key: " . $le->error_details, 'ACCOUNT_KEY_LOAD');
    } else {
        $opt->{'logger'}->info("Generating a new account key");
        $le->generate_account_key == OK or return $opt->{'error'}->("Could not generate an account key: " . $le->error_details, 'ACCOUNT_KEY_GENERATE');
        $opt->{'logger'}->info("Saving generated account key into $opt->{'key'}");
        return $opt->{'error'}->("Failed to save an account key file", 'ACCOUNT_KEY_SAVE') if _write($opt->{'key'}, $le->account_key);
    }

    if ($opt->{'update-contacts'}) {
        # Register.
        my $reg = _register($le, $opt);
        return $reg if $reg;
        my @contacts = (lc($opt->{'update-contacts'}) eq 'none') ? () : grep { $_ } split /\s*\,\s*/, $opt->{'update-contacts'};
        my @rejected = ();
        foreach (@contacts) {
            /^(\w+:)?(.+)$/;
            # NB: tel is not supported by LE at the moment.
            my ($prefix, $data) = (lc($1||''), $2);
            push @rejected, $_ unless ($data=~/^[^\@]+\@[^\.]+\.[^\.]+/ and (!$prefix or ($prefix eq 'mailto:')));
        }
        return $opt->{'error'}->("Unknown format for the contacts: " . join(", ", @rejected), 'CONTACTS_FORMAT') if @rejected;
        return $opt->{'error'}->("Could not update contact details: " . $le->error_details, 'CONTACTS_UPDATE') if $le->update_contacts(\@contacts);
        $opt->{'logger'}->info("Contact details have been updated.");
        return;
    }

    if ($opt->{'revoke'}) {
        my $crt = _read($opt->{'crt'});
        return $opt->{'error'}->("Could not read the certificate file.", 'CERTIFICATE_FILE_READ') unless $crt;
        # Take the first certificate in file, disregard the issuer's one.
        $crt=~s/^(.*?-+\s*END CERTIFICATE\s*-+).*/$1/s;

        # Register.
        my $reg = _register($le, $opt);
        return $reg if $reg;
        my $rv = $le->revoke_certificate(\$crt);
        if ($rv == OK) {
            $opt->{'logger'}->info("Certificate has been revoked.");
        } elsif ($rv == ALREADY_DONE) {
            $opt->{'logger'}->info("Certificate has been ALREADY revoked.");
        } else {
            return $opt->{'error'}->("Problem with revoking certificate: " . $le->error_details, 'CERTIFICATE_REVOKE');
        }
        return;
    }

    if ($opt->{'domains'}) {
        if ($opt->{'e'}) {
            $opt->{'logger'}->warn("Could not encode arguments, support for internationalized domain names may not be available.");
        } else {
            my @domains = grep { $_ } split /\s*\,\s*/, $opt->{'domains'};
            $opt->{'domains'} = join ",", map { _puny($_) } @domains;
        }
    }
    if (-r $opt->{'csr'}) {
        $opt->{'logger'}->info("Loading a CSR from $opt->{'csr'}");
        $le->load_csr($opt->{'csr'}, $opt->{'domains'}) == OK or return $opt->{'error'}->("Could not load a CSR: " . $le->error_details, 'CSR_LOAD');
        return $opt->{'error'}->("For multi-webroot path usage, the amount of paths given should match the amount of domain names listed.", 'WEBROOT_MISMATCH') if _path_mismatch($le, $opt);
        # Load existing CSR key if specified, even if we have CSR (for example for PFX export).
        if ($opt->{'csr-key'} and -e $opt->{'csr-key'}) {
            return $opt->{'error'}->("Could not load existing CSR key from $opt->{'csr-key'} - " . $le->error_details, 'CSR_KEY_LOAD') if $le->load_csr_key($opt->{'csr-key'});
        }
    } else {
        $opt->{'logger'}->info("Generating a new CSR for domains $opt->{'domains'}");
        if (-e $opt->{'csr-key'}) {
             # Allow using pre-existing key when generating CSR
             return $opt->{'error'}->("Could not load existing CSR key from $opt->{'csr-key'} - " . $le->error_details, 'CSR_KEY_LOAD') if $le->load_csr_key($opt->{'csr-key'});
             $opt->{'logger'}->info("New CSR will be based on '$opt->{'csr-key'}' key");
        } else {
             $opt->{'logger'}->info("New CSR will be based on a generated key");
        }
        my ($type, $attr) = $opt->{'curve'} ? (KEY_ECC, $opt->{'curve'}) : (KEY_RSA, $opt->{'legacy'} ? 2048 : 4096);
        $le->generate_csr($opt->{'domains'}, $type, $attr) == OK or return $opt->{'error'}->("Could not generate a CSR: " . $le->error_details, 'CSR_GENERATE');
        $opt->{'logger'}->info("Saving a new CSR into $opt->{'csr'}");
        return "Failed to save a CSR" if _write($opt->{'csr'}, $le->csr);
        unless (-e $opt->{'csr-key'}) {
            $opt->{'logger'}->info("Saving a new CSR key into $opt->{'csr-key'}");
            return $opt->{'error'}->("Failed to save a CSR key", 'CSR_SAVE') if _write($opt->{'csr-key'}, $le->csr_key);
        }
        return $opt->{'error'}->("For multi-webroot path usage, the amount of paths given should match the amount of domain names listed.", 'WEBROOT_MISMATCH') if _path_mismatch($le, $opt);
    }

    return if $opt->{'generate-only'};

    if ($opt->{'renew'}) {
        if ($opt->{'crt'} and -r $opt->{'crt'}) {
            $opt->{'logger'}->info("Checking certificate for expiration (local file).");
            $opt->{'expires'} = $le->check_expiration($opt->{'crt'});
            $opt->{'logger'}->warn("Problem checking existing certificate file.") unless (defined $opt->{'expires'});
        }
        unless (defined $opt->{'expires'}) {
            $opt->{'logger'}->info("Checking certificate for expiration (website connection).");
            if ($opt->{'renew-check'}) {
                $opt->{'logger'}->info("Checking $opt->{'renew-check'}");
                $opt->{'expires'} = $le->check_expiration("https://$opt->{'renew-check'}/");
            } else {
                my %seen;
                # Check wildcards last, try www for those unless already seen.
                foreach my $e (sort { $b cmp $a } @{$le->domains}) {
                   my $domain = $e=~/^\*\.(.+)$/ ? "www.$1" : $e;
                   next if $seen{$domain}++;
                   $opt->{'logger'}->info("Checking $domain");
                   $opt->{'expires'} = $le->check_expiration("https://$domain/");
                   last if (defined $opt->{'expires'});
               }
            }
        }
        return $opt->{'error'}->("Could not get the certificate expiration value, cannot renew.", 'EXPIRATION_GET') unless (defined $opt->{'expires'});
        if ($opt->{'expires'} > $opt->{'renew'}) {
            # A bit specific case - this is not an error technically but some might want an error code.
            # So the message is displayed on "info" level to prevent getting through "quiet" mode, but an error can still be set.
            $opt->{'logger'}->info("Too early for renewal, certificate expires in $opt->{'expires'} days.");
            return $opt->{'error'}->("", 'EXPIRATION_EARLY');
        }
        $opt->{'logger'}->info("Expiration threshold set at $opt->{'renew'} days, the certificate " . ($opt->{'expires'} < 0 ? "has already expired" : "expires in $opt->{'expires'} days") . " - will be renewing.");
    }
    
    if ($opt->{'email'}) {
        return $opt->{'error'}->($le->error_details, 'EMAIL_SET') if $le->set_account_email($opt->{'email'});
    }

    # Register.
    my $reg = _register($le, $opt);
    return $reg if $reg;

    # Build a copy of the parameters from the command line and added during the runtime, reduced to plain vars and hashrefs.
    my %callback_data = map { $_ => $opt->{$_} } grep { ! ref $opt->{$_} or ref $opt->{$_} eq 'HASH' } keys %{$opt};

    # We might not need to re-verify, verification holds for a while. NB: Only do that for the standard LE servers.
    my $new_crt_status = ($opt->{'server'} or $opt->{'directory'}) ? AUTH_ERROR : $le->request_certificate();
    unless ($new_crt_status) {
        $opt->{'logger'}->info("Received domain certificate, no validation required at this time.");
    } else {
        # If it's not an auth problem, but blacklisted domains for example - stop.
        return $opt->{'error'}->("Error requesting certificate: " . $le->error_details, 'CERTIFICATE_GET') if $new_crt_status != AUTH_ERROR;
        # Handle DNS internally along with HTTP
        my ($challenge_handler, $verification_handler) = ($opt->{'handler'}, $opt->{'handler'});
        if (!$opt->{'handler'}) {
            if ($opt->{'handle-as'}) {
                return $opt->{'error'}->("Only 'http' and 'dns' can be handled internally, use external modules for other verification types.", 'VERIFICATION_METHOD') unless $opt->{'handle-as'}=~/^(http|dns)$/i;
                if (lc($1) eq 'dns') {
                    ($challenge_handler, $verification_handler) = (\&process_challenge_dns, \&process_verification_dns);
                }
            }
        }

        return $opt->{'error'}->($le->error_details, 'CHALLENGE_REQUEST') if $le->request_challenge();
        return $opt->{'error'}->($le->error_details, 'CHALLENGE_ACCEPT') if $le->accept_challenge($challenge_handler || \&process_challenge, \%callback_data, $opt->{'handle-as'});

        # If delayed mode is requested, exit early with the same code as for the issuance.
        return { code => $opt->{'issue-code'}||0 } if $opt->{'delayed'};

        # Refresh nonce in case of a long delay between the challenge and the verification step.
        return $opt->{'error'}->($le->error_details, 'NONCE_REFRESH') unless $le->new_nonce();
        return $opt->{'error'}->($le->error_details, 'CHALLENGE_VERIFY') if $le->verify_challenge($verification_handler || \&process_verification, \%callback_data, $opt->{'handle-as'});
    }
    unless ($le->certificate) {
        $opt->{'logger'}->info("Requesting domain certificate.");
        return $opt->{'error'}->($le->error_details, 'CERTIFICATE_REQUEST') if $le->request_certificate();
    }
    $opt->{'logger'}->info("Requesting issuer's certificate.");
    if ($le->request_issuer_certificate()) {
        $opt->{'logger'}->error("Could not download an issuer's certificate, " . ($le->issuer_url ? "try to download manually from " . $le->issuer_url : "the URL has not been provided."));
        $opt->{'logger'}->warn("Will be saving the domain certificate alone, not the full chain.");
        return $opt->{'error'}->("Failed to save the domain certificate file", 'CERTIFICATE_SAVE') if _write($opt->{'crt'}, $le->certificate);
    } else {
        unless ($opt->{'legacy'}) {
            $opt->{'logger'}->info("Saving the full certificate chain to $opt->{'crt'}.");
            return $opt->{'error'}->("Failed to save the domain certificate file", 'CERTIFICATE_SAVE') if _write($opt->{'crt'}, $le->certificate . "\n" . $le->issuer . "\n");
        } else {
            $opt->{'logger'}->info("Saving the domain certificate to $opt->{'crt'}.");
            return $opt->{'error'}->("Failed to save the domain certificate file", 'CERTIFICATE_SAVE') if _write($opt->{'crt'}, $le->certificate);
            $opt->{'crt'}=~s/\.[^\.]+$//;
            $opt->{'crt'}.='.ca';
            $opt->{'logger'}->info("Saving the issuer's certificate to $opt->{'crt'}.");
            $opt->{'logger'}->error("Failed to save the issuer's certificate, try to download manually from " . $le->issuer_url) if _write($opt->{'crt'}, $le->issuer);
        }
    }
    if ($opt->{'export-pfx'}) {
        # Note: At this point the certificate is already issued, but with pfx export option active we will return an error if export has failed, to avoid triggering
        # the 'success' batch processing IIS users might have set up on issuance and export.
        if ($le->issuer) {
            my $target_pfx = $opt->{'crt'};
            $target_pfx=~s/\.[^\.]*$//;
            $opt->{'logger'}->info("Exporting certificate to $target_pfx.pfx.");
            return $opt->{'error'}->("Error exporting pfx: " . $le->error_details, 'CERTIFICATE_EXPORT') if $le->export_pfx("$target_pfx.pfx", $opt->{'export-pfx'}, $le->certificate, $le->csr_key, $le->issuer, $opt->{'tag-pfx'});
        } else {
            return $opt->{'error'}->("Issuer's certificate is not available, skipping pfx export to avoid creating an invalid pfx.", 'CERTIFICATE_EXPORT_ISSUER');
        }
    }
    if ($opt->{'complete-handler'}) {
        my $data = {
            # Note, certificate here is just a domain certificate, issuer is passed separately - so handler could merge those or use them separately as well.
            certificate => $le->certificate, certificate_file => $opt->{'crt'}, key_file => $opt->{'csr-key'}, issuer => $le->issuer, 
            domains => $le->domains, logger => $opt->{'logger'},
        };
        my $rv;
        eval {
            $rv = $opt->{'complete-handler'}->complete($data, \%callback_data);
        };
        if ($@ or !$rv) {
            return $opt->{'error'}->("Completion handler " . ($@ ? "thrown an error: $@" : "did not return a true value"), 'COMPLETION_HANDLER');
        }
    }
    $opt->{'logger'}->info("===> NOTE: You have been using the test server for this certificate. To issue a valid trusted certificate add --live option.") unless $opt->{'live'};
    $opt->{'logger'}->info("The job is done, enjoy your certificate!\n");
    return { code => $opt->{'issue-code'}||0 };
}

sub parse_options {
    my $opt = shift;
    my $args = @ARGV;

    GetOptions ($opt, 'key=s', 'csr=s', 'csr-key=s', 'domains=s', 'path=s', 'crt=s', 'email=s', 'curve=s', 'server=s', 'directory=s', 'api=i', 'config=s', 'renew=i', 'renew-check=s','issue-code=i',
        'handle-with=s', 'handle-as=s', 'handle-params=s', 'complete-with=s', 'complete-params=s', 'log-config=s', 'update-contacts=s', 'export-pfx=s', 'tag-pfx=s',
        'generate-missing', 'generate-only', 'revoke', 'legacy', 'unlink', 'delayed', 'live', 'quiet', 'debug+', 'help') ||
        return $opt->{'error'}->("Use --help to see the usage examples.", 'PARAMETERS_PARSE');

    if ($opt->{'config'}) {
        return $opt->{'error'}->("Configuration file '$opt->{'config'}' is not readable", 'PARAMETERS_PARSE') unless -r $opt->{'config'};
        my $rv = parse_config($opt);
        return $opt->{'error'}->("Configuration file error: $rv" , 'PARAMETERS_PARSE') if $rv;
    }

    usage_and_exit($opt) unless ($args and !$opt->{'help'});
    my $rv = reconfigure_log($opt);
    return $rv if $rv;

    $opt->{'logger'}->info("[ Crypt::LE client v$VERSION started. ]");
    my $custom_server;

    foreach my $url_type (qw<server directory>) {
        if ($opt->{$url_type}) {
            return $opt->{'error'}->("Unsupported protocol for the custom $url_type URL: $1.", 'CUSTOM_' . uc($url_type) . '_URL') if ($opt->{$url_type}=~s~^(.*?)://~~ and uc($1) ne 'HTTPS');
            my $server = $opt->{$url_type}; # For logging.
            $opt->{'logger'}->warn("Remember to URL-escape special characters if you are using $url_type URL with basic auth credentials.") if $server=~s~[^@/]*@~~;
            $opt->{'logger'}->info("Custom $url_type URL 'https://$server' is used.");
            $opt->{'logger'}->warn("Note: '$url_type' setting takes over the 'server' one.") if $custom_server;
            $custom_server = 1;
        }
    }
    $opt->{'logger'}->warn("Note: 'live' option is ignored.") if ($opt->{'live'} and $custom_server);

    if ($opt->{'renew-check'}) {
        $opt->{'error'}->("Unsupported protocol for the renew check URL: $1.", 'RENEW_CHECK_URL') if ($opt->{'renew-check'}=~s~^(.*?)://~~ and uc($1) ne 'HTTPS');
    }

    return $opt->{'error'}->("Incorrect parameters - need account key file name specified.", 'ACCOUNT_KEY_FILENAME_REQUIRED') unless $opt->{'key'};
    if (-e $opt->{'key'}) {
        return $opt->{'error'}->("Account key file is not readable.", 'ACCOUNT_KEY_NOT_READABLE') unless (-r $opt->{'key'});
    } else {
        return $opt->{'error'}->("Account key file is missing and the option to generate missing files is not used.", 'ACCOUNT_KEY_MISSING') unless $opt->{'generate-missing'};
    }

    unless ($opt->{'crt'} or $opt->{'generate-only'} or $opt->{'update-contacts'}) {
        return $opt->{'error'}->("Please specify a file name for the certificate.", 'CERTIFICATE_FILENAME_REQUIRED');
    }

    if ($opt->{'export-pfx'}) {
        if ($opt->{'crt'} and $opt->{'crt'}=~/\.pfx$/i) {
            return $opt->{'error'}->("Please ensure that the extension of the certificate filename is different from '.pfx' to be able to additionally export the certificate in pfx form.", 'CERTIFICATE_BAD_FILENAME_EXTENSION');
        }
        unless ($opt->{'csr-key'} and (-r $opt->{'csr-key'} or ($opt->{'generate-missing'} and ! -e $opt->{'csr'}))) {
            return $opt->{'error'}->("Need either existing csr-key specified or having CSR file generated (via 'generate-missing') for PFX export to work", 'NEED_CSR_KEY_FOR_EXPORT');
        }
    } elsif ($opt->{'tag-pfx'}) {
        $opt->{'logger'}->warn("Option 'tag-pfx' makes no sense without 'export-pfx' - ignoring.");
    }

    if ($opt->{'revoke'}) {
        return $opt->{'error'}->("Need a certificate file for revoke to work.", 'NEED_CERTIFICATE_FOR_REVOKE') unless ($opt->{'crt'} and -r $opt->{'crt'});
        return $opt->{'error'}->("Need an account key - revoke assumes you had a registered account when got the certificate.", 'NEED_ACCOUNT_KEY_FOR_REVOKE') unless (-r $opt->{'key'});
    } elsif (!$opt->{'update-contacts'}) {
        return $opt->{'error'}->("Incorrect parameters - need CSR file name specified.", 'CSR_FILENAME_REQUIRED') unless $opt->{'csr'};
        if (-e $opt->{'csr'}) {
            return $opt->{'error'}->("CSR file is not readable.", 'CSR_NOT_READABLE') unless (-r $opt->{'csr'});
        } else {
            return $opt->{'error'}->("CSR file is missing and the option to generate missing files is not used.", 'CSR_MISSING') unless $opt->{'generate-missing'};
            return $opt->{'error'}->("CSR file is missing and CSR-key file name is not specified.", 'CSR_MISSING') unless $opt->{'csr-key'};
            return $opt->{'error'}->("Domain list should be provided to generate a CSR.", 'DOMAINS_REQUIRED') unless ($opt->{'domains'} and $opt->{'domains'}!~/^[\s\,]*$/);
        }

        if ($opt->{'path'}) {
            my @non_writable = ();
            foreach my $path (grep { $_ } split /\s*,\s*/, $opt->{'path'}) {
                push @non_writable, $path unless (-d $path and -w _);
            }
            return $opt->{'error'}->("Path to save challenge files into should be a writable directory for: " . join(', ', @non_writable), 'CHALLENGE_DIRECTORY_NOT_WRITABLE') if @non_writable;
        } elsif ($opt->{'unlink'}) {
            return $opt->{'error'}->("Unlink option will have no effect without --path.", 'UNLINK_WITHOUT_PATH');
        }

        $opt->{'handle-as'} = $opt->{'handle-as'} ? lc($opt->{'handle-as'}) : 'http';

        if ($opt->{'handle-with'}) {
            my $error = _load_mod($opt, 'handle-with', 'handler');
            return $opt->{'error'}->("Cannot use the module to handle challenges with - $error", 'CHALLENGE_MODULE_UNAVAILABLE') if $error;
            my $method = 'handle_challenge_' . $opt->{'handle-as'};
            return $opt->{'error'}->("Module to handle challenges does not seem to support the challenge type of $opt->{'handle-as'}.", 'CHALLENGE_MODULE_UNSUPPORTED') unless $opt->{'handler'}->can($method);
            my $rv = _load_params($opt, 'handle-params');
            return $rv if $rv;
        }

        if ($opt->{'complete-with'}) {
            my $error = _load_mod($opt, 'complete-with', 'complete-handler');
            return $opt->{'error'}->("Cannot use the module to complete processing with - $error.", 'COMPLETION_MODULE_UNAVAILABLE') if $error;
            return $opt->{'error'}->("Module to complete processing with does not seem to support the required 'complete' method.", 'COMPLETION_MODULE_UNSUPPORTED') unless $opt->{'complete-handler'}->can('complete');
            my $rv = _load_params($opt, 'complete-params');
            return $rv if $rv;
        }
    }
    return;
}

sub encode_args {
    my @ARGVmod = ();
    my @vals = ();
    # Account for cmd-shell parameters splitting.
    foreach my $param (@ARGV) {
        if ($param=~/^-/) {
            if (@vals) {
                push @ARGVmod, join(" ", @vals);
                @vals = ();
            }
            if ($param=~/^(.+?)\s*=\s*(.*)$/) {
                push @ARGVmod, $1;
                push @vals, $2 if $2;
            } else {
                push @ARGVmod, $param;
            }
        } else {
            push @vals, $param;
        }
    }
    push @ARGVmod, join(" ", @vals) if @vals;
    @ARGV = @ARGVmod;
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

sub parse_config {
    my ($opt) = @_;
    unless ($opt) {
        return sub {
            return { code => 1, msg => shift }
        }
    }
    if (my $config = _read($opt->{'config'})) {
        # INI-like, simplified.
        my ($cl, $section) = (0, '');
        my $sections = {
            errors => {
                # NB: Early renewal stop is not considered an error by default.
                EXPIRATION_EARLY => 0,
            },
        };
        for (split /\r?\n/, $config) {
            $cl++;
            next if /^\s*(?:;|#)/;
            if (/^\[\s*(\w*)\s*\]$/) {
                $section = $1;
                return "Invalid section at line $cl." unless ($section and $sections->{$section});
            } else {
                return "Invalid line $cl - outside of section." unless $section;
                return "Invalid line $cl - not a key/value." unless /^\s*(\w+)\s*=\s*([^"'\;\#].*)$/;
                my ($key, $val) = ($1, $2);
                $val=~s/\s*(?:;|#).*$//;
                $sections->{$section}->{$key} = $val;
            }
        }
        # Process errors section.
        my $debug = $opt->{'debug'};
        my $errors = delete $sections->{'errors'};
        $opt->{'error'} = sub {
            my ($msg, $code) = @_;
            if ($code and $code!~/^\d+$/) {
                # Unless associated with 0 exit value, in debug mode
                # prefix the message with a passed down code.
                unless (!$debug or (defined $errors->{$code} and !$errors->{$code})) {
                    $msg = "[ $code ] " . ($msg || '');
                }
                $code = $errors->{$code};
            }
            return { msg => $msg, code => $code };
        };
        return;
    } else {
        return "Could not read config file.";
    }
}

sub reconfigure_log {
    my $opt = shift;
    if ($opt->{'log-config'}) {
        eval {
            Log::Log4perl::init($opt->{'log-config'});
        };
        if ($@ or !%{Log::Log4perl::appenders()}) {
            Log::Log4perl->easy_init({ utf8  => 1 });
            return $opt->{'error'}->("Could not init logging with '$opt->{'log-config'}' file", 'LOGGER_INIT');
        }
        $opt->{logger} = Log::Log4perl->get_logger();
    }
    $opt->{logger}->level($ERROR) if $opt->{'quiet'};
    return;
}

sub _register {
    my ($le, $opt) = @_;
    return $opt->{'error'}->("Could not load the resource directory: " . $le->error_details, 'RESOURCE_DIRECTORY_LOAD') if $le->directory;
    $opt->{'logger'}->info("Registering the account key");
    return $opt->{'error'}->($le->error_details, 'REGISTRATION') if $le->register;
    my $current_account_id = $le->registration_id || 'unknown';
    $opt->{'logger'}->info($le->new_registration ? "The key has been successfully registered. ID: $current_account_id" : "The key is already registered. ID: $current_account_id");
    $opt->{'logger'}->info("Make sure to check TOS at " . $le->tos) if ($le->tos_changed and $le->tos);
    $le->accept_tos();
    if (my $contacts = $le->contact_details) {
        $opt->{'logger'}->info("Current contact details: " . join(", ", map { s/^\w+://; $_ } (ref $contacts eq 'ARRAY' ? @{$contacts} : ($contacts))));
    }
    return 0;
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

sub _load_mod {
    my ($opt, $type, $handler) = @_;
    return unless ($opt and $opt->{$type});
    eval {
        my $mod = $opt->{$type};
        if ($mod=~/(\w+)\.pm$/i) {
            $mod = $1;
            $opt->{$type} = "./$opt->{$type}" unless $opt->{$type}=~/^(\w+:|\.*[\/\\])/;
        }
        load $opt->{$type};
        $opt->{$handler} = $mod->new();
    };
    if (my $rv = $@) {
        $rv=~s/(?: in) \@INC .*$//s; $rv=~s/Compilation failed[^\n]+$//s;
        return $rv || 'error';
    }
    return undef;
}

sub _load_params {
    my ($opt, $type) = @_;
    return unless ($opt and $opt->{$type});
    if ($opt->{$type}!~/[\{\[\}\]]/) {
        $opt->{$type} = _read($opt->{$type});
        return $opt->{'error'}->("Could not read the file with '$type'.", 'FILE_READ') unless $opt->{$type};
    }
    my $j = JSON->new->canonical()->allow_nonref();
    eval {
        $opt->{$type} = $j->decode($opt->{$type});
    };
    return ($@ or (ref $opt->{$type} ne 'HASH')) ? 
        $opt->{'error'}->("Could not decode '$type'. Please make sure you are providing a valid JSON document and {} are in place." . ($opt->{'debug'} ? $@ : ''), 'JSON_DECODE') : 0;
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
           $challenge->{'logger'}->warn("File already exists - might happen if previous validations failed and -unlink option was not used.");
        }
        if (_write($file, $text)) {
           $challenge->{'logger'}->error("Failed to save a challenge file '$file' for domain '$challenge->{domain}'");
           return 0;
        } else {
           $challenge->{'logger'}->info("Successfully saved a challenge file '$file' for domain '$challenge->{domain}'");
           return 1;
        }
    }
    $challenge->{'logger'}->info("Challenge for $challenge->{domain} requires:\nA file '$challenge->{token}' in '/.well-known/acme-challenge/' with the text: $text\n");
    unless ($params->{'delayed'}) {
        print "When done, press <Enter>\n";
        <STDIN>;
    }
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
    my (undef, $host) = $challenge->{domain}=~/^(\*\.)?(.+)$/;
    $challenge->{'logger'}->info("Challenge for '$challenge->{domain}' requires the following DNS record to be created:\nHost: _acme-challenge.$host, type: TXT, value: $value\n");
    unless ($params->{'delayed'}) {
        print "Wait for DNS to update by checking it with the command: nslookup -q=TXT _acme-challenge.$host\nWhen you see a text record returned, press <Enter>\n";
        <STDIN>;
    }
    return 1;
}

sub process_verification_dns {
    my ($results, $params) = @_;
    my (undef, $host) = $results->{domain}=~/^(\*\.)?(.+)$/;
    $results->{logger}->info("Processing the 'dns' verification for '$results->{domain}'");
    if ($results->{valid}) {
        $results->{'logger'}->info("Domain verification results for '$results->{domain}': success.");
    } else {
        $results->{'logger'}->error("Domain verification results for '$results->{domain}': error. " . $results->{'error'});
    }
    $results->{'logger'}->info("You can now delete '_acme-challenge.$host' DNS record");
    1;
}

sub usage_and_exit {
    my $opt = shift;
    print "\n Crypt::LE client v$VERSION\n\n";
    if ($opt->{'help'}) {
        print << 'EOF';
 ===============
 USAGE EXAMPLES: 
 ===============

a) To register (if needed) and issue a certificate:

 le.pl --key account.key --email "my@email.address" --csr domain.csr
       --csr-key domain.key --crt domain.crt --generate-missing
       --domains "www.domain.ext,domain.ext"

If you want to additionally export the certificate into PFX format (for
example to use it with IIS), add --export-pfx <password> as an option,
where password is what will be used to secure your PFX. This option is
currently only available for Windows binaries.

Please note that --email parameter is only used for the initial registration.
To update it later you can use --update-contacts option. Even though it is
optional, you may want to have your email registered to receive certificate
expiration notifications.

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

f) To issue a wildcard certificate, which requires DNS verification:

 le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt
       --domains "*.domain.ext" --generate-missing --handle-as dns

To include a "bare domain", add it too, since it is NOT covered by the wildcard:

 le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt
        --domains "*.domain.ext,domain.ext" --generate-missing
        --handle-as dns

g) To just generate the keys and CSR:

 le.pl --key account.key --csr domain.csr --csr-key domain.key
       --domains "www.domain.ext,domain.ext" --generate-missing
       --generate-only

h) To revoke a certificate:

 le.pl --key account.key --crt domain.crt --revoke

i) To update your contact details:

 le.pl --key account.key --update-contacts "one@example.com, two@example.com" --live

j) To reset your contact details:

 le.pl --key account.key --update-contacts "none" --live

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

You can also use --renew-check option to specify an URL, against which a
certificate will be checked for expirarion in case if it is not available
locally.

 ==========================
 ISSUANCE AND RENEWAL NOTES
 ==========================

By default a staging server is used, which does not provide trusted
certificates. This is to avoid exceeding a rate limits on Let's Encrypt
live server. To generate an actual certificate, always add --live option.

If you want to run the process in two steps (accept a challenge and then
continue after running some other process), you can use --delayed flag.
That flag interrupts the process once the challenge is received and
appropriate information about what is required is printed or logged.

Once you have fulfilled the requirements (by either creating a verification
file or a DNS record), you can re-run the process without --delayed
option.
       
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
-renew-check <URL>           : Check expiration against a specific URL.
-curve <name|default>        : ECC curve name (optional).
-path <absolute path>        : Path to .well-known/acme-challenge/ (optional).
-handle-with <module>        : Module to handle challenges with (optional).
-handle-as <http|dns|tls>    : Type of challenge, by default 'http' (optional).
-handle-params <json|file>   : JSON for the challenge module (optional).
-complete-with <module>      : Module to handle completion with (optional).
-complete-params <json|file> : JSON for the completion module (optional).
-issue-code XXX              : Exit code to use on issuance/renewal (optional).
-email <some@mail.address>   : Email for expiration notifications (optional).
-server <url|host>           : Custom server URL for API root (optional).
-directory <url>             : Custom server URL for API directory (optional).
-api <version>               : API version to use (optional).
-update-contacts <emails>    : Update contact details.
-export-pfx <password>       : Export PFX (Windows binaries only).
-tag-pfx <tag>               : Tag PFX with a specific name.
-config <file>               : Configuration file for the client.
-log-config <file>           : Configuration file for logging.
-generate-missing            : Generate missing files (key, csr and csr-key).
-generate-only               : Exit after generating the missing files.
-unlink                      : Remove challenge files automatically.
-revoke                      : Revoke a certificate.
-legacy                      : Legacy mode (shorter keys, separate CA file).
-delayed                     : Exit after requesting the challenge.
-live                        : Use the live server instead of the test one.
-debug                       : Print out debug messages.
-quiet                       : Suppress all messages but errors.
-help                        : Detailed help.

EOF
    exit(1);
}
