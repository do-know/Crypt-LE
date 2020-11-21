package DNS;
use Data::Dumper;
use strict;
use warnings;

sub new {
    return bless {}, shift;
}

sub handle_challenge_dns {
    my $self = shift;
    my ($challenge, $params) = @_;
    # You can use external logger if it has been provided.
    $challenge->{logger}->info("Processing the 'dns' challenge for '$challenge->{domain}' with " . __PACKAGE__) if $challenge->{logger};
    # You can print the information about the challenge requested and wait for manual input to continue.
    print <<EOF;
Challenge for '$challenge->{domain}' requires the following DNS record to be created:
Host: _acme-challenge.$challenge->{host}, type: TXT, value: $challenge->{record}
Press <Enter> to coninue.
EOF
    <STDIN>;
    # Alternatively you might want to automate the process with the custom code or some external script you can run.
    # For example, in case of Windows, you could use dnscmd command to manipulate DNS records.
    # See https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd

    # Examples:
    # dnscmd dnssvr1.contoso.com /recordadd test A 10.0.0.5
    # dnscmd /recordadd test.contoso.com test MX 10 mailserver.test.contoso.com

    # NB: If you are using a 'delayed' and want to avoid running the command on re-run, then check $params->{delayed}.
    # my $rv = system('dnscmd', '/recordadd', $challenge->{host}, '_acme-challenge', 'TXT', $challenge->{record});

    return 1;
}

sub handle_verification_dns {
    my $self = shift;
    my ($results, $params) = @_;
    # You can use external logger if it has been provided.
    $results->{logger}->info("Processing the 'dns' verification for '$results->{domain}' with " . __PACKAGE__) if $results->{logger};
    # You can display the results of the verification.
    if ($results->{valid}) {
        print "Domain verification results for '$results->{domain}': success.\n";
    } else {
        print "Domain verification results for '$results->{domain}': error. $results->{error}\n";
    }
    # The record can then be deleted either manually ...
    print "You can now delete '_acme-challenge.$results->{host}' DNS record\n";
    # ... or automatically ($rv will contain an exit code).
    # my $rv = system('dnscmd', '/recorddelete', $results->{host}, '_acme-challenge', 'TXT', '/f');

    return 1;
}

sub complete {
    my $self = shift;
    my ($data, $params) = @_;
    # You can use external logger if it has been provided.
    # NB: The list of domains the certificate is issued for is in $data->{domains} (array ref).
    $data->{logger}->info("Handling process completion for " . join(', ', @{$data->{domains}}) . " with " .  __PACKAGE__) if $data->{logger};
    print "Domain Certificate '$data->{certificate_file}':\n$data->{certificate}\n";
    print "Issuer's Certificate:\n$data->{issuer}\n";
    print "Key file: '$data->{key_file}'.\n";
    print "Alternatives: " . Dumper($data->{alternatives});
    # You can automate installing the certificate and reloading the web-server at this point.
    # Note: you can reload the server by granting that permission to a specific user via sudo
    # for example, or running that process completely separately, once the certificate is obtained.
    # You should not need to run the code as a root or a privileged user at all.
    return 1;
};

1;

