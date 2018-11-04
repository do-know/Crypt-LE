package Crypt::LE::Challenge::Simple;
use strict;
use warnings;
use Digest::SHA 'sha256';
use MIME::Base64 'encode_base64url';

our $VERSION = '0.32';

=head1 NAME

Crypt::LE::Challenge::Simple - A boilerplate for extending Crypt::LE and Crypt::LE client
application (le.pl) with challenge/verification handlers.

=head1 SYNOPSIS

 use Crypt::LE;
 use Crypt::LE::Challenge::Simple;
 ...
 my $le = Crypt::LE->new();
 my $simple_challenge = Crypt::LE::Challenge::Simple->new();
 ..
 $le->accept_challenge($simple_challenge);
 $le->verify_challenge($simple_challenge);

=head1 DESCRIPTION

Crypt::LE provides the functionality necessary to use Let's Encrypt API and generate free SSL certificates for your domains.
This Crypt::LE plugin is an example of how challenge and verification handling can be done by an external module.

B<This module can also be used with the provided Crypt::LE client application - le.pl:>

 le.pl ... --handle-with Crypt::LE::Challenge::Simple --handle-params '{"key1": 1, "key2": 2, "key3": "something"}'

=cut

sub new { bless {}, shift }
 
sub handle_challenge_http {
    my $self = shift;
    my ($challenge, $params) = @_;
    # You can use external logger if it has been provided.
    $challenge->{logger}->info("Processing the 'http' challenge for '$challenge->{domain}' with " . __PACKAGE__) if $challenge->{logger};
    print "Challenge for '$challenge->{domain}' requires a file '$challenge->{token}' in '/.well-known/acme-challenge/' with the text '$challenge->{token}.$challenge->{fingerprint}'\n";
    print "When the file is in place, press <Enter>";
    <STDIN>;
    return 1;
};

sub handle_challenge_tls {
    # Return 0 to indicate an error
    return 0;
}

sub handle_challenge_dns {
    my $self = shift;
    my ($challenge, $params) = @_;
    # You can use external logger if it has been provided.
    $challenge->{logger}->info("Processing the 'dns' challenge for '$challenge->{domain}' with " . __PACKAGE__) if $challenge->{logger};
    my $value = encode_base64url(sha256("$challenge->{token}.$challenge->{fingerprint}"));
    my (undef, $host) = $challenge->{domain}=~/^(\*\.)?(.+)$/;
    print "Challenge for '$challenge->{domain}' requires the following DNS record to be created:\n";
    print "Host: _acme-challenge.$host, type: TXT, value: $value\n";
    print "Wait for DNS to update by checking it with the command: nslookup -q=TXT _acme-challenge.$host\n";
    print "When you see a text record returned, press <Enter>";
    <STDIN>;
    return 1;
}

sub handle_verification_http {
    my $self = shift;
    my ($results, $params) = @_;
    # You can use external logger if it has been provided.
    $results->{logger}->info("Processing the 'http' verification for '$results->{domain}' with " . __PACKAGE__) if $results->{logger};
    if ($results->{valid}) {
        print "Domain verification results for '$results->{domain}': success.\n";
    } else {
        print "Domain verification results for '$results->{domain}': error. $results->{error}\n";
    }
    print "You can now delete '$results->{token}' file\n";
    return 1;
}

sub handle_verification_tls {
    1;
}

sub handle_verification_dns {
    my $self = shift;
    my ($results, $params) = @_;
    my (undef, $host) = $results->{domain}=~/^(\*\.)?(.+)$/;
    # You can use external logger if it has been provided.
    $results->{logger}->info("Processing the 'dns' verification for '$results->{domain}' with " . __PACKAGE__) if $results->{logger};
    if ($results->{valid}) {
        print "Domain verification results for '$results->{domain}': success.\n";
    } else {
        print "Domain verification results for '$results->{domain}': error. $results->{error}\n";
    }
    print "You can now delete '_acme-challenge.$host' DNS record\n";
    1;
}

=head1 AUTHOR

Alexander Yezhov, C<< <leader at cpan.org> >>
Domain Knowledge Ltd.
L<https://do-know.com/>

=cut

1;
