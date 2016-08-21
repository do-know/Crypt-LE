package Crypt::LE::Complete::Simple;
use strict;
use warnings;

our $VERSION = '0.18';

=head1 NAME

Crypt::LE::Complete::Simple - A boilerplate for extending Crypt::LE client application (le.pl) with completion handlers.

=head1 SYNOPSIS

 le.pl ... --complete-with Crypt::LE::Complete::Simple --complete-params '{"key1": 1, "key2": 2, "key3": "something"}'

=head1 DESCRIPTION

Crypt::LE provides the functionality necessary to use Let's Encrypt API and generate free SSL certificates for your domains.
It is also shipped with le.pl client application. This Crypt::LE plugin is an example of how process completion can be handled 
by an external module when le.pl is used. 

You only need a 'complete' method defined (apart from 'new') and returning a true value on success.

=cut

sub new { bless {}, shift }
 
sub complete {
    my $self = shift;
    my ($data, $params) = @_;
    # You can use external logger if it has been provided.
    if ($data->{logger}) {
        # NB: The list of domains the certificate is issued for is in $data->{domains} (array ref).
        $data->{logger}->info("Handling process completion for " . join(', ', @{$data->{domains}}) . " with " .  __PACKAGE__);
    }
    print "Domain Certificate '$data->{certificate_file}':\n$data->{certificate}\n";
    print "Issuer's Certificate:\n$data->{issuer}\n";
    print "Key file: '$data->{key_file}'.\n";
    return 1;
};

=head1 AUTHOR

Alexander Yezhov, C<< <leader at cpan.org> >>
Domain Knowledge Ltd.
L<https://do-know.com/>

=cut

1;
