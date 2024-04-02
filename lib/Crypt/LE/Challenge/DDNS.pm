package Crypt::LE::Challenge::DDNS;

=head1 NAME

Crypt::LE::Challenge::DDNS - use dynamic DNS for ACME challenges

=head1 SYNOPSIS

 use Crypt::LE;
 use Crypt::LE::Challenge::DDNS;
 ...
 my $le = Crypt::LE->new();
 my $ddns_challenge = Crypt::LE::Challenge::DDNS->new(...);
 ..
 $le->accept_challenge($ddns_challenge, ...);
 $le->verify_challenge($ddns_challenge, ...);

 # Shell command line:
 $ le.pl ... --handle-as dns --handle-with Crypt::LE::Challenge::DDNS \
    --handle-params '{"server": "127.0.0.1", "keyfile": "/var/named/keys/_le.example.org.key", "zone": "_le.example.org"}'

=head1 DESCRIPTION

This module uses Dynamic DNS (DDNS) updates for storing the ACME challenges
for DNS-01 validation.

Recommended mode of operation is to set up a Dynamic DNS subdomain
solely for ACME challenges (for example, C<_le.example.org>), and for domain
names which would use Let's Encrypt certificates map their
C<_acme-challenge.$fqdn> into this domain.

For example, to get a certificate for C<myhost.example.org>,
create the following static DNS record in the C<example.org> zone:

  _acme-challenge.myhost.example.org. IN CNAME myhost.example.org._le.example.org.

This module will then ask the ACME server (Let's Encrypt CA) for a DNS-based
challenge, and will store it using DDNS update to
C<myhost.example.org._le.example.org.> TXT record. LE will then try to verify
the challenge at C<_acme-challenge.myhost.example.org> and will find it
after being redirected by the above CNAME record.

Note that "C<example.org>" string is used both in the DDNS domain name,
and inside that name. This is intentional - this way one common DDNS domain
C<_le.example.org> can serve for ACME challenges for multiple
real DNS domains. If you want the renaming to be done in a different way,
feel free to override the C<rr_from_fqdn()> function in this module.

The module accepts the following parameters (usable in C<--handle-params>
from the C<le.pl> command line):

=over 4

=item server

IP address of the DDNS server, where challenges will be stored.

=item keyfile

Authentication key for DDNS. This will be used for signing the DDNS update
requests. Any key file format supported by C<Net::DNS::RR::TSIG> will do.

=item zone

DDNS zone to which challenges will be written (C<_le.example.org> in the
above examples). If "zone" is a suffix of the host name for which the
certificate is being created (e.g. C<example.org>), then the challenge
will be stored directly to

  _acme-challenge.$that_host_name

instead of mapping to a different zone as described above.

=back

=head1 DDNS ZONE SETUP

A quick and dirty tutorial how to create a Dynamic DNS zone and key
in BIND.

Firstly, create directories and the key file:

  BIND_DIR=/var/named
  DDNS_DOMAIN=_le.example.org
  install -d -u named -g named -m 775 $BIND_DIR/dynamic
  install -d -u root -g named -m 755 $BIND_DIR/keys
  tsig-keygen $DDNS_DOMAIN > $BIND_DIR/keys/$DDNS_DOMAIN.key
  chown root:named $BIND_DIR/keys/$DDNS_DOMAIN.key
  chmod 640 $BIND_DIR/keys/$DDNS_DOMAIN.key

Create a zone file:

  cat > $BIND_DIR/dynamic/$DDNS_DOMAIN <<'EOF'
  $TTL 300
     IN SOA  ns.example.org. root.example.org. (
        1   ; serial
        1H  ; refresh
        3H  ; retry
        2W  ; expire
        1   ; negative ttl
        )
     IN NS   ns.example.org.
  EOF

Use the key and zone file in your named.conf:

  include "keys/_le.example.org.key";

  zone "_le.example.org" {
    type master;
    file "dynamic/_le.example.org";
    allow-query { any; };
    allow-update { !{ !127.0.0.1; any; }; key _le.example.org; };
    journal "dynamic/_le.example.org.jnl";
  }

Reload named and verify that it works:

  rndc reload
  nsupdate -k $BIND_DIR/keys/$DDNS_DOMAIN.key
  > server 127.0.0.1
  > add test._le.example.org. 300 TXT "my test record"
  > send
  host -t any test._le.example.org. 127.0.0.1

=head1 SEE ALSO

L<https://letsencrypt.org/docs/challenge-types/>, L<Crypt::LE>,
L<Net::DNS::RR::TSIG>, L<Crypt::LE::Challenge::Simple>,
L<nsupdate(1)>, L<tsig-keygen(1)>

=head1 AUTHOR

Jan "Yenya" Kasprzak C<< <kas you_know_what yenya.net> >>.
Based on C<Crypt::LE::Challenge::Simple> by Alexander Yezhov.

=cut

use strict;
use warnings;
use Data::Dumper;
use base qw(Crypt::LE::Challenge::Simple);
use Digest::SHA 'sha256';
use MIME::Base64 'encode_base64url';
use Net::DNS;
use Net::DNS::RR::TSIG;
use Carp;

our $TTL        = 1;

sub _sanitize_params {
	my ($params) = @_;
	my $hp = $params->{'handle-params'}
		or croak '_sanitize_params: handle-params not defined';
	my $zone = $hp->{zone}
		or croak 'zone in handle-params missing';
	$zone =~ s/\.\z//;
	my $server = $hp->{server}
		or croak 'server in handle-params missing';
	my $keyfile = $hp->{keyfile}
		or croak 'keyfile in handle-params missing';
	return ($zone, $server, $keyfile);
}

sub rr_from_fqdn {
    my ($fqdn, $zone) = @_;

    if ($fqdn =~ /\.$zone\z/) {
	return "_acme-challenge.$fqdn.";
    } else {
        return "$fqdn.$zone.";
    }
}

sub handle_challenge_dns {
    my ($self, $challenge, $params) = @_;
    # print STDERR Dumper $challenge;
    # print STDERR Dumper $params;
    my ($zone, $server, $keyfile) = _sanitize_params($params);

    my $logger = $challenge->{logger};
    # my $text = $challenge->{record};
    $logger->debug("token=$challenge->{token}");
    $logger->debug("fingerprint=$challenge->{fingerprint}");
    my $text = encode_base64url(sha256(
        "$challenge->{token}.$challenge->{fingerprint}"
    ));
    my $fqdn = $challenge->{host};
    my $rrname = rr_from_fqdn($fqdn, $zone);

    my $update = new Net::DNS::Update($zone, 'IN');
    $update->push(update => rr_del("$rrname TXT"));
    $update->push(update => rr_add(qq{$rrname $TTL TXT $text}));
    $update->sign_tsig($keyfile);

    my $resolver = new Net::DNS::Resolver;
    $resolver->nameservers($server);

    $logger->info("Creating DDNS record $rrname TXT $text at $server.");
    my $reply = $resolver->send($update);
    if ($reply && $reply->header->rcode eq 'NOERROR') {
        $logger->info("Created successfully.");
        return 1; # success
    }
    if ($reply) {
        $logger->error("FAILED: Server returned "
            . $reply->header->rcode . '.');
    } else {
        $logger->error("FAILED: Resolver error "
            . $resolver->errorstring . '.');
    }
    return undef;
}

sub handle_verification_dns {
    my ($self, $results, $params) = @_;

    my $logger = $results->{logger};
    my ($zone, $server, $keyfile) = _sanitize_params($params);

    my $fqdn = $results->{domain};
    my $rrname = rr_from_fqdn($fqdn, $zone);
    $logger->info("DNS verification for $fqdn:");

    if ($results->{valid}) {
        $logger->info("Success for $fqdn.");
    } else {
        $logger->error("FAILURE for $fqdn: $results->{error}");
    }

    my $update = new Net::DNS::Update($zone, 'IN');
    $update->push(update => rr_del("$rrname TXT"));
    $update->sign_tsig($keyfile);

    my $resolver = new Net::DNS::Resolver;
    $resolver->nameservers($server);

    $logger->info("Removing the $rrname record at $server");
    my $reply = $resolver->send($update);
    if ($reply && $reply->header->rcode eq 'NOERROR') {
        $logger->info("Removed $rrname TXT.");
    } elsif ($reply) {
        $logger->error("FAILED: Server returned "
            . $reply->header->rcode . '.');
    } else {
        $logger->error("FAILED: Resolver error "
            . $resolver->errorstring . '.');
    }
    return $results->{valid} ? 1 : undef;
}

1;
