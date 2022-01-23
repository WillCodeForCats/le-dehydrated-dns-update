#!/usr/bin/perl
#
# Use RFC2136 DNS updates with TSIG to set DNS challenge for dehydrated.
#
# Usage in dehydrated-hook.sh:
#
# deploy_challenge() {
#     local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"
#     /path/to/dehydrated-dns-update.pl -u "${DOMAIN}" "${TOKEN_VALUE}"
# }
# clean_challenge() {
#     local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"
#     /path/to/dehydrated-dns-update.pl -d "${DOMAIN}" "${TOKEN_VALUE}"
# }
#
# https://github.com/WillCodeForCats/le-dehydrated-dns-update
#

use strict;
use Net::DNS;
use Getopt::Std;

my %opts = ();
getopts ('ud', \%opts);

my $domain = shift;
my $challenge = shift;

# config
my $dns_master = ""; #set dns update server here 
my $sleep_time = 5;
my $tsig = Net::DNS::RR->new(
    name        => 'acmechallenge-key',
    type        => 'TSIG',
    algorithm   => '', #set algorithm here
    key         => '', #set shared secret here
);

# setup
my $domain = "_acme-challenge." . $domain;
my $update = new Net::DNS::Update('rollernet.us', 'IN');
my $resolver = new Net::DNS::Resolver;

if (!defined($challenge)) {
    die("Error: TOKEN_VALUE not set");
}
if (!defined($domain)) {
    die("Error: DOMAIN not set");
}

$resolver->nameservers($dns_master);

# add challenge record
if ($opts{'u'}) {
    $update->push( pre => nxdomain("$domain TXT") );
    $update->push( update => rr_add("$domain TXT $challenge") );
    $update->sign_tsig( $tsig );
}

# delete challenge record
elsif ($opts{'d'}) {
    $update->push( pre => yxdomain("$domain TXT") );
    $update->push( update => rr_del("$domain TXT") );
    $update->sign_tsig( $tsig );
}

# show usage help
else {
    print<<EOF;

Usage: dehydrated-dns-update.pl -u|-d DOMAIN TOKEN_VALUE

    -u Update ACME Challenge
    -d Delete ACME Challenge

EOF
exit(1);
}

# send update
my $reply = $resolver->send($update);

if ($reply) {
    if ( $reply->header->rcode eq 'NOERROR' ) {
        $reply->verify( $update ) || die $reply->verifyerr;
        sleep $sleep_time unless ($opts{'d'});
        print "Update succeeded: $domain $challenge\n";
        exit(0);
    }
    else {
        print 'Update failed: ', $reply->header->rcode, "\n";
        exit(1);
    }
}
else {
    print 'Update failed: ', $resolver->errorstring, "\n";
    exit(1);
}
