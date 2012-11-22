# -*- perl -*-
use Test::More;
use Test::Exception;
use File::Spec;


# Create the following certificate tree:
#
# + The root CA (self-signed)
# |
# `-+ An intermediate CA #1
#   |
#   `-+ An intermediate CA #2
#     |
#     `-- An user
#
# Then do the following:
#
#  1. Make a mail signed by an user private key and let it contain
#     certificates of two intermediate CAs.
#
#  2. Verify the mail with only the root CA certificate and its
#     key. Can we prove the mail is actually trustable?

plan tests => 8;

use_ok('Crypt::SMIME');

sub key {
    my $who = shift;
    local $/;
    open my $fh, '<', "t/chained.$who.key" or die $!;
    return scalar <$fh>;
};

sub crt {
    my $who = shift;
    local $/;
    open my $fh, '<', "t/chained.$who.crt" or die $!;
    return scalar <$fh>;
}

my $plain = q{From: alice@example.org
To: bob@example.org
Subject: Crypt::SMIME test

This is a test mail. Please ignore...
};
$plain =~ s/\r?\n|\r/\r\n/g;
my $verified = q{Subject: Crypt::SMIME test

This is a test mail. Please ignore...
};
$verified =~ s/\r?\n|\r/\r\n/g;

# -----------------------------------------------------------------------------

my $signed = do {
    my $SMIME;
    lives_ok { $SMIME = Crypt::SMIME->new } 'new';
    lives_ok { $SMIME->setPrivateKey(key('user'), crt('user')) } 'setPrivateKey(USER)';
    lives_ok { $SMIME->setPublicKey(crt('intermed-1')."\n".crt('intermed-2')) } 'setPublicKey(INTERMED-1 & INTERMED-2)';
    my $tmp;
    lives_ok { $tmp = $SMIME->sign($plain) } 'sign($plain)';
    $tmp;
};

do {
    my $SMIME = Crypt::SMIME->new;
    lives_ok { $SMIME->setPublicKey(crt('root')) } 'setPublicKey(ROOT)';
    my $checked;
    lives_ok { $checked = $SMIME->check($signed) } 'check';
    is($checked, $verified, '$verified eq check(sign($plain))');
};

__END__

Certificates and Keys were prepared as follow:

###################
### CA
###################
chained.root.cfg
----------------
[ req ]
distinguished_name     = req_distinguished_name
attributes             = req_attributes
req_extensions         = v3_ca
prompt                 = no
[ req_distinguished_name ]
C                      = JP
ST                     = Some-State
L                      = Some-Locality
O                      = Crypt::SMIME
OU                     = The Root CA
CN                     = ROOT
[ req_attributes ]
[ v3_ca ]
basicConstraints       = CA:true
----------------

openssl genrsa > chained.root.key
openssl req -new -key chained.root.key -out chained.root.csr -config chained.root.cfg
openssl x509 -in chained.root.csr -out chained.root.crt -req -signkey chained.root.key -set_serial 1 -extfile chained.root.cfg -extensions v3_ca

###################
### Intermediate 1
###################
chained.intermed-1.cfg
----------------
[ req ]
distinguished_name     = req_distinguished_name
attributes             = req_attributes
req_extensions         = v3_ca
prompt                 = no
[ req_distinguished_name ]
C                      = JP
ST                     = Some-State
L                      = Some-Locality
O                      = Crypt::SMIME
OU                     = An intermediate CA No.1
CN                     = INTERMED-1
[ req_attributes ]
[ v3_ca ]
basicConstraints       = CA:true
----------------

openssl genrsa > chained.intermed-1.key
openssl req -new -key chained.intermed-1.key -out chained.intermed-1.csr -config chained.intermed-1.cfg
openssl x509 -in chained.intermed-1.csr -out chained.intermed-1.crt -req -CA chained.root.crt -CAkey chained.root.key -set_serial 1 -extfile chained.root.cfg -extensions v3_ca

###################
### Intermediate 2
###################
chained.intermed-2.cfg
----------------
[ req ]
distinguished_name     = req_distinguished_name
attributes             = req_attributes
req_extensions         = v3_ca
prompt                 = no
[ req_distinguished_name ]
C                      = JP
ST                     = Some-State
L                      = Some-Locality
O                      = Crypt::SMIME
OU                     = An intermediate CA No.2
CN                     = INTERMED-2
[ req_attributes ]
[ v3_ca ]
basicConstraints       = CA:true
----------------

openssl genrsa > chained.intermed-2.key
openssl req -new -key chained.intermed-2.key -out chained.intermed-2.csr -config chained.intermed-2.cfg
openssl x509 -in chained.intermed-2.csr -out chained.intermed-2.crt -req -CA chained.intermed-1.crt -CAkey chained.intermed-1.key -set_serial 1 -extfile chained.root.cfg -extensions v3_c

###################
### End User
###################
chained.user.cfg
----------------
[ req ]
distinguished_name     = req_distinguished_name
attributes             = req_attributes
prompt                 = no
[ req_distinguished_name ]
C                      = JP
ST                     = Some-State
L                      = Some-Locality
O                      = Crypt::SMIME
OU                     = An user
CN                     = USER
[ req_attributes ]
----------------

openssl genrsa > chained.user.key
openssl req -new -key chained.user.key -out chained.user.csr -config chained.user.cfg
openssl x509 -in chained.user.csr -out chained.user.crt -req -CA chained.intermed-2.crt -CAkey chained.intermed-2.key -set_serial 1

