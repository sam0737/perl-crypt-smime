# -*- perl -*-
use Test::More tests => 23;
use Test::Exception;
use File::Spec;
use strict;
use warnings;

use Crypt::SMIME;

sub key {
    my $i = shift;

    local $/ = undef;
    open my $fh, '<', "t/test.$i.key";
    <$fh>;
}

sub crt {
    my $i = shift;

    local $/ = undef;
    open my $fh, '<', "t/test.$i.crt";
    <$fh>;
}

my $plain = q{From: alice@example.org
To: bob@example.org
Subject: Crypt::SMIME test

This is a test mail. Please ignore...
};
$plain =~ s/\r?\n|\r/\r\n/g;
my $verify = q{Subject: Crypt::SMIME test

This is a test mail. Please ignore...
};
$verify =~ s/\r?\n|\r/\r\n/g;

#-----------------------

my $smime;
ok($smime = Crypt::SMIME->new, 'new');

ok($smime->setPrivateKey(key(1), crt(1)), 'setPrivateKey (without passphrase)');

dies_ok {$smime->sign} 'sign undef';
dies_ok {$smime->sign(\123)} 'sign ref';
dies_ok {$smime->signonly} 'signonly undef';
dies_ok {$smime->signonly(\123)} 'signonly ref';
dies_ok {$smime->encrypt} 'encrypt undef';
dies_ok {$smime->encrypt(\123)} 'encrypt ref';
dies_ok {$smime->isSigned} 'isSigned undef';
dies_ok {$smime->isSigned(\123)} 'isSigned ref';
dies_ok {$smime->isEncrypted} 'isEncrypted undef';
dies_ok {$smime->isEncrypted(\123)} 'isEncrypted ref';

my $signed;
ok($signed = $smime->sign($plain), 'sign');
ok($smime->isSigned($signed), 'signed');

ok($smime->setPublicKey(crt(1)), 'setPublicKey (one key)');

my $checked;
ok($checked = $smime->check($signed), 'check');
is($checked, $verify, '$verify eq check(sign($plain))');

ok($smime->setPublicKey([crt(1), crt(2)]), 'setPublicKey (two keys)');

my $encrypted;
ok($encrypted = $smime->encrypt($plain), 'encrypt');
ok($smime->isEncrypted($encrypted), 'isEncrypted');

my $decrypted;
ok($decrypted = $smime->decrypt($encrypted), 'decrypt (by sender\'s key)');
is($decrypted, $verify, '$plain eq decrypt(encrypt($plain))');

$smime->setPrivateKey(key(2), crt(2));
ok($decrypted = $smime->decrypt($encrypted), 'decrypt (by recipient\'s key)');

1;

__END__

Certificates and Keys were prepared as follow:

test.cfg
----------------
[ req ]
distinguished_name     = req_distinguished_name
attributes             = req_attributes
prompt                 = no
[ req_distinguished_name ]
C                      = AU
ST                     = Some-State
L                      = Test Locality
O                      = Organization Name
OU                     = Organizational Unit Name
CN                     = Common Name
emailAddress           = test@email.address
[ req_attributes ]
----------------

openssl genrsa -out test.1.key
openssl req -new -key test.1.key -out test.1.csr -config test.cfg
openssl x509 -in test.1.csr -out test.2.crt -req-signkey test.1.key

openssl genrsa -out test.2.key
openssl req -new -key test.2.key -out test.2.csr -config test.cfg
openssl x509 -in test.2.csr -out test.2.crt -req-signkey test.2.key

