# -*- perl -*-
use Test::More tests => 3;
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

my $signed = eval
{
    local $/;
    open my $fh, '<', "t/nocerts.signed.txt";
    <$fh>;
};

my $smime;
ok($smime = Crypt::SMIME->new, 'new');
ok($smime->setPublicKey(crt(1)), 'setPublicKey');

lives_ok { $smime->check($signed) } 'verify signature without embedded certs';

1;

__END__

The nocerts.sign.txt was prepared as follow:

openssl smime -nocerts -sign -signer test.1.crt -inkey test.1.key -in nocerts.txt -out nocerts.signed.txt


