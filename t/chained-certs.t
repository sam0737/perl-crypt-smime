# -*- perl -*-
use Test::More tests => 8;
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

my $DEVNULL = File::Spec->devnull();
my $OPENSSL = do {
    my $tmp = `which openssl 2>$DEVNULL`;
    if ($? == 0) {
        chomp $tmp;
        $tmp;
    }
    else {
        BAIL_OUT("No openssl(1) were found in the PATH.");
    }
};
diag "Using `$OPENSSL'...\n";

# Create the root CA.
do {
    do {
        open my $fh, '>', "root.$$.cfg" or die $!;
        print {$fh} <<'EOF';
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
EOF
        close $fh;
    };
    system(qq{$OPENSSL genrsa > root.$$.key 2>$DEVNULL}) and die $!;
    system(qq{$OPENSSL req -new -key root.$$.key -out root.$$.csr -config root.$$.cfg 2>&1 >$DEVNULL}) and die $!;
    system(qq{$OPENSSL x509 -in root.$$.csr -out root.$$.crt -req -signkey root.$$.key -set_serial 1 -extfile root.$$.cfg -extensions v3_ca 2>&1 >$DEVNULL}) and die;
};

# Create an intermediate CA #1.
do {
    do {
        open my $fh, '>', "intermed-1.$$.cfg" or die $!;
        print {$fh} <<'EOF';
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
EOF
        close $fh;
    };
    system(qq{$OPENSSL genrsa > intermed-1.$$.key 2>$DEVNULL}) and die $!;
    system(qq{$OPENSSL req -new -key intermed-1.$$.key -out intermed-1.$$.csr -config intermed-1.$$.cfg 2>&1 >$DEVNULL}) and die $!;
    system(qq{$OPENSSL x509 -in intermed-1.$$.csr -out intermed-1.$$.crt -req -CA root.$$.crt -CAkey root.$$.key -set_serial 1 -extfile root.$$.cfg -extensions v3_ca 2>&1 >$DEVNULL}) and die;
};

# Create an intermediate CA #2.
do {
    do {
        open my $fh, '>', "intermed-2.$$.cfg" or die $!;
        print {$fh} <<'EOF';
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
EOF
        close $fh;
    };
    system(qq{$OPENSSL genrsa > intermed-2.$$.key 2>$DEVNULL}) and die $!;
    system(qq{$OPENSSL req -new -key intermed-2.$$.key -out intermed-2.$$.csr -config intermed-2.$$.cfg 2>&1 >$DEVNULL}) and die $!;
    system(qq{$OPENSSL x509 -in intermed-2.$$.csr -out intermed-2.$$.crt -req -CA intermed-1.$$.crt -CAkey intermed-1.$$.key -set_serial 1 -extfile root.$$.cfg -extensions v3_ca 2>&1 >$DEVNULL}) and die;
};

# Create an user.
do {
    do {
        open my $fh, '>', "user.$$.cfg" or die $!;
        print {$fh} <<'EOF';
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
EOF
        close $fh;
    };
    system(qq{$OPENSSL genrsa > user.$$.key 2>$DEVNULL}) and die $!;
    system(qq{$OPENSSL req -new -key user.$$.key -out user.$$.csr -config user.$$.cfg 2>&1 >$DEVNULL}) and die $!;
    system(qq{$OPENSSL x509 -in user.$$.csr -out user.$$.crt -req -CA intermed-2.$$.crt -CAkey intermed-2.$$.key -set_serial 1 2>&1 >$DEVNULL}) and die;
};

# Delete temporary files later.
END {
    foreach my $who (qw(root intermed-1 intermed-2 user)) {
        unlink "$who.$$.key", "$who.$$.cfg", "$who.$$.csr", "$who.$$.crt";
    }
}

sub key {
    my $who = shift;
    local $/;
    open my $fh, '<', "$who.$$.key" or die $!;
    return scalar <$fh>;
};

sub crt {
    my $who = shift;
    local $/;
    open my $fh, '<', "$who.$$.crt" or die $!;
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

BEGIN {
    use_ok('Crypt::SMIME');
}

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
