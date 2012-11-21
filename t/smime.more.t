# -*- perl -*-
use strict;
use Test::More tests => 13;

BEGIN {
use_ok( 'Crypt::SMIME' );
}

diag( "Testing Crypt::SMIME $Crypt::SMIME::VERSION" );

my $key = &KEY;
my $crt = &CRT;
my $password = '';
my $src_mime = "Content-Type: text/plain\r\n"
             . "Subject: S/MIME test.\r\n"
             . "From: alice\@example.com\r\n"
             . "To:   bob\@example.org\r\n"
             . "\r\n"
             . "test message.\r\n";
my $verify = "Content-Type: text/plain\r\n"
           . "Subject: S/MIME test.\r\n"
           . "\r\n"
           . "test message.\r\n";
my $verify_header = "Subject: S/MIME test.\r\n"
                  . "From: alice\@example.com\r\n"
                  . "To:   bob\@example.org\r\n";
my $signed;
my $encrypted;

{
  # smime-sign.
  my $smime = Crypt::SMIME->new();
  ok($smime, "new instance of Crypt::SMIME");
  
  $smime->setPrivateKey($key, $crt, $password);
  $signed = $smime->sign($src_mime); # $src_mimeはMIMEメッセージ文字列
  ok($signed, 'got anything from $smime->sign');
  my @lf = $signed=~/\n/g;
  my @crlf = $signed=~/\r\n/g;
  is(scalar@crlf,scalar@lf,'all \n in signed are part of \r\n');
  #diag($signed);
  
  # prepare/sign-only
  my ($prepared,$header) = $smime->prepareSmimeMessage($src_mime);
  is($prepared,$verify,"prepared mime message");
  is($header,$verify_header,"outer headers of prepared mime message");
  ok(index($signed,$prepared)>=0, 'prepared message is apprers in signed message too');
  ok(index($signed,$header)>=0, 'outer headers of prepared message is apprers in signed message too');
  
  my $signed_only = $smime->signonly($src_mime);
  ok($signed_only, 'got anything from $smime->signonly');
  #diag($signed_only);
  @lf = $signed_only=~/\n/g;
  @crlf = $signed_only=~/\r\n/g;
  is(scalar@crlf,scalar@lf,'all \n in signed_only are part of \r\n');
}

{
  # smime-encrypt.
  my $smime = Crypt::SMIME->new();
  $smime->setPublicKey($crt);
  $encrypted = $smime->encrypt($signed);
  ok($encrypted, 'got anything from $smime->encrypt');
}

{
  # smime-decrypt.
  my $smime = Crypt::SMIME->new();
  $smime->setPrivateKey($key, $crt, $password);
  my $decrypted = $smime->decrypt($encrypted);
  ok($decrypted, 'got anything from $smime->decrypt');
  
  # and verify.
  $smime->setPublicKey($crt);
  is($smime->check($decrypted),$verify, 'verify result of decrypt.');
}

# end.

sub CRT
{
  <<EOF;
-----BEGIN CERTIFICATE-----
MIIBfDCCASYCCQC9wYuTsewFLTANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQGEwJB
VTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMB4XDTA3MDkyNTAyMjIzMloXDTM3MTEwNjAyMjIzMlowRTELMAkG
A1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0
IFdpZGdpdHMgUHR5IEx0ZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDdI1kvCGTV
uvgkbyZb/TEGuzBiG7YwxpafcOlgd2t/aTmI9SvlUeAqLl38kH7IAnN2vLPa2mU7
Zra5iHN0r/ctAgMBAAEwDQYJKoZIhvcNAQEFBQADQQAlcpY2FiC5qHj86MhZQUcX
MwcBQwAE9U3VQeY/E/+kNZ9gGbGi9gjc0o2oikKJEY5CrghMUGMA4X+Cmk2a35Mw
-----END CERTIFICATE-----
EOF
}
sub KEY
{
  <<EOF;
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAN0jWS8IZNW6+CRvJlv9MQa7MGIbtjDGlp9w6WB3a39pOYj1K+VR
4CouXfyQfsgCc3a8s9raZTtmtrmIc3Sv9y0CAwEAAQJBALz+t/sNdniAOhGReTxH
UT5Kf1hqDLT1FMghzSNoDNSvN5K2kRyW4jk77NGYrglkyY/Mw1ilcVlSAuL0/v4c
2wECIQD5ufTXR32p7l9OUwiuUcg4PC9p/DIMW+xIN+/lmrptbQIhAOKxiNEHvMCO
PgPghCxbSPUzcE00UcgFLKGSqtmk3ljBAiEA+Gd3GuVsJKqOdvS1f+CtzvJfH4fT
qOOPJ08s/DFrHAkCIGUqc3NNb6fDEtvqEzI0Xr/Gf+SEZ8bKwFsut/4+/FdBAiAf
XScJuxkmAOksNPRSq0sMVv3vrDBe+ldaFtDb/u8OCw==
-----END RSA PRIVATE KEY-----
EOF
}

