package Crypt::SMIME;
use warnings;
use strict;

our $VERSION = '0.10';

require XSLoader;
XSLoader::load(__PACKAGE__, $VERSION);

__PACKAGE__->_init;

1;

sub sign {
	my $this = shift;
	my $mime = shift;

	if(!defined($mime)) {
		die __PACKAGE__."#sign: ARG[1] is not defined.\n";
	} elsif(ref($mime)) {
		die __PACKAGE__."#sign: ARG[1] is a Ref. [$mime]\n";
	}

	$this->_moveHeaderAndDo($mime, '_sign');
}

sub signonly {
	my $this = shift;
	my $mime = shift;

	if(!defined($mime)) {
		die __PACKAGE__."#signonly: ARG[1] is not defined.\n";
	} elsif(ref($mime)) {
		die __PACKAGE__."#signonly: ARG[1] is a Ref. [$mime]\n";
	}

	# suppose that $mime is prepared.
	my $result = $this->_signonly($mime);
	$result =~ s/\r?\n|\r/\r\n/g;
	$result;
}

sub encrypt {
	my $this = shift;
	my $mime = shift;

	if(!defined($mime)) {
		die __PACKAGE__."#encrypt: ARG[1] is not defined.\n";
	} elsif(ref($mime)) {
		die __PACKAGE__."#encrypt: ARG[1] is a Ref. [$mime]\n";
	}

	$this->_moveHeaderAndDo($mime, '_encrypt');
}

sub isSigned {
	my $this = shift;
	my $mime = shift;

	if(!defined($mime)) {
		die __PACKAGE__."#isSigned: ARG[1] is not defined.\n";
	} elsif(ref($mime)) {
		die __PACKAGE__."#isSigned: ARG[1] is a Ref. [$mime]\n";
	}

	my $ctype = $this->_getContentType($mime);
	if($ctype =~ m!^application/(?:x-)?pkcs7-mime! && $ctype =~ m!smime-type=signed-data!) {
		# signed-data署名
		1;
	} elsif($ctype =~ m!^multipart/signed! && $ctype =~ m!protocol="application/(?:x-)?pkcs7-signature"!) {
		# 分離署名 (クリア署名)
		1;
	} else {
		undef;
	}
}

sub isEncrypted {
	my $this = shift;
	my $mime = shift;

	if(!defined($mime)) {
		die __PACKAGE__."#isEncrypted: ARG[1] is not defined.\n";
	} elsif(ref($mime)) {
		die __PACKAGE__."#isEncrypted: ARG[1] is a Ref. [$mime]\n";
	}

	my $ctype = $this->_getContentType($mime);
	if($ctype =~ m!^application/(?:x-)?pkcs7-mime!
	&& ($ctype !~ m!smime-type=! || $ctype =~ m!smime-type=enveloped-data!)) {
		# smime-typeが存在しないか、それがenveloped-dataである。
		1;
	} else {
		undef;
	}
}

sub _moveHeaderAndDo {
	my $this = shift;
	my $mime = shift;
	my $method = shift;

	# Content- または MIME- で始まるヘッダはそのままに、
	# それ以外のヘッダはmultipartのトップレベルにコピーしなければならない。
	# (FromやTo、Subject等)
	($mime,my $headers) = $this->prepareSmimeMessage($mime);

	my $result = $this->$method($mime);
	$result =~ s/\r?\n|\r/\r\n/g;

	# コピーしたヘッダを入れる
	$result =~ s/\r\n\r\n/\r\n$headers\r\n/;
	$result;
}

sub _getContentType {
	my $this = shift;
	my $mime = shift;

	my $headkey;
	my $headline = '';

	$mime =~ s/\r?\n|\r/\r\n/g;
	foreach my $line (split /\r\n/, $mime) {
		if(!length($line)) {
			return $headline;
		} elsif($line =~ m/^([^:]+):\s?(.*)/) {
			my ($key, $value) = ($1, $2);
			$headkey = $key;

			if($key =~ m/^Content-Type$/i) {
				$headline = $value;
			}
		} else {
			if($headkey =~ m/^Content-Type$/i) {
				$headline .= "\r\n$line";
			}
		}
	}

	return $headline;
}

# -----------------------------------------------------------------------------
# my ($message,$movedheader) = $smime->prepareSmimeMessage($mime);
#
sub prepareSmimeMessage {
	my $this = shift;
	my $mime = shift;

	$mime =~ s/\r?\n|\r/\r\n/g;

	my $move = '';
	my $rest = '';
	my $is_move = 0;
	my $is_rest = 1;
	while($mime=~/(.*\n?)/g) {
		my $line = $1;
		if($line eq "\r\n") { # end of header.
			$rest .= $line . substr($mime,pos($mime));
			last;
		}
		if($line=~/^(Content-|MIME-)/i) {
			($is_move, $is_rest) = (0,1);
		} elsif( $line =~ /^(Subject:)/i ) {
			($is_move, $is_rest) = (1,1);
		} elsif( $line =~ /^\S/ ) {
			($is_move, $is_rest) = (1,0);
		}
		$is_move and $move .= $line;
		$is_rest and $rest .= $line;
	}
	($rest,$move);
}

__END__

=encoding utf-8

=head1 NAME

Crypt::SMIME - S/MIME message signing, verification, encryption and decryption


=head1 SYNOPSIS

  use Crypt::SMIME;
  
  my $plain = <<'EOF';
  From: alice@example.org
  To: bob@example.com
  Subject: Crypt::SMIME test
  
  This is a test mail. Please ignore...
  EOF
  
  my $smime = Crypt::SMIME->new();
  $smime->setPrivateKey($privkey, $crt);
  # $smime->setPublicKey([$icacert]); # if need be.
  
  my $signed = $smime->sign($plain);
  print $signed;

=head1 DESCRIPTION

This module provides a class for handling S/MIME messages. It can sign, verify,
encrypt and decrypt messages. It requires libcrypto (L<http://www.openssl.org>)
to work.


=head2 METHODS

=over 4

=item new()

  my $smime = Crypt::SMIME->new();

The constructor takes no arguments.


=item setPrivateKey()

  $smime->setPrivateKey($key, $crt);
  $smime->setPrivateKey($key, $crt, $password);

Store a private key and its X.509 certificate into the instance. The private key
will be used for signing and decryption. Note that this method takes a PEM
string, not a name of a file which contains a key or a certificate.


The private key and certificate must be encoded in PEM format. The method dies
if it fails to load the key.


=item setPublicKey()

  $smime->setPublicKey($crt);
  $smime->setPublicKey([$crt1, $crt2, ...]);

Store one or more X.509 certificates into the instance. The public keys will be
used for signing, verification and encryption.


The certificates must be encoded in PEM format. The method dies if it fails to
load the certificates.


=item sign()

  $signed_mime = $smime->sign($raw_mime);

Sign a MIME message and return an S/MIME message. The signature is always
detached.


Any headers except C<Content-*>, C<MIME-*> and C<Subject> will be moved to the
top-level of the MIME message. C<Subject> header will be copied to both of the
plain text part and the top-level for mail clients which can't properly handle
S/MIME messages.


=item signonly()

  $sign = $smime->signonly($prepared_mime);

Generate a signature from a MIME message. The resulting signature is encoded in
Base64. The MIME message to be passed to this method should be preprocessed
beforehand by the prepareSmimeMessage() method. You would rarely need to call
this method directly.


=item prepareSmimeMessage()

  ($prepared_mime, $outer_header)
      = $smime->prepareSmimeMessage($source_mime);

Preprocess a MIME message to be signed. C<$prepared_mime> will be a string
containing the processed MIME message, and C<$outer_header> will be a string
that is a list of headers to be moved to the top-level of MIME message. You
would rarely need to call this method directly.


The entity body of C<$source_mime> will be directly copied to
C<$prepared_mime>. Any headers of C<$source_mime> except C<Content-*>, C<MIME-*>
and C<Subject> will be copied to C<$prepared_mime>, and those excluded headers
will be copied to C<$outer_header>. Note that the C<Subject> header will be
copied to both side exceptionally.


=item check()

  $source_mime = $smime->check($signed_mime);

Verify a signature of S/MIME message and return a MIME message. The method dies
if it fails to verify it.


=item encrypt()

  $encrypted_mime = $smime->encrypt($raw_mime);

Encrypt a MIME message and return a S/MIME message.


Any headers except C<Content-*>, C<MIME-*> and C<Subject> will be moved to the
top-level of the MIME message. C<Subject> header will be copied to both of the
plain text part and the top-level for mail clients which can't properly handle
S/MIME messages.


=item decrypt()

  $decrypted_mime = $smime->decrypt($encrypted_mime);

Decrypt an S/MIME and return a MIME message. This method dies if it fails to
decrypt it.


=item isSigned()

  $is_signed = $smime->isSigned($mime);

Return true if the given string is a signed S/MIME message. Note that if the
message was encrypted after signing, this method returns false because in that
case the signature is hidden in the encrypted message.


=item isEncrypted()

  $is_encrypted = $smime->isEncrypted($mime);

Return true if the given string is an encrypted S/MIME message. Note that if the
message was signed with non-detached signature after encryption, this method
returns false because in that case the encrypted message is hidden in the
signature.


=back

=head1 AUTHOR

Copyright 2006-2007 YMIRLINK Inc. All Rights Reserved.


This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself


Bug reports and comments to: tl@tripletail.jp


=for comment
Local Variables:
mode: cperl
End:

