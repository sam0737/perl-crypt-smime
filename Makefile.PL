use strict;
use warnings;
use ExtUtils::MakeMaker;

require 'openssl_config.PL';
my $OPENSSL = &openssl_config();

WriteMakefile(
    NAME                => 'Crypt::SMIME',
    AUTHOR              => 'Ymirlink <tl@tripletail.jp>',
    VERSION_FROM        => 'SMIME.pl',
    ABSTRACT            => 'S/MIME message signing, verification, encryption and decryption',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::Exception' => 0,
        'Test::More'      => 0,
        'XSLoader'        => 0,
    },
    LIBS                => "$OPENSSL->{LIBS}",
    INC                 => "$OPENSSL->{CFLAGS}",
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => {
        FILES => 'Crypt-SMIME-* SMIME.pod',
    },
    PM                  => {
        'lib/SMIME.pm'     => '$(INST_LIBDIR)/SMIME.pm',
        'lib/SMIME/JA.pod' => '$(INST_LIBDIR)/SMIME/JA.pod',
    },
    depend              => {
        'lib/SMIME.pm'
          => "SMIME.pl SMIME.pod\n" .
	         "\tmkdir -p lib\n" .
                 "\tcat SMIME.pl  >  \$\@\n" .
                 "\techo          >> \$\@\n" .
                 "\techo __END__  >> \$\@\n" .
                 "\techo          >> \$\@\n" .
                 "\tcat SMIME.pod >> \$\@\n",
        
        'SMIME.pod'
          => "SMIME.mlpod\n" .
                 "\tmlpod2pod \$< > \$\@",

        'lib/SMIME/JA.pod'
          => "SMIME.mlpod\n" .
	         "\tmkdir -p lib/SMIME\n" .
                 "\tmlpod2pod --langs=ja \$< | perl -pe 's/(\\xe5\\x90\\x8d\\xe5\\x89\\x8d)/NAME/' > \$\@",
    },
);

