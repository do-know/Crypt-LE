# Crypt-LE

This module provides the functionality necessary to use Let's Encrypt API and generate free SSL certificates for your domains. It can also be used to generate private RSA (_and from version 0.20 also ECC_) keys or Certificate Signing Requests without resorting to openssl command line. Crypt::LE is shipped with a self-sufficient client for obtaining SSL certificates - `le.pl`.

> The client + library package is codenamed ZeroSSL with the project homepage at https://ZeroSSL.com

**Note:** If you do not need the automation and the flexibility this package offers, and just want to get a free SSL certificate without installing anything, you can do it too - with the In-Browser client, also at https://ZeroSSL.com

### COMPATIBILITY

- The code has been successfully tested on more than 500 combinations of OS and Perl versions. It should install and run fine on Linux, FreeBSD, NetBSD, etc. It also works on Mac OS X and Windows (tested with ActiveState and Strawberry Perl). You can find appropriate PPMs at [ActiveState](https://code.activestate.com/ppm/Crypt-LE/). Please note that pure Windows environments are supported starting from version 0.17 of the module. If you are using Cygwin, then earlier versions would work too.

- If you are a _Windows_ user, you can download portable [Win32/Win64 binaries](https://github.com/do-know/Crypt-LE/releases) (works even on Windows XP).

- In addition, you can pull the latest client image from [Docker Hub](https://hub.docker.com/r/zerossl/client/) (lightweight non-root container).

### REQUIREMENTS

With Linux systems there are just 3 essential things which should be in place for the package to be successfully installed: "gcc", "make" and the SSL development package. The SSL development package name differs depending on Linux distribution and it can be either "libssl-dev" or "openssl-devel". See https://zerossl.com/installation.html for more details.

With Windows you don't have to install anything but Perl. In fact, in case of [Strawberry Perl](http://strawberryperl.com/releases.html) you don't have to install Perl either - it is enough to download the portable version of it, unzip and then use "cpanm" to install Crypt::LE. This way you can even carry it with you on a flash drive and run it anywhere.

### INSTALLATION

**With CPANminus**

    cpanm Crypt::LE
    
**With CPAN**

    cpan -i Crypt::LE
    
**Manual installation**:

	perl Makefile.PL
	make
	make test
	make install

### CLIENT

With `le.pl` you should be able to quickly get your SSL certificates issued. Run it without parameters to see how it is used. The client supports 'http' and 'dns' challenges out of the box.

> **Important:** By default all your actions are run against the test server, which behaves exactly as the live one, but produces certificates **not** trusted by the browsers. Once you have tested the process and want to get an actual **trusted** certificate, always append **`--live`** parameter to the command line.

*_Usage example:_*

    le.pl --key account.key --csr domain.csr --csr-key domain.key --crt domain.crt --domains  "www.domain.ext,domain.ext" --generate-missing

That will generate an account key and a CSR if they are missing. If any of those files exists, they will just be loaded, so it is safe to re-run the client. 

*_To use HTTP verification and have challenge files created/removed automatically, you can use `--path` and `--unlink` parameters:_*

    le.pl ... --path /some/path/to/.well-known/acme-challenge --unlink

*_To use DNS verification of domain ownership, you can use `--handle-as` and `handle-with` parameters:_*

     le.pl ... --handle-as dns --handle-with Crypt::LE::Challenge::Simple

For more examples, logging configuration and all available parameters overview use `--help`:

    le.pl --help

**Note:** It is advised to also use `--email` parameter for the very first run of the client, to register your account key with the email. While it is optional, that will allow you to receive certificaties expiration notifications and it might be used later to recover access to your account if you lose the key.

### RENEWALS

To RENEW your existing certificate use the same command line as you used for issuing the certificate, with one additional parameter:

       --renew XX, where XX is the number of days left until certificate expiration.

If client detects that it is XX or fewer days left until certificate expiration, then (and only then) the renewal process will be run, so the script can be safely put into crontab to run on a daily basis if needed.

The amount of days left is checked by either of two methods:

 * If the certificate (which name is used with --crt parameter) is available locally, then it will be loaded and checked.
 * If the certificate is not available locally (for example if you moved it to another server), then an attempt to connect to the domains listed in --domains or CSR will be made until the first successful response is received. The peer certificate will be then checked for expiration.

### PLUGINS

Both the library and the client can be easily extended with custom plugins to handle Let's Encrypt challenges (both pre- and post-verification). See *Crypt::LE::Challenge::Simple* module as an example of such plugin. 

The client application can also be easily extended with modules handling process completion. See *Crypt::LE::Complete::Simple* module as an example of such plugin.

Client options related to plugins are:

 * --handle-with
 * --handle-params
 * --handle-as
 * --complete-with
 * --complete-params

Please note that parameters for `--handle-params` and `--complete-params` are expected to be valid JSON documents or to point to files containing valid JSON documents.

### CUSTOM LOGGING

Client uses *Log::Log4perl* module for logging. You can easily configure it to log into file, database, syslog, etc. Logger object is available to plugins which are called from the client and to the library itself. Below is an example of a logging configuration file to log both to screen and into le.log file:

     log4perl.rootLogger=DEBUG, File, Screen
     log4perl.appender.File = Log::Log4perl::Appender::File
     log4perl.appender.File.filename = le.log
     log4perl.appender.File.mode = append
     log4perl.appender.File.layout = PatternLayout
     log4perl.appender.File.layout.ConversionPattern = %d [%p] %m%n
     log4perl.appender.Screen = Log::Log4perl::Appender::Screen
     log4perl.appender.Screen.layout = PatternLayout
     log4perl.appender.Screen.layout.ConversionPattern = %d [%p] %m%n

Save the configuration into some file and then run `le.pl` with `--log-config` parameter specifying that configuration file name, for those settings to take effect.

### SUPPORT AND DOCUMENTATION

After installing, you can find documentation for this module with the
perldoc command.

    perldoc Crypt::LE

You can also look for information at:

 * [RT, CPAN's request tracker (report bugs here)](http://rt.cpan.org/NoAuth/Bugs.html?Dist=Crypt-LE)
 * [AnnoCPAN, Annotated CPAN documentation](http://annocpan.org/dist/Crypt-LE)
 
For feedback or custom development requests see:

 * Company homepage - https://do-know.com
 * Project homepage - https://ZeroSSL.com

### NOTES

Crypt::LE has been initially created over weekend, when I noticed that some of my previously bought certificates are about to expire soon enough. The initial goal was to make this work, make it easy to use and possibly remove the need to use openssl command line. It may contain some (hopefully minor) bugs, so feel free to submit a bug report.

If you'd like to contribute a custom plugin, for example to support automatic DNS records creation and removal via API of certain DNS providers (or your registrar), feel free to create a module under Crypt::LE::Challenge:: namespace and either upload it to CPAN or submit a pull request. 

In the former case please specify a dependency from Crypt::LE of at least version 0.11 in your Makefile.

In the latter case please be aware that your module might be uploaded to CPAN later (unless you object) and might be uploaded separately rather than as a part of Crypt::LE (this might happen if you are using dependencies not necessarily required for the rest of Crypt::LE package).

You can also contribute the completion-handling modules under Crypt::LE::Complete:: namespace, for example to scp the domain  key and certificate to another host or to send an email about successful certificate renewal.

### LICENSE AND COPYRIGHT

Copyright (C) 2016-2017 Alexander Yezhov

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

http://www.perlfoundation.org/artistic_license_2_0

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
