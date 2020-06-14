# Crypt-LE

This module provides the functionality necessary to use Let's Encrypt API and generate free SSL certificates for your domains. It can also be used to generate private RSA/ECC keys and Certificate Signing Requests without resorting to openssl command line. Crypt::LE is shipped with a self-sufficient client for obtaining SSL certificates - `le.pl`. 

**Both ACME v1 and ACME v2 protocols and wildcard certificate issuance are supported.**

_Please note that ACME v1 is being deprecated by Let's Encrypt and, starting from version 0.34 of the client, the default version selected is ACME v2 (unless you have specified the version explicitly using `--api` option or specified a custom server using `--server` option - in the latter case the client will use auto-sensing to select appropriate protocol version)._

**Note:** If you do not need the automation and the flexibility this package offers, and just want to get a free SSL certificate without installing anything, you can do that online on **[ZeroSSL.com](https://zerossl.com/)**.

#### COMPATIBILITY

- The code has been successfully tested on more than 500 combinations of OS and Perl versions. It should install and run fine on Linux, FreeBSD, NetBSD, etc. It also works on Mac OS X and Windows (tested with ActiveState and Strawberry Perl).

- If you are a Windows user, you can download portable **[Win32/Win64 binaries](https://github.com/do-know/Crypt-LE/releases)** (they work even on Windows XP and require NO installation).

- In addition, you can use the latest **[Docker Image](https://hub.docker.com/r/zerossl/client/)** (lightweight non-root container).

__Quick start on Windows:__

> Download and unzip the **[latest release](https://github.com/do-know/Crypt-LE/releases/latest/download/le64.zip)** of the client for Windows (no installation required, for more details see the [releases page](https://github.com/do-know/Crypt-LE/releases)), then run the client and follow the instructions (below we are issuing the certificate for `example.org` and `www.example.org` in interactive mode - see the full documentation for more usage examples):

`le64.exe -email "admin@example.org" -key account.key -csr domain.csr -csr-key domain.key -crt domain.crt -domains "example.org,www.example.org" -generate-missing -live`

__Quick start on Linux/Mac:__

> Install the client using one of the [methods described](#installation) (usually "cpan -i Crypt::LE" should be sufficient), then run the client and follow the instructions (below we are issuing the certificate for `example.org` and `www.example.org` in interactive mode - see the full documentation for more usage examples):

`le.pl -email "admin@example.org" -key account.key -csr domain.csr -csr-key domain.key -crt domain.crt -domains "example.org,www.example.org" -generate-missing -live`

Table of Contents
-----------------

  * [Requirements](#requirements)
      * [For Linux](#for-linux)
      * [For Windows](#for-windows)
  * [Installation](#installation)
      * [With CPANminus](#with-cpanminus)
      * [With CPAN](#with-cpan)
      * [Manual installation](#manual-installation)
      * [Windows installation](#windows-installation-with-strawberry-perl)
  * [Client](#client)
  * [Windows client](#windows-client)
  * [Wildcard certificates support](#wildcard-certificates-support)
  * [PFX/P12 (IIS) support](#pfxp12-iis-support)
  * [IDN (internationalized domain names) support](#idn-internationalized-domain-names-support)
  * [Renewals](#renewals)
  * [Contact details updates](#contact-details-updates)
  * [Plugins](#plugins)
  * [Custom logging](#custom-logging)
  * [Custom exit codes](#custom-exit-codes)
  * [Proxy support](#proxy-support)
  * [Support and Documentation](#support-and-documentation)

### REQUIREMENTS

#### For Linux

With Linux systems there are just 3 essential things which should be in place for the package to be successfully installed: "gcc", "make" and the SSL development package (usually either "libssl-dev" or "openssl-devel"). You can install those as shown below - _note that your server may already have them, so you might just try installing the client/library itself_.

- For CentOS minimal installation: `sudo yum install gcc openssl-devel`

- For Debian/Ubuntu server installation: `sudo apt-get install make gcc libssl-dev`

#### For Windows

_With Windows there are no specific requirements at all and *you don't have to install anything* if you want to use [Windows binaries](https://github.com/do-know/Crypt-LE/releases) - self-sufficient and portable. Otherwise you just need to install Perl (see below)._

If you use [Strawberry Perl](http://strawberryperl.com/releases.html), then CPANminus will be already pre-installed and you will only need to instatll Crypt::LE itself. It is enough to download the portable version of Strawberry Perl for your platform (64bit or less likely 32bit). Then just unzip it to the directory of your choice (say C:\Perl64\) and use "cpanm" to install Crypt::LE.

If you use ActiveState Perl, then after installing the Perl itself, you will need to install App-cpanminus (using 'ppm' - Perl Package Manager). Note that for business license users ActiveState offers more ppm packages (including Crypt-LE), so it could then be installed directly, without the need to install App-cpanminus.

### INSTALLATION

> _The installation is quite easy and straightforward. The provided client does not need any specific privileges (certainly does not need to be run as a root or any privileged user). Keep in mind that the client functionality can be extended with plugins, so make sure you have read the [Plugins](https://github.com/do-know/Crypt-LE#plugins) section and especially [Plugins in multiuser environment](https://github.com/do-know/Crypt-LE#plugins-in-multiuser-environment) notes._

Please note that for Windows you can just download portable **[Win32/Win64 binaries](https://github.com/do-know/Crypt-LE/releases)** - you do not have to install anything, _even if you intend to use custom Perl plugins_. You would only need to install the Crypt::LE library on Windows if you intend to use it with your own client (or the custom version of le.pl client). 

#### With CPANminus

    cpanm Crypt::LE

#### With CPAN

    cpan -i Crypt::LE
    
#### Manual installation

	perl Makefile.PL
	make
	make test
	make install

#### Windows installation (with Strawberry Perl)

    cpanm -f Log::Log4perl
    cpanm Crypt::LE

Note: there might be some rare cases where installation fails on Linux - for example on a freshly installed Debian 10 (buster) you may see an error for Net::SSLeay. This can be fixed by running `sudo apt-get install libnet-ssleay-perl`.

See https://zerossl.com/installation.html for more details.

### CLIENT

With `le.pl` you should be able to quickly get your SSL certificates issued. Run it without parameters to see how it is used or with --help for an extended help and examples. The client supports 'http' and 'dns' challenges out of the box.

> **Important:** By default all your actions are run against the test server, which behaves exactly as the live one, but produces certificates **not** trusted by the browsers. Once you have tested the process and want to get an actual **trusted** certificate, always append **`--live`** parameter to the command line.

*_Usage example:_*

    le.pl --key account.key --email "my@email.address" --csr domain.csr --csr-key domain.key --crt domain.crt --domains  "www.domain.ext,domain.ext" --generate-missing

That will generate an account key and a CSR if they are missing. If any of those files exists, they will just be loaded, so it is safe to re-run the client.

Please note that --email parameter is only used for the initial registration. To update it later you can use --update-contacts option. Even though it is optional, you may want to have your email registered to receive certificate expiration notifications.

*_To use HTTP verification and have challenge files created/removed automatically, you can use `--path` and `--unlink` parameters:_*

    le.pl --key account.key --email "my@email.address" --csr domain.csr --csr-key domain.key --crt domain.crt --domains "www.domain.ext,domain.ext" --generate-missing --unlink --path /some/path/.well-known/acme-challenge

If `www.domain.ext` and `domain.ext` use different "webroots", you can specify those in --path parameter, as a comma-separated list as follows:

    le.pl --key account.key --email "my@email.address" --csr domain.csr --csr-key domain.key --crt domain.crt --domains "www.domain.ext,domain.ext" --generate-missing --unlink --path /a/.well-known/acme-challenge,/b/.well-known/acme-challenge

Please note that with multiple webroots specified, the amount of those should match the amount of domains listed. They will be used in the same order as the domains given and all of those folders should be writable.

*_To use DNS verification of domain ownership, you can use `--handle-as` parameter:_*

     le.pl ... --handle-as dns

For more examples, logging configuration and all available parameters overview use `--help`:

    le.pl --help
    
### WINDOWS CLIENT

Everything described [above](#client) for the Perl client is applicable to the Windows client, which you can download from the [Releases page](https://github.com/do-know/Crypt-LE/releases). The only difference is that you will be running either le32.exe or le64.exe (depending on your platform) instead of le.pl. There is one thing though you need to take into account when you are specifying the `--path` to store verification files for the HTTP verification on Windows:

> You should **NOT** use a single backslash before the closing quote (if you had path quoted) - you need to either use a double-backslash or none at all. This is specific to Windows environment. To illustrate:

- `--path C:\Directory` - right
- `--path C:\Directory\` - right
- `--path "C:\Directory"` - right
- `--path "C:\\Directory\\"` - right
- `--path "C:\Directory\\"` - right
- `--path "C:\Directory\"` - wrong

You can also use a forward slash (/) if you like.

### WILDCARD CERTIFICATES SUPPORT

*_To issue a wildcard certificate, use DNS verification and specify the domain in the following format: *.some.domain._*

     le.pl ... --domains "*.some.domain" --handle-as dns

Please note that at the moment wildcards are only supported by the v2.0 of the API and they can only be issued if DNS verification is used.

**Important** - if you are issuing a wildcard certificate and also want a so-called "naked domain" ("some.domain") to be covered, list both of those names in the `domains` parameter. You will then need to create two TXT records with _identical_ names but different values - this is normal and this is how you should create them.

     le.pl ... --domains "*.some.domain, some.domain" --handle-as dns

### PFX/P12 (IIS) SUPPORT

Windows binaries include export functions into PFX/P12 format, which is normally required by IIS. The export (in addition to saving certificates in PEM format) can be activated by specifying a PFX password with `--export-pfx` option.

      le.pl ... --export-pfx "mypassword"
      
**Note:** This fuction does NOT require OpenSSL or any PFX conversion tools to be installed on your machine - it is supported internally by the client. 

By default, exported PFX file will be seen as "ZeroSSL exported" under the "Friendly Name" column of the Certificate Management Console. If you want to specify your own arbitrary string instead, use `--tag-pfx` parameter.

      le.pl ... --export-pfx "mypassword" --tag-pfx "My own Friendly Name"
      
**NB:** If you are receiving an error mentioning PKCS12 during an attempt to export to PFX, please ensure that the domain key which you have specified with `--csr-key` option is indeed a private key in PEM format (with -----BEGIN and -----END lines around it). If it is a key exported via MMC in Windows for example, you may need to export the key and remove the passphrase from it before it can be used, for example as mentioned in [this guide](https://www.thawte.nl/en/support/manuals/microsoft/all+windows+servers/export+private+key+or+certificate/). If the key has been generated by the client itself, you should see no errors, as it is already in the expected format.

### IDN (INTERNATIONALIZED DOMAIN NAMES) SUPPORT

If you are using IDN (Internationalized Domain Names) and generating a certificate for those, you can either encode those into "[punycode](https://www.punycoder.com/)" form by yourself, or let the client do that for you. Please note that for the
conversion to work properly you need to have correct locale settings on your system. For Linux-based systems you can check that with the "locale" command, for Windows make sure that "System locale" in the Control Panel is
set correctly.

### RENEWALS

To RENEW your existing certificate use the same command line as you used for issuing the certificate, with one additional parameter:

       --renew XX, where XX is the number of days left until certificate expiration.

If client detects that it is XX or fewer days left until certificate expiration, then (and only then) the renewal process will be run, so the script can be safely put into crontab to run on a daily basis if needed.

The amount of days left is checked by either of two methods:

 * If the certificate (which name is used with --crt parameter) is available locally, then it will be loaded and checked.
 * If the certificate is not available locally (for example if you moved it to another server), then an attempt to connect to the domains listed in --domains or CSR will be made until the first successful response is received. The peer certificate will be then checked for expiration.
 
### CONTACT DETAILS UPDATES

If you would like to receive expiration notifications for your domain, you can specify `--email` parameter and an appropriate email address during the initial registration of the account. Later, shall you want to change your email or specify more than one, you can use `--update-contacts` parameter to update your contact information. For example:

    le.pl --key account.key --update-contacts "one@email.address, another@email.address" --live

To reset your contact details, please specify "none" as a value, as follows:

    le.pl --key account.key --update-contacts "none" --live

### PLUGINS

Both the library and the client can be easily extended with custom plugins to handle Let's Encrypt challenges (both pre- and post-verification). See *Crypt::LE::Challenge::Simple* module as an example of such plugin. 

The client application can also be easily extended with modules handling process completion. See *Crypt::LE::Complete::Simple* module as an example of such plugin.

Client options related to plugins are:

 * --handle-with
 * --handle-params
 * --handle-as
 * --complete-with
 * --complete-params

Please note that parameters for `--handle-params` and `--complete-params` are expected to be _valid JSON documents_ or to _point to files containing valid JSON documents_ (the latter is a preferable method).

Example of running the client with plugins (you can modify the source code of the provided Crypt::LE::Challenge::Simple and Crypt::LE::Complete::Simple):

    le.pl --key account.key --email "my@email.address" --csr domain.csr --csr-key domain.key --crt domain.crt --domains "www.domain.ext,domain.ext" --generate-missing --handle-with Crypt::LE::Challenge::Simple --complete-with Crypt::LE::Complete::Simple
    
**Note**: you can use the same plugin to cover both the challenge/verification and the completion process, as long as it has appropriately named methods defined. You can also point directly to a Perl module file rather than specify a name of the module. 

**This will work even on Windows, without any need to install anything - having just the binary file of the client and the plugin file is sufficient.**

For example, if you have your le64.exe client and then created or downloaded the plugin code (see **Plugins/DNS.pm** for example) into the same directory, you can use it like this:

    le64.exe -key account.key -domains test.com -csr test.csr -csr-key test.key -crt test.crt -generate-missing -handle-with DNS.pm -handle-as dns

All comand line parameters are passed to the methods of the plugin, along with the information about the challenge requirements and the verification results. For example, if you have defined handle_challenge_dns method, it will receive the challenge data and the parameters data. The challenge data will contain all the necessary details, including "domain", "host" and "record" values. In this case the "host" would be the same as the "domain", except the wildcard part removed (if it was present). To illustrate:

- If the "domain" is test.com, then the "host" is test.com;
- If the "domain is "\*.test.com", then the "host" is test.com;

So you would need to set \_acme-challenge record in your "host" zone with the value of the "record".

In a similar way, for the HTTP verification, the method handle_challenge_http would have access to "file", which contains the name of the file to be created, and the "text", which contains the content of that file.

Please note that before v0.32 the parameters passed with --handle-params and --complete-params were accessible directly as keys of the parameters passed to the method. However, starting from v0.32 they are passed under their own key along with all the command line parameters. So if you have passed something like { "name": 123 } as JSON for --handle-params, then previously in your methos you would access that "name" as follows:

my $value = $params->{'name'};

Now you need to access it as follows:

my $value = $params->{'handle-params'}->{'name'};

_This is a potentially breaking change if you used custom handlers and were passing additional custom parameters from the command line of the client, but it is necessary to make all command line parameters accessible to plugins and avoid overlapping the keys._

#### Plugins in multiuser environment ####

It is important to remember that the client code allows plugins to be used. While this makes the client rather flexible in terms of possible automation, it should be kept in mind that you should not be running it from a privileged user (and you do not need to), especially in the multiuser environment. As with any other application that can extend the functionality either by plugins or by executing some commands/hooks, it is never a good idea to make it writable by anyone else or make it run with the privileges it does not actually need. You can almost always achieve the resuts you need without resorting to making your application (or the script that runs it) running as a root or a privileged user - for example to allow reloading the web server on completion you can just configure sudo to allow that reload to a specific user, etc.

### CUSTOM LOGGING

Client uses *Log::Log4perl* module for logging. You can easily configure it to log into file, database, syslog, etc. Logger object is available to plugins which are called from the client and to the library itself. Below is an example of a logging configuration file to log both to screen and into le.log file:

     log4perl.rootLogger=DEBUG, File, Screen
     log4perl.appender.File = Log::Log4perl::Appender::File
     log4perl.appender.File.filename = le.log
     log4perl.appender.File.mode = append
     log4perl.appender.File.layout = PatternLayout
     log4perl.appender.File.layout.ConversionPattern = %d [%p] %m%n
     log4perl.appender.File.utf8 = 1
     log4perl.appender.Screen = Log::Log4perl::Appender::Screen
     log4perl.appender.Screen.layout = PatternLayout
     log4perl.appender.Screen.layout.ConversionPattern = %d [%p] %m%n
     log4perl.appender.Screen.utf8 = 1

Save the configuration into some file and then run `le.pl` with `--log-config` parameter specifying that configuration file name, for those settings to take effect.

### CUSTOM EXIT CODES

By default the client application produces a limited set of exit codes - 1 on help or unknown parameters and 255 in case of other errors. Additionally the case of attempting a renewal too early is not considered an error. This behaviour can be changed to assign custom exit codes to different errors (including setting an error code for an early renewal). 

If you wish to change an exit code for a particular error, you need to find the associated message first and then assign some code via a config file. For example, say you are receiving an error message saying "Could not read the certificate file." and you want to assign an error code of 200 to it. If you you add `--debug` flag to the command line, that same error message would look as "\[ CERTIFICATE_FILE_READ \] Could not read the certificate file." If now you create a configuration file as shown below, running the same command as before with `--config name_of_your_configuration_file` will change the exit code for that error to 200:

    [errors]
    CERTIFICATE_FILE_READ = 200

### PROXY SUPPORT

In the rare case of connecting through a proxy, you can instruct the client to use one by setting HTTPS_PROXY environment variable in the form of https://user:pass@proxy.example.com/ (user:pass@ part is only needed if proxy requires basic auth).

### SUPPORT AND DOCUMENTATION

After installing, you can find documentation for this module with the
perldoc command.

    perldoc Crypt::LE

You can also look for information at:

 * [RT, CPAN's request tracker (report bugs here)](http://rt.cpan.org/NoAuth/Bugs.html?Dist=Crypt-LE)
 * [AnnoCPAN, Annotated CPAN documentation](http://annocpan.org/dist/Crypt-LE)
 
For feedback see:

 * [Do-Know.com](https://do-know.com)

### NOTES

Crypt::LE has been initially created over weekend, when I noticed that some of my previously bought certificates are about to expire soon enough. The initial goal was to make this work, make it easy to use and possibly remove the need to use openssl command line. It may contain some (hopefully minor) bugs, so feel free to submit a bug report.

If you'd like to contribute a custom plugin, for example to support automatic DNS records creation and removal via API of certain DNS providers (or your registrar), feel free to create a module under Crypt::LE::Challenge:: namespace and either upload it to CPAN or submit a pull request. 

In the former case please specify a dependency from Crypt::LE of at least version 0.11 in your Makefile.

In the latter case please be aware that your module might be uploaded to CPAN later (unless you object) and might be uploaded separately rather than as a part of Crypt::LE (this might happen if you are using dependencies not necessarily required for the rest of Crypt::LE package).

You can also contribute the completion-handling modules under Crypt::LE::Complete:: namespace, for example to scp the domain  key and certificate to another host or to send an email about successful certificate renewal.

### LICENSE AND COPYRIGHT

Copyright (C) 2016-2020 Alexander Yezhov

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
