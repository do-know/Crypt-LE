FROM alpine
LABEL vendor="ZeroSSL.com"
RUN set -xe \
    && apk add --no-cache make gcc build-base gnupg perl perl-dev perl-uri openssl openssl-dev \
    && cpan -i Net::SSLeay Crypt::LE \
    && rm -rf ~/.cpan/ \
    && apk del make gcc build-base perl-dev
RUN adduser -S -h /data zerossl
ENV LC_ALL=en_US.UTF-8
VOLUME /data
WORKDIR /data
USER zerossl
ENTRYPOINT ["le.pl"]

