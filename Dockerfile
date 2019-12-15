FROM alpine
LABEL vendor="ZeroSSL"
RUN set -xe \
    && apk add --no-cache make gcc build-base gnupg perl perl-dev perl-uri openssl openssl-dev zlib-dev \
    && cpan -i Net::SSLeay Crypt::LE \
    && rm -rf ~/.cpan/ \
    && apk del make gcc build-base perl-dev zlib-dev
RUN adduser -S -h /data zerossl
ENV LC_ALL=en_US.UTF-8
VOLUME /data
WORKDIR /data
USER zerossl
ENTRYPOINT ["le.pl"]

