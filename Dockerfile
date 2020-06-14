FROM alpine
LABEL vendor="Crypt::LE"
RUN set -xe \
    && apk add --no-cache make gcc build-base gnupg perl perl-dev perl-uri openssl openssl-dev zlib-dev \
    && cpan -i Net::SSLeay Crypt::LE \
    && rm -rf ~/.cpan/ \
    && apk del make gcc build-base perl-dev zlib-dev
RUN adduser -S -h /data ssl
ENV LC_ALL=en_US.UTF-8
VOLUME /data
WORKDIR /data
USER ssl
ENTRYPOINT ["le.pl"]
