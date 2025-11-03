FROM composer:2.7 as composer

ARG TESTING=false
ENV TESTING=$TESTING

WORKDIR /usr/local/src/

COPY composer.lock /usr/local/src/
COPY composer.json /usr/local/src/

RUN composer install --ignore-platform-reqs --optimize-autoloader \
    --no-plugins --no-scripts --prefer-dist

FROM appwrite/base:0.11.3 as final

LABEL maintainer="team@appwrite.io"

WORKDIR /usr/src/code

RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

RUN echo "opcache.enable_cli=1" >> $PHP_INI_DIR/php.ini

RUN echo "memory_limit=1024M" >> $PHP_INI_DIR/php.ini

COPY --from=composer /usr/local/src/vendor /usr/src/code/vendor

# Add Source Code
COPY ./tests /usr/src/code/tests
COPY ./src /usr/src/code/src
COPY ./phpunit.xml /usr/src/code/phpunit.xml
COPY ./phpstan.neon /usr/src/code/phpstan.neon
COPY ./pint.json /usr/src/code/pint.json

CMD [ "tail", "-f", "/dev/null" ]
