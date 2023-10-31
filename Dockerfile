FROM php:8.2-cli
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      libltdl-dev \
      libpcsclite-dev \
      libxml2-dev \
      git \
      libzip-dev \
      zip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install soap zip

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
COPY kalkancrypt.so.82nts kalkancrypt.so
RUN mv kalkancrypt.so $(php-config --extension-dir)/kalkancrypt.so && \
    echo "extension=kalkancrypt" >> $(php-config  --ini-dir)/kalkancrypt.ini
RUN mkdir -p /usr/local/share/ca-certificates/extra

WORKDIR /app