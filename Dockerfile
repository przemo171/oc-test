FROM registry.redhat.io/rhel9/php-82:1-11
MAINTAINER Przemas przemek@przemek.com
LABEL description="Przykładowy apache z ubi9"
RUN echo "DocumentRoot /var/www/html" >> /etc/httpd/conf/httpd.conf
USER root
CMD ["httpd", "-D", "FOREGROUND"]
