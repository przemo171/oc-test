FROM registry.redhat.io/rhel9/php-82:1-11
MAINTAINER Przemas przemek@przemek.com
LABEL description="Przykładowy apache z ubi9"
RUN echo "DocumentRoot /var/www/html" >> /etc/httpd/conf/httpd.conf
ADD https://download.limesurvey.org/latest-master/limesurvey6.5.5+240429.zip /var/www/html/
RUN unzip /var/www/html/limesurvey*
CMD ["httpd", "-D", "FOREGROUND"]
