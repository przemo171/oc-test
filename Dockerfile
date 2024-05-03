FROM registry.redhat.io/rhel9/php-82:1-11
MAINTAINER Przemas przemek@przemek.com
LABEL description="Przykładowy apache z ubi9"
RUN echo "DocumentRoot /var/www/html" >> /etc/httpd/conf/httpd.conf
ADD https://download.limesurvey.org/latest-master/limesurvey6.5.5+240429.zip /var/www/html/
CMD chown default:root /var/www/html/limesurvey6.5.5+240429.zip
CMD unzip /var/www/html/limesurvey6.5.5+240429.zip -d /var/www/html/
CMD rm -fr /var/www/html/limesurvey6.5.5+240429.zip
CMD ["httpd", "-D", "FOREGROUND"]
