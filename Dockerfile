FROM registry.redhat.io/rhel9/php-82:1-11
MAINTAINER Przemas przemek@przemek.com
LABEL description="Przykładowy apache z ubi9"
RUN echo "Cześć Dockerfile" > /var/www/index.html
RUN echo "<?php phpinfo(); ?>" > /var/www/phpinfo.php
CMD ["httpd", "-D", "FOREGROUND"]
