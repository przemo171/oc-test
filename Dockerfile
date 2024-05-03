FROM registry.redhat.io/rhel9/php-82:1-11
MAINTAINER Przemas przemek@przemek.com
LABEL description="Przykładowy apache z ubi9"
RUN echo "Cześć Dockerfile" > /srv/www/html/index.html
RUN echo "<?php phpinfo(); ?>" > /srv/www/html/phpinfo.php
CMD ["httpd", "-D", "FOREGROUND"]
