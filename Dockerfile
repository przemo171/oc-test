FROM registry.redhat.io/rhel9/php-82:1-11
MAINTAINER Przemas przemek@przemek.com
LABEL description="Przykładowy apache z ubi9"
RUN echo "Cześć Dockerfile" > /opt/app-root/src/index.html
RUN echo "<?php phpinfo(); ?>" > /opt/app-root/src/phpinfo.php
CMD ["httpd", "-D", "FOREGROUND"]
