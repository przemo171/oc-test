FROM ubi9/ubi9:latest
MAINTAINER Przemas przemek@przemek.com
LABEL description="Przykładowy apache z ubi9"
RUN yum install -y httpd && \
yum clean all
RUN echo "Cześć Dockerfile" > /var/www/html/index.html
RUN echo "ServerName root@localhost" >> /etc/httpd/conf/httpd.conf
RUN echo 'PidFile "/run/httpd.pid"' >> /etc/httpd/conf/httpd.conf
EXPOSE 80
CMD ["sleep", "inf"]
USER root
