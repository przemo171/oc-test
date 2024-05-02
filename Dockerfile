FROM registry.access.redhat.com/ubi9:latest
MAINTAINER Przemas przemek@przemek.com
LABEL description="Przykładowy apache z ubi9"
RUN yum install -y httpd && \
yum clean all
RUN sed -i 's/Listen 80/Listen 0.0.0.0:8080/g' /etc/httpd/conf/httpd.conf
RUN echo "Cześć Dockerfile" > /var/www/html/index.html
RUN echo "ServerName root@localhost" >> /etc/httpd/conf/httpd.conf
RUN echo 'PidFile "/run/httpd.pid"' >> /etc/httpd/conf/httpd.conf
EXPOSE 8080
CMD ["sleep", "inf"]
USER root
