FROM registry.access.redhat.com/ubi9:latest
MAINTAINER Przemas przemek@przemek.com
LABEL description="Przykładowy apache z ubi9"
RUN yum install -y httpd && \
yum clean all
RUN echo "Cześć Dockerfile" > /var/www/html/index.html
EXPOSE 80
CMD ["sleep", "inf"]
