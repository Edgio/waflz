FROM ubuntu:16.04

RUN apt-get update && \
    apt-get install -y git software-properties-common && \
    add-apt-repository ppa:maxmind/ppa && \
    apt-get update && \
    apt-get install -y libssl-dev libpcre3-dev libxml2-dev libicu-dev protobuf-compiler libprotobuf-dev python-pip libmaxminddb0 libmaxminddb-dev cmake make g++ uuid-dev liblzma-dev google-perftools libgoogle-perftools-dev

RUN cd /opt && \
    git clone https://github.com/VerizonDigital/waflz

RUN cd /opt/waflz && \
     pip install -r requirements.txt && \
     ./build.sh && \
     echo "SecRule ARGS:x \"@streq test\" \"deny,status:403,id:123\"" > test.conf

EXPOSE 12345

CMD ["/opt/waflz/build/util/waflz_server/waflz_server --conf-file=/opt/waflz/test.conf"]
