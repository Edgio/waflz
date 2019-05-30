FROM ubuntu:16.04

RUN apt-get update && \
    apt-get install -y git software-properties-common && \
    apt-get install -y libssl-dev libpcre3-dev libxml2-dev libicu-dev protobuf-compiler libprotobuf-dev python-pip cmake make g++ uuid-dev liblzma-dev google-perftools libgoogle-perftools-dev libhiredis-dev libkyotocabinet-dev

COPY . /opt/waflz

RUN cd /opt/waflz && \
     pip install -r requirements.txt && \
     ./build.sh && \
     echo "SecRule ARGS:x \"@streq test\" \"deny,status:403,id:123\"" > test.conf

EXPOSE 12345

CMD ["/opt/waflz/build/util/waflz_server/waflz_server --conf-file=/opt/waflz/test.conf"]
