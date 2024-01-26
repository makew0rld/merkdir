FROM fedora:latest
RUN dnf update -y && dnf upgrade -y
RUN dnf install -y just git go && git clone https://github.com/ZacharyWills/merkdir.git merkdir

RUN cd /merkdir && just

CMD ["/merkdir/merkdir"]
