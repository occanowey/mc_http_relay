# build docker image
build:
    nix build path:.#dockerImage

# load docker image locally
load: build
    pv result | docker load

# push docker image to host
push HOST: build
    pv result | ssh {{HOST}} docker load

# inspect docker image
dive: build
    gunzip --stdout  result > result.tar
    dive -- docker-archive://$(pwd)/result.tar

# remove docker image
clean:
    rm result result.tar