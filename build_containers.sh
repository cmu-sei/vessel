docker build -t vessel .
docker build --target test -t vessel-test -f ./Dockerfile.test .
