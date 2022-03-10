# Build Multiple Architectures from macOS

Create buildx bootstrap builder:
```shell
docker buildx create --name your-builder-name

docker buildx use your-builder-name

docker buildx inspect --bootstrap
```

Run build:
```shell
# linux/386
docker buildx build \                                                                                                                                 
  --platform linux/386 \  
  --push \
  -t 071048290189.dkr.ecr.eu-west-2.amazonaws.com/profusion-pypiserver:latest \
  .

# Multiple
docker buildx build --platform linux/amd64,linux/arm64 -t profusion-pypiserver:latest --push .
```