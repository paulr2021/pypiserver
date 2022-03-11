# Build Multiple Architectures from macOS:arm64

Run build and push to AWS:
```shell
aws ecr get-login-password --region eu-west-2 | docker login --username AWS --password-stdin 071048290189.dkr.ecr.eu-west-2.amazonaws.com

docker build --platform linux/386 -t profusion-pypiserver:latest .

docker push 071048290189.dkr.ecr.eu-west-2.amazonaws.com/profusion-pypiserver:latest
```
