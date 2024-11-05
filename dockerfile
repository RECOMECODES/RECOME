FROM python:3.11-slim-bullseye

WORKDIR /usr/src/app
# 换源
RUN sed -i 's/deb.debian.org/mirrors.hust.edu.cn/g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y git libxml2 libjansson4 libyaml-0-2 vim && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# 暴露容器的8000端口到24150
EXPOSE 8000

# 容器运行时直接启动flask服务器
CMD ["python3", "server.py"]