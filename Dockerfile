FROM node:20-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl python3 tar unzip && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
# Download official latest Linux amd64 releases from GitHub Releases.
COPY install-cores.py /tmp/install-cores.py
RUN python3 /tmp/install-cores.py && rm /tmp/install-cores.py
COPY . .
RUN mkdir -p /data /data/core && chown -R node:node /app /data
ENV PORT=8080 DATA_DIR=/data CONFIG_DIR=/data/core COOKIE_SECURE=true
EXPOSE 8080
USER node
CMD ["npm","start"]
