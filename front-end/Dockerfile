FROM node:18-alpine

WORKDIR /app

# Install dependencies first (cache layer)
COPY package*.json ./
RUN npm install --omit=dev

# Copy application code
COPY . .

# Create logs directory (mount a volume here in production to persist logs)
RUN mkdir -p /app/logs

# Log level: error | warn | info | http | debug
ENV LOG_LEVEL=info
ENV LOG_DIR=/app/logs

EXPOSE 3000

CMD ["node", "src/server.js"]
