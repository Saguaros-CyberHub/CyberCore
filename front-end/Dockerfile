FROM node:18-alpine

WORKDIR /app

# Install dependencies first (cache layer)
COPY package*.json ./
RUN npm ci --only=production

# Copy application code
COPY . .

EXPOSE 3000

CMD ["node", "src/server.js"]
