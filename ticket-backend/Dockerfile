# Use Node.js image
FROM node:18

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm install

# Copy source code
COPY . .

# Expose backend port
EXPOSE 3000

CMD ["node", "src/index.js"]
