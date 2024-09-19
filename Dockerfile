# Stage 1: Install Dependencies
FROM node:18-alpine AS dependencies

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install --only=production

# Stage 2: Production Image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy only the necessary files from the dependencies stage
COPY --from=dependencies /app/node_modules ./node_modules

# Copy the server.js and other necessary files
COPY server.mjs ./

# Expose the port your app runs on
EXPOSE 8081

# Define environment variable for production
ENV NODE_ENV=production

# Start the Node.js application
CMD ["node", "server.mjs"]
#CMD ["sh", "-c", "sleep 10 && node server.mjs"]


