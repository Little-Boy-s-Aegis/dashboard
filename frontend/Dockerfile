# Build stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine
# Copy built files to /usr/share/nginx/html/soc to match Vite base: '/soc/'
COPY --from=builder /app/dist /usr/share/nginx/html/soc

# Configure Nginx to serve the SPA on port 3001 under the /soc/ path
RUN echo 'server { \
    listen 3001; \
    location /soc/ { \
        alias /usr/share/nginx/html/soc/; \
        try_files $uri $uri/ /soc/index.html; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 3001
CMD ["nginx", "-g", "daemon off;"]
