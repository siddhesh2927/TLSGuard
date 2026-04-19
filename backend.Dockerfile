FROM node:20-alpine
# Install heavy system tools required for native C++ SQLite compilation
RUN apk update && apk add --no-cache python3 make g++ gcc libc-dev

WORKDIR /app

COPY package*.json ./
COPY backend/package.json ./backend/
COPY frontend/package.json ./frontend/

RUN npm install

COPY backend ./backend

EXPOSE 3000

WORKDIR /app/backend
CMD ["npm", "run", "start"]
