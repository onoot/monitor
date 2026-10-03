FROM node:18-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm install

COPY . .


CMD ["npm", "run", "dev", "--", "--port=3000"]
