FROM node:argon

ADD package.json package.json
RUN npm install
ADD . .

LABEL databox.type="store"

EXPOSE 8080

CMD ["npm","start"]
