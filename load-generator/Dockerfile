FROM grafana/k6:latest

COPY generate.js /scripts/generate.js

ENTRYPOINT ["k6", "run", "/scripts/generate.js"]
