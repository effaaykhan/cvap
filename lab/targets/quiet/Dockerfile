# nginx that will not name itself: `server_tokens off`.
#
# The response shape still identifies it, which is the whole point of having
# this target — see targets/quiet/nginx.conf.
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN sed -i 's/^http {/http {\n    server_tokens off;/' /etc/nginx/nginx.conf
