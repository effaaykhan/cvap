# A real telnet service. alpine's stock busybox omits the telnetd applet, so
# busybox-extras supplies it. It negotiates IAC options and presents /bin/login —
# plaintext by nature -> plaintext-telnet.
FROM alpine:3.20
RUN apk add --no-cache busybox-extras && adduser -D lab && echo 'lab:labpass' | chpasswd
EXPOSE 23
CMD ["busybox-extras", "telnetd", "-F", "-l", "/bin/login"]
