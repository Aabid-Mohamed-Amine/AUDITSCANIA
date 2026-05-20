FROM instrumentisto/nmap:latest

# Make sure nmap is available system-wide
RUN nmap --version

# Default entrypoint provided by base image is nmap itself
# The worker calls: docker exec <container> nmap <args>
ENTRYPOINT ["tail"]
CMD ["-f", "/dev/null"]
