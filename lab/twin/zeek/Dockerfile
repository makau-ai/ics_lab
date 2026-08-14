FROM zeek/zeek:lts
# Install CISA's ICSNPP DNP3 parser (MQTT is a built-in Zeek analyzer, nothing to add).
RUN zkg autoconfig && zkg install --force icsnpp-dnp3
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY run-zeek.sh /usr/local/bin/run-zeek
RUN chmod +x /usr/local/bin/run-zeek
WORKDIR /kit/pcaps
CMD ["bash"]
