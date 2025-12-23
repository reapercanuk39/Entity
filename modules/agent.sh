#!/bin/bash
# Queen agent placeholder - signed and auditable by operator
LOGFILE=/var/log/queen_agent.log
echo "Queen agent starting at $(date -Is)" >> "$LOGFILE"
while true; do
  echo "heartbeat $(date -Is)" >> "$LOGFILE"
  sleep 60
done
