#!/bin/bash
inotifywait -q -m -r -e delete_self /etc/wlp/config/certificates | \
  while read event; do
    echo "inotify event"
    echo "inotify event" >> /tmp/inotify
    /opt/ibm/helpers/runtime/gen-icp-cert.sh
  done
