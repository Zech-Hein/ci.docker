#!/bin/bash

case "${LICENSE,,}" in
  "accept" ) # Suppress license message in logs
    grep -s -F "com.ibm.ws.logging.hideMessage" /config/bootstrap.properties \
      && sed -i 's/^\(com.ibm.ws.logging.hideMessage=.*$\)/\1,CWWKE0100I/' /config/bootstrap.properties \
      || echo "com.ibm.ws.logging.hideMessage=CWWKE0100I" >> /config/bootstrap.properties
    ;;
  "view" ) # Display license file
    cat /opt/ibm/wlp/lafiles/LI_${LANG:-en}
    exit 1
    ;;
  "" ) # Continue, displaying license message in logs
    true
    ;;
  *) # License not accepted
    echo -e "Set environment variable LICENSE=accept to indicate acceptance of license terms and conditions.\n\nLicense agreements and information can be viewed by running this image with the environment variable LICENSE=view.  You can also set the LANG environment variable to view the license in a different language."
    exit 1
    ;;
esac

keystorePath="/config/configDropins/defaults/keystore.xml"

if [ "$KEYSTORE_REQUIRED" == "true" ]
then
  if [ ! -e $keystorePath ]
  then
    # Generate the keystore.xml
    PASSWORD=$(openssl rand -base64 32)
    XML="<server description=\"Default Server\"><keyStore id=\"defaultKeyStore\" password=\"$PASSWORD\" /></server>"

    # Create the keystore.xml file and place in configDropins
    mkdir -p $(dirname $keystorePath)
    echo $XML > $keystorePath
  fi
fi

publicCert="/etc/wlp/config/certificates/tls.crt"
privateKey="/etc/wlp/config/certificates/tls.key"
customkeystore="/etc/wlp/config/customKeystore/customkeystore.p12"
customtruststore="/etc/wlp/config/customTruststore/customtruststore.p12"

# If the ICP CA tls.crt and tls.key, or custom keystore and truststore exists, convert to P12 and use
if [ -e $publicCert ] && [ -e $privateKey ] || [ -e $customkeystore ]
then
  echo 'debug: cert/key or customkeystore found, running script'
  #Always generate on startup
  /opt/ibm/helpers/runtime/gen-icp-cert.sh
  
  #Start inotify
  /opt/ibm/helpers/runtime/inotify-cert.sh &
fi

# Pass on to the real server run
exec "$@"
