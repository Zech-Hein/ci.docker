#!/bin/bash

keystoreXML="/config/configDropins/defaults/keystore.xml"
keystoreDir="/output/resources/security"
tmpKeystoreDir="/tmp/resources/security"
keystore="$tmpKeystoreDir/key.p12"
truststore="$tmpKeystoreDir/trust.p12"

configDir="/etc/wlp/config"
customKeystore="$configDir/customKeystore/customkeystore.p12"
customKeystorePwdFile="$configDir/customKeystore/customkeystorepwd.txt"
customTruststore="$configDir/customTruststore/customtruststore.p12"
customTruststorePwdFile="$configDir/customTruststore/customtruststorepwd.txt"

publicCert="$configDir/certificates/tls.crt"
privateKey="$configDir/certificates/tls.key"

icpCertExists=false
customKeystoreExists=false
customTruststoreExists=false
keystoreXMLExists=false
createSSLServerXML=false

checkICPCerts () {
  if [ -e $publicCert ] && [ -e $privateKey ];then
    icpCertExists=true
  fi
}

checkCustomKeystore () {
  if [ -e $customKeystore ] && [ -e $customKeystorePwdFile ];then
    customKeystoreExists=true
  elif [ -e $customKeystore ] && [ ! -e $customKeystorePwdFile ];then
    echo 'error: Found custom keystore, but No custom keystore password file.'
    exit 0
  fi
}

checkCustomTruststore () {
  if [ -e $customTruststore ] && [ -e $customTruststorePwdFile ];then
    customTruststoreExists=true
  elif [ -e $customTruststore ] && [ ! -e $customTruststorePwdFile ];then
    echo 'error: Found custom truststore, but No custom truststore password file.'
    exit 0
  fi
}

checkKeystoreXML () {
  if [ -e $keystoreXML ];then
    keystoreXMLExists=true
  fi
}

processKeystoreXML () {
  #Retrieve passwords for the keystore and truststore
  if [ $icpCertExists = true ];then
    if [ $keystoreXMLExists = true ];then
      passwords=($(grep -oP 'password="\K[^"]*' $keystoreXML ))
      KEYSTORE_PASSWORD=${passwords[0]}
      TRUSTSTORE_PASSWORD=${passwords[1]}
    else
      KEYSTORE_PASSWORD=$(openssl rand -base64 32)
      TRUSTSTORE_PASSWORD=$KEYSTORE_PASSWORD
      createSSLServerXML=true
    fi
  fi
  
  if [ $customKeystoreExists = true ];then
    KEYSTORE_PASSWORD=$(cat $customKeystorePwdFile)
    createSSLServerXML=true
  fi
  
  if [ $customTruststoreExists = true ];then
    TRUSTSTORE_PASSWORD=$(cat $customTruststorePwdFile)
    createSSLServerXML=true
  fi
  
  #generate keystore XML
  if [ $createSSLServerXML = true ];then
    if [ $keystoreXMLExists = true ];then
    #delete old keystore to avoid thrashing
      rm $keystoreXML
    fi
    XML="<server description=\"Default Server\"><ssl id=\"defaultSSLConfig\" keyStoreRef=\"defaultKeyStore\" trustStoreRef=\"defaultTrustStore\"/><keyStore id=\"defaultKeyStore\" location=\"$keystoreDir/key.p12\" type=\"PKCS12\" password=\"$KEYSTORE_PASSWORD\" /><keyStore id=\"defaultTrustStore\" location=\"$keystoreDir/trust.p12\" type=\"PKCS12\" password=\"$TRUSTSTORE_PASSWORD\" /></server>"
    mkdir -p $(dirname $keystoreXML)
    echo $XML > $keystoreXML
  fi
}

processKeystore () {
  #create a temporary dir for keystore and truststore to avoid thrashing
  mkdir -p $tmpKeystoreDir
  #generate keystore from ICP Cert
  if [ $icpCertExists = true ];then
    openssl pkcs12 -export -in $publicCert -inkey $privateKey -out $keystore -name default -passout pass:$KEYSTORE_PASSWORD
    openssl pkcs12 -in $keystore -nokeys -clcerts -passin pass:$KEYSTORE_PASSWORD -nomacver | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > $tmpKeystoreDir/cl.crt
    openssl pkcs12 -in $keystore -nokeys -chain -cacerts -passin pass:$KEYSTORE_PASSWORD -nomacver | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > $tmpKeystoreDir/icp_ca_issuer.crt
  fi
  #override ICP keystore if customKeystore exists
  if [ $customKeystoreExists = true ];then
    #normalize keystore name and location
    mv -f $customKeystore $keystore
  fi
  mkdir -p $keystoreDir
  mv -f $keystore $keystoreDir/key.p12
}

processTruststore () {
  #generate truststore from ICP Cert if it exists
  if [ $icpCertExists = true ];then
    keytool -importcert -keystore $truststore -storetype pkcs12 -storepass $TRUSTSTORE_PASSWORD -file $tmpKeystoreDir/cl.crt -alias defaultServer -noprompt
    keytool -importcert -keystore $truststore -storetype pkcs12 -storepass $TRUSTSTORE_PASSWORD -file $tmpKeystoreDir/icp_ca_issuer.crt -noprompt
  fi
  #combine ICP Cert and custom truststore
  if [ $icpCertExists = true ] && [ $customTruststoreExists = true ];then
    #merge truststores together
    keytool -importkeystore -srckeystore $customTruststore -srcstoretype pkcs12 -srcstorepass $TRUSTSTORE_PASSWORD -destkeystore $truststore -deststoretype pkcs12 -deststorepass $TRUSTSTORE_PASSWORD -noprompt
  #custom truststore only
  elif [ $customTruststoreExists = true ];then
    #normalize name and location
    mv -f $customTruststore $truststore
  fi
  mv -f $truststore $keystoreDir/trust.p12
}

cleanUp () {
#Delete the temporary directory and the files within
  rm -r $tmpKeystoreDir
}

checkICPCerts
checkCustomKeystore
checkCustomTruststore
checkKeystoreXML
processKeystoreXML
processKeystore
processTruststore
cleanUp
