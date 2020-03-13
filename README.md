Artifactory secret decryption tool
==================================

Artifactory stores secrets encrypted on the disk. It may need these passwords to e.g. authenticate to another repository. They are encrypted using AES/CBC/PKCS5Padding.

This tool provides a portable way of decrypting these secrets offline, without using the API:
```
usage: artifactory_decrypt_secret.py [-h] -k ARTIFACTORY_KEY_FILE
                                     [-o OUTPUT_FILE]
                                     [artifactory_config_file]

positional arguments:
  artifactory_config_file

optional arguments:
  -h, --help            show this help message and exit
  -k ARTIFACTORY_KEY_FILE, --artifactory-key-file ARTIFACTORY_KEY_FILE
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
```


Decryption key
--------------

The decryption key is stored in ```/var/opt/jfrog/artifactory/etc/security/artifactory.key``` and looks like:
```
JS.25rLQ.AES128.7fcJFd3Y2ib3wi4EHnhbvZuxu
```

Where:

* ```JS``` denotes a key
* ```25rLQ``` is a unique key identifier that keeps track of which key can decrypt which secrets
* ```AES128``` obviously is the algorithm used
* ```7fcJFd3Y2ib3wi4EHnhbvZuxu``` is the base58 encoding of the key and 2 bytes of CRC


Secrets
-------

Secrets are found in the [configuration descriptors](https://www.jfrog.com/confluence/display/JFROG/Configuration+Files#ConfigurationFiles-GlobalConfigurationDescriptor), e.g. ```/var/opt/jfrog/artifactory/etc/artifactory.config.latest.xml``` and look like:
```
<keyStorePassword>AM.25rLQ.AES128.vJMeKkaK6RBRQCUKJWvYEHUw6zs394X1CrRugvJsQGPanhMgQ5be8yjWDhJYC4BEz2KRE</keyStorePassword>
```

Where:

* ```AM``` always denotes an artifactory encrypted secret
* ```25rLQ``` is the secret identifier that has to match the key's identifier
* ```AES128``` obviously is the algorithm used
* ```vJMeK...KRE``` is the base58 encoding of ```IV_SIZE|IV|secret|CRC```

More secrets can be found (tokens, configuration backups ...) by using the following regexp:
```
grep -r 'AM\..*\.AES128\.' /var/opt/jfrog/artifactory/
```
