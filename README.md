# HttpSpnegoClient

Sample program demonstrate Java 11 HttpClient connecting to HiveServer2 WebUi (spnego enabled)

##### How to Build
```kubernetes helm
mvn clean package
```

##### How to Run
build command create a standalone jar that can be used to run with provided options
```kubernetes helm

java -Djava.security.krb5.conf=/tmp/krb5.conf \
 -cp target/SpnegoHttpClient-jar-with-dependencies.jar org.example.SpnegoHttpClient \
 -u http://HS2_WEBUI_HOST:10002 \
 -c raj@ROOT.HWX.SITE -p testpass \
 -sp HTTP/hostfqdn@ROOT.HWX.SITE

```

Expected output will print the response header and response body.
