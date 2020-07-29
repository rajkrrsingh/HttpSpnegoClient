package org.example;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginContext;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;

/**
 * SpnegoHttpClient self contained http client to connect spnego httpserver
 *
 */
public class SpnegoHttpClient
{
    public static void main( String[] args ) throws Exception {
        Options options = new Options();
        String serviceUrl = null,clientPrincipal = null ,clientPasswd = null,servicePrincipal = null;

        Option urlOpt = Option.builder("u")
                .longOpt("url")
                .hasArg(true)
                .desc("http server url")
                .required(true)
                .build();

        Option cnameOpt = Option.builder("c")
                .longOpt("cname")
                .hasArg(true)
                .desc("client principal")
                .required(true)
                .build();

       Option passwdOpt =  Option.builder("p")
                .longOpt("passwd")
                .hasArg(true)
                .desc("client password")
                .required(true)
                .build();

       Option spOpts = Option.builder("sp")
               .longOpt("srvprinc")
               .hasArg(true)
               .desc("service principal")
               .required(true)
               .build();

       options.addOption(cnameOpt)
               .addOption(passwdOpt)
               .addOption(urlOpt)
               .addOption(spOpts);

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
            serviceUrl = cmd.getOptionValue("u");
            clientPrincipal = cmd.getOptionValue("c");
            clientPasswd = cmd.getOptionValue("p");
            servicePrincipal = cmd.getOptionValue("sp");
            StringBuilder suppliedArgsBuilder = new StringBuilder();
            if (serviceUrl != null) {
                suppliedArgsBuilder.append(" service URL : "+serviceUrl);
            }
            if (clientPrincipal != null) {
                suppliedArgsBuilder.append(" clientPrincipal : "+clientPrincipal);
            }
            if (clientPasswd != null) {
                suppliedArgsBuilder.append(" clientPasswd : "+clientPasswd);
            }
            if (servicePrincipal != null) {
                suppliedArgsBuilder.append(" servicePrincipal URL : "+servicePrincipal);
            }

            System.out.println("supplied args : "+suppliedArgsBuilder.toString());
        } catch (ParseException pe) {
            System.out.println("Error parsing command-line arguments, please priovide options correctly!");
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp( "Spnego client arg parser options", options );
            System.exit(1);
        }


        //System.setProperty("sun.security.krb5.debug","true");
        System.setProperty("java.security.auth.login.config", "jaas.conf");
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");

        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        CompletableFuture<HttpResponse<String>> httpResponse = null;
        try {
            String finalServicePrincipal = servicePrincipal;
            String token = doAs(clientPrincipal, clientPasswd.toCharArray(),
                    new Callable<String>() {
                        @Override
                        public String call() throws Exception {
                            GSSManager gssManager = GSSManager.getInstance();
                            GSSContext gssContext = null;
                            try {
                                //String servicePrincipal = "HTTP/rajkumarsingh-2.rajkumarsingh.root.hwx.site@ROOT.HWX.SITE";
                                Oid spnegoOid = new Oid("1.3.6.1.5.5.2");
                                // for some reason NT_HOSTBASED_SERVICE was not working in my kerberos setup but can be
                                // use interchangeably
                                GSSName serviceName = gssManager.createName(finalServicePrincipal,
                                        GSSName.NT_USER_NAME);
                                gssContext = gssManager.createContext(serviceName, spnegoOid,
                                        null,
                                        GSSContext.DEFAULT_LIFETIME);
                                gssContext.requestCredDeleg(true);
                                gssContext.requestMutualAuth(true);

                                byte[] inToken = new byte[0];
                                byte[] outToken = gssContext.initSecContext(inToken, 0, inToken.length);
                                return Base64.getEncoder().encodeToString(outToken);

                            } finally {
                                if (gssContext != null) {
                                    gssContext.dispose();
                                }
                            }
                        }
                    });
            System.out.println("Token : " + token);

            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .GET()
                    .uri(URI.create(serviceUrl))
                    .setHeader("User-Agent", "Java 11 HttpClient Test")
                    .setHeader("Authorization", "Negotiate " + token)
                    .build();
            httpResponse =
                    httpClient.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            System.err.println("Error while processing the request");
            e.printStackTrace();
        }
        System.out.println("################### Printing Headers ######################################");
        System.out.println("###########################################################################");
        if (httpResponse != null) {
            httpResponse.get().headers().map().forEach((x, y) -> System.out.println(x + ":" + y));
        } else {
            System.err.println("Error while processing the response");
        }
        System.out.println();
        System.out.println("###########################################################################");
        System.out.println("################### Printing Response Body ################################");
        System.out.println("###########################################################################");
        System.out.println(httpResponse.get().body());
        System.out.println("###########################################################################");


    }

    public static <T> T doAs(String principal, char[] passArr, final Callable<T> callable) throws Exception {
        LoginContext loginContext = null;
        try {
            loginContext = new LoginContext("KerbLogin",
                    new CallbackHandler() {

                        @Override
                        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                            for (Callback cb : callbacks) {
                                if (cb instanceof NameCallback) {
                                    NameCallback nc = (NameCallback) cb;
                                    nc.setName(principal);
                                } else if (cb instanceof PasswordCallback) {
                                    PasswordCallback pc = (PasswordCallback) cb;
                                    pc.setPassword(passArr);
                                } else {
                                    throw new UnsupportedCallbackException(cb);
                                }
                            }
                        }
                    });
            loginContext.login();
            Subject subject = loginContext.getSubject();
            KerberosTicket kt = (KerberosTicket) subject.getPrivateCredentials().iterator().next();
            //System.out.println("client auth succeed, kerbero ticket "+kt);
            return Subject.doAs(subject, new PrivilegedExceptionAction<T>() {
                @Override
                public T run() throws Exception {
                    return callable.call();
                }
            });
        } catch (PrivilegedActionException ex) {
            throw ex.getException();
        } finally {
            if (loginContext != null) {
                loginContext.logout();
            }
        }
    }

}
