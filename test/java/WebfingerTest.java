import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.util.Constants;
import org.oidc.services.Webfinger;

public class WebfingerTest {

    private static final ServiceContext SERVICE_CONTEXT =
            new ServiceContext();

    @Test
    public void testQueryDevice() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        Map<String,String> requestArguments = new HashMap<String,String>();
        requestArguments.put("resource", "device:p1.example.com");

        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
        Assert.assertTrue(httpArguments.getUrl().equals("https://p1.example.com/.well-known/webfinger?resource=device%3Ap1.example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer"));
    }

    @Test
    public void testQueryUrl() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT);
        Map<String,String> requestArguments = new HashMap<String,String>();
        requestArguments.put("resource", "acct:bob@example.com");

        AddedClaims addedClaims = new AddedClaims.AddedClaimsBuilder()
                .setOidcIssuers(Arrays.asList("http://webfinger.net/rel/profile-page", "vcard"))
                .buildAddedClaims();
        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
        Assert.assertTrue(httpArguments.getUrl().equals("https://example.com/.well-known/webfinger?resource" +
                "=acct%3Abob%40example.com&rel=http%3A%2F%2Fwebfinger.net%2Frel%2Fprofile-page&rel=vcard"));
    }

    @Test
    public void testQueryAcct() throws Exception {
        Webfinger webfinger = new Webfinger(SERVICE_CONTEXT, Arrays.asList(Constants.OIDC_ISSUER));
        Map<String,String> requestArguments = new HashMap<String,String>();
        requestArguments.put("resource", "acct:carol@example.com");

        HttpArguments httpArguments = webfinger.getRequestParameters(requestArguments);
        Assert.assertTrue(httpArguments.getUrl().equals("https://example.com/.well-known/webfinger?" +
                "resource=acct%3Acarol%40example.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1" +
                ".0%2Fissuer"));
    }
}
